package org.fogbowcloud.ssh;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.apache.sshd.common.util.Base64;
import org.fogbowcloud.ssh.db.TokenDataStore;
import org.fogbowcloud.ssh.db.TunnelServerDataStore;
import org.fogbowcloud.ssh.model.Token;
import org.json.JSONArray;
import org.json.JSONObject;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class TunnelHttpServer extends NanoHTTPD {

	// private TunnelServer tunneling;
	private static final int SSH_SERVER_VERIFICATION_TIME = 300;
	private static final long TOKEN_EXPIRATION_CHECK_INTERVAL = 30L; // 30s in
																		// seconds
	private static final Logger LOGGER = Logger.getLogger(TunnelHttpServer.class);

	private TokenDataStore tokenDs;
	private TunnelServerDataStore tunnelServerDs;

	private List<TunnelServer> tunnelServers;

	private String hostKeyPath;
	private KeyPair kp;

	private int lowerPort;
	private int higherPort;
	private String sshTunnelHost;
	private int lowerSshTunnelPort;
	private int higherSshTunnelPort;
	private Long idleTokenTimeout;
	private int checkSSHServersInterval;

	private int portsPerShhServer;

	private ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
	private ScheduledExecutorService monitorExpiredTokensExecutor = Executors.newScheduledThreadPool(1);

	protected TunnelHttpServer(int httpPort, String sshTunnelHost, int lowerSshTunnelPort, int higherSshTunnelPort,
			int lowerPort, int higherPort, Long idleTokenTimeout, String hostKeyPath, int portsPerShhServer,
			TokenDataStore tokenDs, TunnelServerDataStore tunnelServerDs, boolean startServers, boolean clearDatastore) throws Exception {

		super(httpPort);
		this.hostKeyPath = hostKeyPath;

		this.lowerPort = lowerPort;
		this.higherPort = higherPort;
		this.sshTunnelHost = sshTunnelHost;
		this.lowerSshTunnelPort = lowerSshTunnelPort;
		this.higherSshTunnelPort = higherSshTunnelPort;
		this.idleTokenTimeout = idleTokenTimeout;
		this.portsPerShhServer = portsPerShhServer;
		this.tokenDs = tokenDs;
		this.tunnelServerDs = tunnelServerDs;
		
		if(!clearDatastore){

			tunnelServers = tunnelServerDs.getAllTunnelServers();

			if (tunnelServers.size() > 0) {
				for (TunnelServer tunnelServer : tunnelServers) {

					List<Token> tokens = tokenDs.getAllTokenPortsBySshServerPort(tunnelServer.getSshTunnelPort());
					tunnelServer.setTokens(tokens);
					if(startServers){
						this.startTunnelServer(tunnelServer);
					}
				}
			}
			
		}else{
			this.tokenDs.deleteAll();
			this.tunnelServerDs.deleteAll();
			tunnelServers = new ArrayList<TunnelServer>();
		}
	}

	public TunnelHttpServer(int httpPort, String sshTunnelHost, int lowerSshTunnelPort, int higherSshTunnelPort,
			int lowerPort, int higherPort, Long idleTokenTimeout, String hostKeyPath, int portsPerShhServer,
			int checkSSHServersInterval, String dataStoreUrl, boolean cleanDataStore) throws Exception {
		
		this(httpPort, sshTunnelHost, lowerSshTunnelPort, higherSshTunnelPort, lowerPort, higherPort, idleTokenTimeout,
				hostKeyPath, portsPerShhServer, new TokenDataStore(dataStoreUrl),
				new TunnelServerDataStore(dataStoreUrl), true, cleanDataStore);

		this.checkSSHServersInterval = checkSSHServersInterval == 0 ? SSH_SERVER_VERIFICATION_TIME
				: checkSSHServersInterval;

		try {
			
			if(tunnelServers == null || tunnelServers.isEmpty()){
				this.createNewTunnelServer();
			}

			executor.scheduleWithFixedDelay(new Runnable() {
				@Override
				public void run() {

					List<TunnelServer> tunnelsToRemove = new ArrayList<TunnelServer>();

					for (TunnelServer tunnelServer : tunnelServers) {
						if (tunnelServer.getActiveTokensNumber() <= 0) {
							tunnelsToRemove.add(tunnelServer);
						}
					}

					for (TunnelServer tunneling : tunnelsToRemove) {
						try {
							removeTunnelServer(tunneling);
						} catch (InterruptedException e) {
							LOGGER.error(e.getMessage(), e);
						}
					}
				}

			}, this.checkSSHServersInterval, this.checkSSHServersInterval, TimeUnit.SECONDS);

			monitorExpiredTokensExecutor.scheduleWithFixedDelay(new Runnable() {
				@Override
				public void run() {
					for (TunnelServer tunnelServer : tunnelServers) {
						List<Token> expiredTokens = new ArrayList<Token>(tunnelServer.getExpiredTokens());
						try {
							tokenDs.deleteListOfTokenPort(expiredTokens);
						} catch (Exception e) {
							LOGGER.error("Erro while trying to delete expired token from tunnel ["
									+ tunnelServer.getSshTunnelPort() + "]", e);
						}
					}
				}
			}, 0L, TOKEN_EXPIRATION_CHECK_INTERVAL, TimeUnit.SECONDS);

		} catch (IOException e) {
			LOGGER.error(e.getMessage(), e);
		}
	}

	@Override
	public Response serve(IHTTPSession session) {
		Method method = session.getMethod();
		String uri = session.getUri();
		String[] splitUri = uri.split("\\/");
		if (splitUri.length < 2) {
			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
		}
		if (splitUri[1].equals("token")) {

			if (splitUri.length > 4) {
				return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
			}

			String tokenId = splitUri[2];

			if (method.equals(Method.GET)) {
				if (splitUri.length == 4 && splitUri[3].equals("all")) {
					Map<String, Integer> ports = new HashMap<String, Integer>();
					for (TunnelServer tunneling : tunnelServers) {
						ports.putAll(tunneling.getPortByPrefix(tokenId));
					}
					return new NanoHTTPD.Response(new JSONObject(ports).toString());
				} else {
					Integer port = this.getPortByTokenId(tokenId);
					if (port == null) {
						return new NanoHTTPD.Response(Status.NOT_FOUND, MIME_PLAINTEXT, "404 Port Not Found");
					}
					return new NanoHTTPD.Response(port.toString());
				}
			}
			if (method.equals(Method.POST)) {

				Token token = null;

				if (tunnelServers != null && !tunnelServers.isEmpty()) {

					for (TunnelServer tunneling : tunnelServers) {
						
						Integer instancePort = tunneling.getPort(tokenId);
						
						if (instancePort != null) {
							token = new Token(tokenId, instancePort, tunneling.getSshTunnelPort());
							break;
						}
					}
				}

				if (token == null) {
					
					try {
						TunnelServer availableTunnelServer = null;
						
						if (tunnelServers != null && !tunnelServers.isEmpty()) {
							for (TunnelServer tunneling : tunnelServers) {
								if(!tunneling.isServerBusy()){
									availableTunnelServer = tunneling;
									break;
								}
							}
						}
						
						if(availableTunnelServer == null){
							availableTunnelServer = this.createNewTunnelServer();
						}
						
						if (availableTunnelServer != null) {
							token = this.createNewPort(tokenId, availableTunnelServer);
						}
						
					} catch (Exception e) {
						return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT,
								"Error while creating shh server to handle new port.");
					}
				}
				
				if(token == null){
					return new NanoHTTPD.Response(Status.FORBIDDEN, MIME_PLAINTEXT,
							"Token [" + tokenId + "] didn't get any port. All ssh servers are busy.");
				}
				
				// Return format: instancePort:sshTunnelServerPort (int:int)
				return new NanoHTTPD.Response(token.getPort() + ":" + token.getSshServerPort());
			}

			if (method.equals(Method.DELETE)) {

				if (splitUri.length == 4) {
					String portNumber = splitUri[3];
					if (Utils.isNumber(portNumber)) {
						try {
							if (this.releaseInstancePort(tokenId, Integer.parseInt(portNumber))) {
								return new NanoHTTPD.Response(Status.OK, MIME_PLAINTEXT, "OK");
							}
						} catch (Exception e) {
							LOGGER.error("Erro while trying to release port :"+portNumber);
							return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT,
									"Token can not delete this port due:"+e.getMessage());
						}
						
					}
				}
				return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT,
						"Token can not delete this port");
			}

			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");

		} else if (splitUri[1].equals("hostkey")) {
			if (method.equals(Method.GET)) {
				if (kp == null) {
					ObjectInputStream ois = null;
					try {
						ois = new ObjectInputStream(new FileInputStream(hostKeyPath));
						this.kp = (KeyPair) ois.readObject();
					} catch (Exception e) {
						return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT, "Internal error");
					} finally {
						try {
							ois.close();
						} catch (Exception e) {
						}
					}
				}
				try {
					String pk = new String(Base64.encodeBase64(kp.getPublic().getEncoded()), "utf-8");
					return new NanoHTTPD.Response(pk);
				} catch (UnsupportedEncodingException e) {
					return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT, "Internal error");
				}
			}

			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
			
		} else if (splitUri[1].equals("informations")) {
			
			if (method.equals(Method.GET)) {
				
				Map<String, Integer> ports = new HashMap<String, Integer>();
				
				try {
					
					JSONArray tokensArray = new JSONArray();
					
					List<Token> tokens =  tokenDs.getAllTokenPorts();
					for(Token token : tokens){
						JSONObject tokenJSON = new JSONObject();
						tokenJSON.put("token", token.getTokenId());
						tokenJSON.put("port", token.getPort());
						tokenJSON.put("ssh-server-port", token.getSshServerPort());
						tokensArray.put(tokenJSON);
					}
					return new NanoHTTPD.Response(tokensArray.toString());
					
				} catch (Exception e) {
					return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT, "Internal error: "+e.getMessage());
				}
				
			}

			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
		}

		return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
	}
	
	protected Token createNewPort(String tokenId, TunnelServer tunnel) throws Exception{
		
		Token token = tunnel.createPort(tokenId);
		tokenDs.insertTokenPort(token);
		
		return token;
	}

	protected TunnelServer createNewTunnelServer() throws Exception {

		// Setting available ports to this tunnel server
		int initialPort = 0;
		int endPort = 0;
		int sshTunnelPort = 0;

		Set<Integer> usedInitialPorts = new HashSet<Integer>();
		if(tunnelServers != null){
			for (TunnelServer tunnelServer : tunnelServers) {
				usedInitialPorts.add(new Integer(tunnelServer.getLowerPort()));
			}
		}

		for (int port = lowerPort; port < higherPort; port += portsPerShhServer) {
			if (!usedInitialPorts.contains(new Integer(port))) {
				initialPort = port;
				break;
			}
		}

		if (initialPort == 0) {
			return null;
		}

		endPort = initialPort + (portsPerShhServer - 1);
		if (endPort > higherPort) {
			endPort = higherPort;
		}

		// Setting the port that this tunnel Server listening to manage
		// connections requests.
		for (int port = lowerSshTunnelPort; port <= higherSshTunnelPort; port++) {
			
			if(tunnelServerDs.getTunnelServerByPort(port) == null){
				sshTunnelPort = port;
				break;
			}
		}

		if (sshTunnelPort == 0) {
			return null;
		}
		
		TunnelServer tunneling = new TunnelServer(sshTunnelHost, sshTunnelPort, initialPort, endPort, idleTokenTimeout,
				hostKeyPath, new ArrayList<Token>());

		tunnelServerDs.insertTunnelServer(tunneling);
		if(tunnelServers == null){
			tunnelServers = new ArrayList<TunnelServer>();
		}
		tunnelServers.add(tunneling);
		return tunneling;
	}

	protected boolean startTunnelServer(TunnelServer tunneling)
			throws Exception {
		if(tunneling != null){
			tunneling.start();
			return true;
		}
		return false;
	}
	
	protected List<TunnelServer> getAllTunnelServers(){
		return this.tunnelServers;
	}
	
	protected void setTunnelServers(List<TunnelServer> tunnelServers){
		this.tunnelServers = tunnelServers;
	}

	protected void setTokenDs(TokenDataStore tokenDs) {
		this.tokenDs = tokenDs;
	}

	protected void setTunnelServerDs(TunnelServerDataStore tunnelServerDs) {
		this.tunnelServerDs = tunnelServerDs;
	}

	private Integer getPortByTokenId(String tokenId) {
		for (TunnelServer tunneling : tunnelServers) {
			if (tunneling.getPort(tokenId) != null) {
				return tunneling.getPort(tokenId);
			}
		}
		return null;
	}

	// TODO: Create new method to validate if the requester have available quota
	// to request new port.

	private boolean releaseInstancePort(String tokenId, Integer port) throws Exception {
		for (TunnelServer tunneling : tunnelServers) {

			Integer actualPort = tunneling.getPort(tokenId);

			if (actualPort != null && (actualPort.compareTo(port) == 0)) {
				Token token = tunneling.releasePort(port);
				tokenDs.deleteTokenPort(token);
				if (tunneling.getActiveTokensNumber() == 0) {
					try {
						this.removeTunnelServer(tunneling);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
				return true;
			}
			
		}
		return false;
	}

	private void removeTunnelServer(TunnelServer tunneling) throws InterruptedException {
		if (tunneling != null) {
			tunneling.stop();
			LOGGER.warn("Removing ssh server with port: " + tunneling.getSshTunnelPort());
			tunnelServers.remove(tunneling.getSshTunnelPort());
		}
	}
}