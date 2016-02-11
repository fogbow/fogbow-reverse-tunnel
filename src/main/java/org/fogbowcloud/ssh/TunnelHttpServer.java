package org.fogbowcloud.ssh;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.apache.sshd.common.util.Base64;
import org.json.JSONObject;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class TunnelHttpServer extends NanoHTTPD {
	
	
	private static final int DEFAULT_TOKEN_PORT_QUOTA = 5;
	
	private static final String REMOTE_ADDR = "remote-addr";
	private static final String HTTP_CLIENT_IP = "http-client-ip";
	//private TunnelServer tunneling;
	private static final int SSH_SERVER_VERIFICATION_TIME = 300;
	private static final Logger LOGGER = Logger.getLogger(TunnelHttpServer.class);
	
	private Map<Integer, TunnelServer> tunnelServers = new ConcurrentHashMap<Integer, TunnelServer>();
	private Map<String, Integer> clientPortQuota = new ConcurrentHashMap<String, Integer>();
	
	//Key(Integer): port used by an client. Value (String): Client IP that use this port.
	private Map<Integer, String> portClientMap = new ConcurrentHashMap<Integer, String>();
	
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

	public TunnelHttpServer(int httpPort, String sshTunnelHost, int lowerSshTunnelPort, int higherSshTunnelPort, 
			int lowerPort, int higherPort, Long idleTokenTimeout, String hostKeyPath, int portsPerShhServer, int checkSSHServersInterval) {
		super(httpPort);
		this.hostKeyPath = hostKeyPath;
		
		this.lowerPort = lowerPort;
		this.higherPort = higherPort;
		this.sshTunnelHost = sshTunnelHost;
		this.lowerSshTunnelPort = lowerSshTunnelPort;
		this.higherSshTunnelPort = higherSshTunnelPort;
		this.idleTokenTimeout = idleTokenTimeout;
		this.portsPerShhServer = portsPerShhServer;
		this.checkSSHServersInterval = checkSSHServersInterval == 0 ? SSH_SERVER_VERIFICATION_TIME : checkSSHServersInterval;
		
		try {
			
			this.createNewTunnelServer();
			
			executor.scheduleWithFixedDelay(new Runnable() {
				@Override
				public void run() {
					
					List<TunnelServer> tunnelsToRemove = new ArrayList<TunnelServer>();
					
					for(Entry<Integer, TunnelServer> entry : tunnelServers.entrySet()){
						if(entry.getValue().getActiveTokensNumber() <= 0){
							tunnelsToRemove.add(entry.getValue());
						}
					}
					
					for(TunnelServer tunneling : tunnelsToRemove){
						try {
							removeTunnelServer(tunneling);
						} catch (InterruptedException e) {
							LOGGER.error(e.getMessage(), e);
						}
					}
					
				}
			}, this.checkSSHServersInterval, this.checkSSHServersInterval, TimeUnit.SECONDS);
			
		} catch (IOException e) {
			LOGGER.error(e.getMessage(), e);
		}
	}
	
	protected TunnelHttpServer(int httpPort, String sshTunnelHost, int lowerSshTunnelPort, int higherSshTunnelPort, 
			int lowerPort, int higherPort, Long idleTokenTimeout, String hostKeyPath, int portsPerShhServer) {
		super(httpPort);
		
		this.hostKeyPath = hostKeyPath;
		this.lowerPort = lowerPort;
		this.higherPort = higherPort;
		this.sshTunnelHost = sshTunnelHost;
		this.lowerSshTunnelPort = lowerSshTunnelPort;
		this.higherSshTunnelPort = higherSshTunnelPort;
		this.idleTokenTimeout = idleTokenTimeout;
		this.portsPerShhServer = portsPerShhServer;
	}

	@Override
	public Response serve(IHTTPSession session) {
		
		Method method = session.getMethod();
		String uri = session.getUri();
		String[] splitUri = uri.split("\\/");
		
		String clientIP = session.getHeaders().get(HTTP_CLIENT_IP);
		
		if(clientIP == null || clientIP.isEmpty()){
			clientIP = session.getHeaders().get(REMOTE_ADDR);
		}
		
		if (splitUri.length < 2) {
			return new NanoHTTPD.Response(Status.BAD_REQUEST, MIME_PLAINTEXT, "Wrong tokenQuota parameter.");
		}
		if (splitUri[1].equals("token")) {
			
			if (splitUri.length > 4) {
				return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
			}
			
			String tokenIdAndQuota = splitUri[2];
			String[] splitTokenIdAndQuota = tokenIdAndQuota.split(":");

			if(splitTokenIdAndQuota.length < 1){
				return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
			}
			
			String tokenId = splitTokenIdAndQuota[0];
			Integer tokenQuote = new Integer(DEFAULT_TOKEN_PORT_QUOTA);
			
			if(splitTokenIdAndQuota.length > 1 && Utils.isNumber(splitTokenIdAndQuota[1])){
				tokenQuote = Integer.valueOf(splitTokenIdAndQuota[1]);
			}
			
			if(clientPortQuota.get(clientIP) == null){
				clientPortQuota.put(clientIP, tokenQuote);
			}
			
			if (method.equals(Method.GET)) {
				if (splitUri.length == 4 && splitUri[3].equals("all")) {
					Map<String, Integer> ports = new HashMap<String, Integer>();
					for(TunnelServer tunneling : tunnelServers.values()){
						ports.putAll(tunneling.getPortByPrefix(tokenId));
					}
					return new NanoHTTPD.Response(new JSONObject(ports).toString());
				} else {
					Integer port = this.getPortByTokenId(tokenId);
					if (port == null) {
						return new NanoHTTPD.Response(Status.NOT_FOUND, 
								MIME_PLAINTEXT, "404 Port Not Found");
					}
					return new NanoHTTPD.Response(port.toString());
				}
			}
			if (method.equals(Method.POST)) {
				
				LOGGER.debug("Recieving request of port from ["+clientIP+"]");
				
				if(this.hasAvailableQuota(clientIP)){

					Integer instancePort = null ;
					Integer sshServerPort = null ;

					if(tunnelServers.values() != null && !tunnelServers.values().isEmpty()){
						for(TunnelServer tunneling : tunnelServers.values()){
							instancePort = tunneling.createPort(tokenId);
							if(instancePort != null){
								sshServerPort = tunneling.getSshTunnelPort();
								break;
							}
						}
					}

					if (instancePort == null) {
						try {
							TunnelServer tunneling = this.createNewTunnelServer();
							if(tunneling != null){
								instancePort = tunneling.createPort(tokenId);
								sshServerPort = tunneling.getSshTunnelPort();
							}
						} catch (IOException e) {
							return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT, "Error while creating shh server to handle new port.");
						}
					}

					if (instancePort == null) {
						return new NanoHTTPD.Response(Status.FORBIDDEN, MIME_PLAINTEXT, "Token [" + tokenId + "] didn't get any port. All ssh servers are busy.");
					}

					portClientMap.put(instancePort, clientIP);

					//Return format: instancePort:sshTunnelServerPort (int:int) 
					return new NanoHTTPD.Response(instancePort.toString()+":"+sshServerPort.toString());

				}else{
					LOGGER.debug("Client ["+clientIP+"] has reached port limit");
					return new NanoHTTPD.Response(Status.FORBIDDEN, MIME_PLAINTEXT, "Token [" + tokenId + "] didn't get any port. Quota limit has been reached.");
				}
			}
			
			if (method.equals(Method.DELETE)) {
				
				if (splitUri.length == 4) {
					String portNumber = splitUri[3];
					if(Utils.isNumber(portNumber)){
						if(this.releaseInstancePort(tokenId, Integer.parseInt(portNumber))){
							return new NanoHTTPD.Response(Status.OK, MIME_PLAINTEXT, "OK");
						}
					}
				}
				return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "Token can not delete this port");
			}
			
			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
			
		} else if (splitUri[1].equals("hostkey")) {
			if (method.equals(Method.GET)) {
				if (kp == null) {
					ObjectInputStream ois = null;
					try {
						ois = new ObjectInputStream(
								new FileInputStream(hostKeyPath));
						this.kp = (KeyPair) ois.readObject();
					} catch (Exception e) {
						return new NanoHTTPD.Response(Status.INTERNAL_ERROR, 
								MIME_PLAINTEXT, "Internal error");
					} finally {
						try {
							ois.close();
						} catch (Exception e) {
						}
					}
				}
				try {
					String pk = new String(Base64.encodeBase64(
							kp.getPublic().getEncoded()), "utf-8");
					return new NanoHTTPD.Response(pk);
				} catch (UnsupportedEncodingException e) {
					return new NanoHTTPD.Response(Status.INTERNAL_ERROR, 
							MIME_PLAINTEXT, "Internal error");
				}
			}
			
			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
		}
		
		return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
	}
	
	private TunnelServer createNewTunnelServer() throws IOException{
			
			//Setting available ports to this tunnel server 
			int initialPort = 0;
			int endPort = 0;
			int sshTunnelPort = 0;

			Set<Integer> usedInitialPorts = new HashSet<Integer>();
			for (TunnelServer tunnelServer : tunnelServers.values()) {
				usedInitialPorts.add(new Integer(tunnelServer.getLowerPort()));
			}

			for(int port = lowerPort; port < higherPort; port+=portsPerShhServer){
				if(!usedInitialPorts.contains(new Integer(port))){
					initialPort = port;
					break;
				}
			}
			
			if(initialPort == 0){
				return null;
			}

			endPort = initialPort+(portsPerShhServer-1);
			if(endPort > higherPort){
				endPort = higherPort;
			}

			//Setting the port that this tunnel Server listening to manage connections requests.
			for(int port =  lowerSshTunnelPort ; port <= higherSshTunnelPort ; port++){
				if(!tunnelServers.containsKey(new Integer(port))){
					sshTunnelPort = port;
					break;
				}
			}

			if(sshTunnelPort == 0){
				return null;
			}
			
			TunnelServer tunneling = new TunnelServer(sshTunnelHost, sshTunnelPort, 
					initialPort, endPort, idleTokenTimeout, hostKeyPath);

			tunnelServers.put(new Integer(sshTunnelPort), tunneling);
			tunneling.start();
			
			return tunneling;
	}
	
	private Integer getPortByTokenId(String tokenId){
		for(TunnelServer tunneling : tunnelServers.values()){
			if(tunneling.getPort(tokenId) != null){
				return tunneling.getPort(tokenId);
			}
		}
		return null;
	}
	
	private boolean hasAvailableQuota(String clientIp){
		
		Integer tokenQuota = clientPortQuota.get(clientIp);
		
		List<Integer> allPort = new ArrayList<Integer>();
		List<Integer> portsToRemove = new ArrayList<Integer>();
		
		for(TunnelServer tunneling : tunnelServers.values()){
			allPort.addAll(tunneling.getAllPorts().values());
		}
		
		int totalUsage = 0;
		
		for(Entry<Integer, String> entry : portClientMap.entrySet()){
			if(allPort.contains(entry.getKey())){
				if(entry.getValue().equals(clientIp)){
					totalUsage++;
				}
			}else{
				portsToRemove.add(entry.getKey());
			}
		}
		
		if(!portsToRemove.isEmpty()){
			for(Integer port : portsToRemove){
				portClientMap.remove(port);
			}
		}
		
		return tokenQuota.compareTo(new Integer(totalUsage)) > 0 ? true : false; 
	}
	
	
	private boolean releaseInstancePort(String tokenId, Integer port){
		for(TunnelServer tunneling : tunnelServers.values()){
			
			Integer actualPort = tunneling.getAllPorts().get(tokenId);
			
			if( actualPort != null && (actualPort.compareTo(port)== 0) ){
				tunneling.releasePort(port);
				if(tunneling.getActiveTokensNumber() == 0){
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
	
	private void removeTunnelServer(TunnelServer tunneling) throws InterruptedException{
		if(tunneling != null){
			tunneling.stop();
			LOGGER.warn("Removing ssh server with port: "+tunneling.getSshTunnelPort());
			tunnelServers.remove(tunneling.getSshTunnelPort());
		}
	}

	protected void setTunnelServers(Map<Integer, TunnelServer> tunnelServers) {
		this.tunnelServers = tunnelServers;
	}
	
	
}