package org.fogbowcloud.ssh;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.util.Base64;
import org.json.JSONObject;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class TunnelHttpServer extends NanoHTTPD {
	
	//private TunnelServer tunneling;
	
	private Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
	
	private String hostKeyPath;
	private KeyPair kp;
	
	private int lowerPort;
	private int higherPort;
	private String sshTunnelHost;
	private int lowerSshTunnelPort;
	private int higherSshTunnelPort;
	private Long idleTokenTimeout;
	
	private int portsPerShhServer;

	public TunnelHttpServer(int httpPort, String sshTunnelHost, int lowerSshTunnelPort, int higherSshTunnelPort, 
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
		
		try {
			this.createNewTunnelServer();
		} catch (IOException e) {
			e.printStackTrace();
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
				
				//TODO verify if the request can request new port. (ports quota per instance.)
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
						return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT, "");
					}
				}
				
				if (instancePort == null) {
					return new NanoHTTPD.Response(Status.INTERNAL_ERROR, MIME_PLAINTEXT, "");
				}
				//Return format: instancePort:sshTunnelServerPort (int:int) 
				return new NanoHTTPD.Response(instancePort.toString()+":"+sshServerPort.toString());
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
	
	//TODO: Create new method to create a new TunnelServer.
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
	
	//TODO: Create new method to validate if the requester have available quota to request new port. 
	private boolean releaseInstancePort(String tokenId, Integer port){
		for(TunnelServer tunneling : tunnelServers.values()){
			
			Integer actualPort = tunneling.getAllPorts().get(tokenId);
			
			if( actualPort != null && (actualPort.compareTo(port)== 0) ){
				tunneling.releasePort(port);
				if(tunneling.getTotalUsedPorts() == 0){
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
			tunnelServers.remove(tunneling.getSshTunnelPort());
		}
	}
}