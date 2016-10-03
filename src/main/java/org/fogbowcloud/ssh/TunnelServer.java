package org.fogbowcloud.ssh;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.ForwardingFilter;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.Session.AttributeKey;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthNone;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.session.ServerSession;
import org.fogbowcloud.ssh.model.Token;

public class TunnelServer {

	private static final Logger LOGGER = Logger.getLogger(TunnelServer.class);
	
	private static final int TOKEN_EXPIRATION_TIMEOUT = 1000 * 60 * 10; // 10min in ms
	
	private static final AttributeKey<String> TOKEN = new AttributeKey<String>();
	private List<Token> tokens = new ArrayList<Token>();

	private SshServer sshServer;
	private String sshTunnelHost;
	private int sshTunnelPort;
	private int lowerPort;
	private int higherPort;
	private String hostKeyPath;
	private Long idleTokenTimeout;
	
	private int nioWorkers;
	
	public TunnelServer(String sshTunnelHost, int sshTunnelPort, int lowerPort, 
			int higherPort, Long idleTokenTimeout, String hostKeyPath, List<Token> tokens) {
		this.sshTunnelHost = sshTunnelHost;
		this.sshTunnelPort = sshTunnelPort;
		this.lowerPort = lowerPort;
		this.higherPort = higherPort;
		this.idleTokenTimeout = idleTokenTimeout == null ? TOKEN_EXPIRATION_TIMEOUT
				: idleTokenTimeout;
		this.hostKeyPath = hostKeyPath;
		//+2 is to have a secure margin of works for ports. If number of ports is 5, workers will be set to 6;
		this.nioWorkers = (higherPort - lowerPort)+2; 
		this.tokens = tokens;
	}
	
	public synchronized Token createPort(String tokenId) {
		if(tokenId == null){
			return null;
		}
		Integer newPort = null;
		for(Token token : tokens){
			if(tokenId.equals(token.getTokenId())){
				return token;
			}
		}
		
		for (int port = lowerPort; port <= higherPort; port++) {
			if (isTaken(port)) {
				continue;
			}
			newPort = port;
			break;
		}
		if (newPort == null) {
			LOGGER.debug("Token [" + tokenId + "] didn't get any port. All ports are busy.");
			return null;
		}
		
		LOGGER.debug("Token [" + tokenId + "] got port [" + newPort + "].");
		Token newToken = new Token(tokenId, newPort, sshTunnelPort);
		tokens.add(newToken);
		return newToken;
	}
	
	private boolean isTaken(int port) {
		for (Token token : tokens) {
			if (token.getPort().equals(port)) {
				return true;
			}
		}
		return false;
	}

	private ReverseTunnelForwarder getActiveSession(int port) {
		List<AbstractSession> activeSessions = sshServer.getActiveSessions();
		for (AbstractSession session : activeSessions) {
			Service rawService = ((ReverseTunnelSession)session).getService();
			if (rawService == null) {
				continue;
			}
			if (!(rawService instanceof ServerConnectionService)) {
				continue;
			}
			ServerConnectionService service = (ServerConnectionService) rawService;
			ReverseTunnelForwarder f = (ReverseTunnelForwarder) service.getTcpipForwarder();
			for (SshdSocketAddress address : f.getLocalForwards()) {
				if (address.getPort() == port) {
					return f;
				}
			}
		}
		return null;
	}

	public void start() throws IOException {
		this.sshServer = SshServer.setUpDefaultServer();
		SimpleGeneratorHostKeyProvider keyPairProvider = new SimpleGeneratorHostKeyProvider(hostKeyPath);
		keyPairProvider.loadKeys();
		sshServer.setKeyPairProvider(keyPairProvider);
		sshServer.setCommandFactory(createUnknownCommandFactory());
		LinkedList<NamedFactory<UserAuth>> userAuthenticators = new LinkedList<NamedFactory<UserAuth>>();
		
		userAuthenticators.add(new NamedFactory<UserAuth>(){
			@Override
			public UserAuth create() {
				return new UserAuthNone() {
					@Override
					public Boolean auth(ServerSession session, String username,
							String service, Buffer buffer) throws Exception {
						
						boolean hasSession = false;
						
						for(Token token : tokens){
							if(username.equals(token.getTokenId())){
								hasSession = true;
							}
						}
						
						if (!hasSession) {
							session.close(true);
							return false;
						}
						session.setAttribute(TOKEN, username);
						return true;
					}
				};
			}

			@Override
			public String getName() {
				return "none";
			}});
		
		sshServer.setTcpipForwardingFilter(createAcceptAllFilter());
		sshServer.setTcpipForwarderFactory(new ReverseTunnelForwarderFactory());
		sshServer.setSessionFactory(new ReverseTunnelSessionFactory());
		sshServer.setUserAuthFactories(userAuthenticators);
		sshServer.setHost(sshTunnelHost == null ? "0.0.0.0" : sshTunnelHost);
		sshServer.setPort(sshTunnelPort);
		sshServer.setNioWorkers(nioWorkers);
		
		sshServer.start();
	}

	private static CommandFactory createUnknownCommandFactory() {
		return new CommandFactory() {
			@Override
			public Command createCommand(String command) {
				return new UnknownCommand(command);
			}
		};
	}

	private ForwardingFilter createAcceptAllFilter() {
		return new ForwardingFilter() {
			@Override
			public boolean canListen(SshdSocketAddress address, Session session) {
				String username = session.getAttribute(TOKEN);
				if (username == null) {
					session.close(true);
					return false;
				}
				
				Token token = null;
				
				for(Token t : tokens){
					if(username.equals(token.getTokenId())){
						t = token;
					}
				}
				
				if (token == null || !token.getPort().equals(address.getPort())) {
					session.close(true);
					return false;
				}
				ReverseTunnelForwarder existingSession = getActiveSession(token.getPort());
				if (existingSession != null) {
					existingSession.close(true);
				}
				return true;
			}
			
			@Override
			public boolean canForwardX11(Session session) {
				return false;
			}
			
			@Override
			public boolean canForwardAgent(Session session) {
				return true;
			}
			
			@Override
			public boolean canConnect(SshdSocketAddress address, Session session) {
				return true;
			}
		};
	}

	public Integer getPort(String tokenId) {
		
		if(tokenId == null){
			return null;
		}
		
		for (Token token : tokens) {
			if(tokenId.equals(token.getTokenId())){
				return token.getPort();
			}
		}
		return null;
	}
	
	public List<Token> getAllPorts() {
		
		return tokens;
	}
	
	public Map<String, Integer> getPortByPrefix(String tokenId) {
		Map<String, Integer> portsByPrefix = new HashMap<String, Integer>();
		Integer sshPort = getPort(tokenId);
		if (sshPort != null) {
			portsByPrefix.put("ssh", sshPort);
		}
		for (Token token : tokens) {
			String tokenPrefix = tokenId + "-";
			if (token.getTokenId().startsWith(tokenPrefix)) {
				portsByPrefix.put(
						token.getTokenId().substring(tokenPrefix.length()), 
						token.getPort());
			}
		}
		return portsByPrefix;
	}
	
	public boolean isServerBusy(){
		for (int port = lowerPort; port <= higherPort; port++) {
			if (!isTaken(port)) {
				return false;
			}
		}
		return true;
	}
	
	//TODO: Create a new method to remove a token and release the relative port. 
	public void removeToken(String tokenId){
		tokens.remove(tokenId);
		
	}
	
	public Token releasePort(Integer port){
		if(port != null){
			Token tokenToRemove = null;
			for(Token token : tokens){
				if(port.compareTo(token.getPort()) == 0){
					tokenToRemove = token;
					break;
				}
			}
			
			if(this.getActiveSession(port.intValue()) != null){
				this.getActiveSession(port.intValue()).close(true);
			}
			tokens.remove(tokenToRemove);
			return tokenToRemove;
		}
		return null;
	}
	
	public void stop() throws InterruptedException{
		
		List<AbstractSession> activeSessions = sshServer.getActiveSessions();
		if(activeSessions != null && !activeSessions.isEmpty()){
			for (AbstractSession session : activeSessions) {
				session.close(true);
			}
		}
		sshServer.stop(true);
		
	}
	
	public Set<Token> getExpiredTokens(){
		
		Set<Token> tokensToExpire = new HashSet<Token>();
		for (Token token : tokens) {
			if (getActiveSession(token.getPort()) == null) {
				long now = System.currentTimeMillis();
				if (token.getLastIdleCheck() == 0) {
					token.setLastIdleCheck(now);
				}
				if (now - token.getLastIdleCheck() > idleTokenTimeout) {
					tokensToExpire.add(token);
				}
			} else {
				token.setLastIdleCheck(0L);
			}
		}
		for (Token token : tokensToExpire) {
			LOGGER.debug("Expiring token [" + token + "].");
			tokens.remove(token);
		}
		return tokensToExpire;

	}

	public int getActiveTokensNumber(){
		return tokens.size();
	}
	
	public int getLowerPort() {
		return lowerPort;
	}

	public int getHigherPort() {
		return higherPort;
	}

	public int getSshTunnelPort() {
		return sshTunnelPort;
	}

	public List<Token> getTokens() {
		return tokens;
	}

	public void setTokens(List<Token> tokens) {
		this.tokens = tokens;
	}

	public String getSshTunnelHost() {
		return sshTunnelHost;
	}

	public Long getIdleTokenTimeout() {
		return idleTokenTimeout;
	}

	public void setIdleTokenTimeout(Long idleTokenTimeout) {
		this.idleTokenTimeout = idleTokenTimeout;
	}

	public String getHostKeyPath() {
		return hostKeyPath;
	}

	public void setHostKeyPath(String hostKeyPath) {
		this.hostKeyPath = hostKeyPath;
	}

	public void setLowerPort(int lowerPort) {
		this.lowerPort = lowerPort;
	}

	public void setHigherPort(int higherPort) {
		this.higherPort = higherPort;
	}

	
}