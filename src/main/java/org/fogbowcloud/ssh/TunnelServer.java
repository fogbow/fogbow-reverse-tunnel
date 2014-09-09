package org.fogbowcloud.ssh;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.ForwardingFilter;
import org.apache.sshd.common.NamedFactory;
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

public class TunnelServer {

	private static final Logger LOGGER = Logger.getLogger(TunnelServer.class);
	
	private static final long TOKEN_EXPIRATION_CHECK_INTERVAL = 30L; // 30s in seconds
	private static final int TOKEN_EXPIRATION_TIMEOUT = 1000 * 60 * 10; // 10min in ms
	
	private static final AttributeKey<String> TOKEN = new AttributeKey<String>();
	private final Map<String, Token> tokens = new ConcurrentHashMap<String, Token>();
	private ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
	
	static class Token {
		Integer port;
		Long lastIdleCheck = 0L;
		public Token(Integer port) {
			this.port = port;
		}
	}
	
	private SshServer sshServer;
	private String sshTunnelHost;
	private int sshTunnelPort;
	private int lowerPort;
	private int higherPort;
	private String hostKeyPath;
	
	public TunnelServer(String sshTunnelHost, int sshTunnelPort, int lowerPort, 
			int higherPort, String hostKeyPath) {
		this.sshTunnelHost = sshTunnelHost;
		this.sshTunnelPort = sshTunnelPort;
		this.lowerPort = lowerPort;
		this.higherPort = higherPort;
		this.hostKeyPath = hostKeyPath;
	}

	public synchronized Integer createPort(String token) {
		Integer newPort = null;
		if (tokens.containsKey(token)) {
			return tokens.get(token).port;
		}
		for (int port = lowerPort; port <= higherPort; port++) {
			if (isTaken(port)) {
				continue;
			}
			newPort = port;
			break;
		}
		LOGGER.debug("Token [" + token + "] got port [" + newPort + "].");
		tokens.put(token, new Token(newPort));
		return newPort;
	}
	
	private boolean isTaken(int port) {
		for (Token token : tokens.values()) {
			if (token.port.equals(port)) {
				return true;
			}
		}
		return false;
	}

	private ReverseTunnelForwarder getActiveSession(int port) {
		List<AbstractSession> activeSessions = sshServer.getActiveSessions();
		for (AbstractSession session : activeSessions) {
			ServerConnectionService service = session.getService(ServerConnectionService.class);
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
						if (!tokens.containsKey(username)) {
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
		sshServer.setHost(sshTunnelHost);
		sshServer.setPort(sshTunnelPort);
		executor.scheduleWithFixedDelay(new Runnable() {
			@Override
			public void run() {
				Set<String> tokensToExpire = new HashSet<String>();
				for (Entry<String, Token> tokenEntry : tokens.entrySet()) {
					Token token = tokenEntry.getValue();
					if (getActiveSession(token.port) == null) {
						long now = System.currentTimeMillis();
						if (token.lastIdleCheck == 0) {
							token.lastIdleCheck = now;
						}
						if (now - token.lastIdleCheck > TOKEN_EXPIRATION_TIMEOUT) {
							tokensToExpire.add(tokenEntry.getKey());
						}
					} else {
						token.lastIdleCheck = 0L;
					}
				}
				for (String token : tokensToExpire) {
					LOGGER.debug("Expiring token [" + token + "].");
					tokens.remove(token);
				}
			}
		}, 0L, TOKEN_EXPIRATION_CHECK_INTERVAL, TimeUnit.SECONDS);
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
				Token token = tokens.get(username);
				if (token == null || !token.port.equals(address.getPort())) {
					session.close(true);
					return false;
				}
				ReverseTunnelForwarder existingSession = getActiveSession(token.port);
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
		Token token = tokens.get(tokenId);
		if (token == null) {
			return null;
		}
		return token.port;
	}
	
}
