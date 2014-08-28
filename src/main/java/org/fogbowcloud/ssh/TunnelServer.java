package org.fogbowcloud.ssh;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.ForwardingFilter;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
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

	private static final org.apache.sshd.common.Session.AttributeKey<String> TOKEN = new org.apache.sshd.common.Session.AttributeKey<String>();
	private final Map<String, Integer> tokens = new HashMap<String, Integer>();
	
	private SshServer sshServer;
	private int sshTunnelPort;
	private int lowerPort;
	private int higherPort;
	private String hostKeyPath;
	
	public TunnelServer(int sshTunnelPort, int lowerPort, 
			int higherPort, String hostKeyPath) {
		this.sshTunnelPort = sshTunnelPort;
		this.lowerPort = lowerPort;
		this.higherPort = higherPort;
		this.hostKeyPath = hostKeyPath;
	}

	public Integer createPort(String token) {
		Integer newPort = null;
		for (int port = lowerPort; port <= higherPort; port++) {
			if (isActiveSession(port) || isTaken(port)) {
				continue;
			}
			newPort = port;
			break;
		}
		tokens.put(token, newPort);
		return newPort;
	}
	
	private boolean isTaken(int port) {
		return tokens.values().contains(port);
	}

	private boolean isActiveSession(int port) {
		List<AbstractSession> activeSessions = sshServer.getActiveSessions();
		for (AbstractSession session : activeSessions) {
			ServerConnectionService service = session.getService(ServerConnectionService.class);
			ReverseTunnelForwarder f = (ReverseTunnelForwarder) service.getTcpipForwarder();
			for (SshdSocketAddress address : f.getLocalForwards()) {
				if (address.getPort() == port) {
					return true;
				}
			}
		}
		return false;
	}

	public void start() throws IOException {
		this.sshServer = SshServer.setUpDefaultServer();
		sshServer.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(hostKeyPath));
		sshServer.setCommandFactory(createUnknownCommandFactory());
		LinkedList<NamedFactory<UserAuth>> userAuthenticators = new LinkedList<NamedFactory<UserAuth>>();
		
		userAuthenticators.add(new NamedFactory<UserAuth>(){
			@Override
			public UserAuth create() {
				return new UserAuthNone() {
					@Override
					public Boolean auth(ServerSession session, String username,
							String service, Buffer buffer) throws Exception {
						Integer expectedPort = tokens.get(username);
						if (expectedPort == null) {
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
		sshServer.setTcpipForwarderFactory(new ReverseTunnelForwarderFactory(tokens));
		sshServer.setUserAuthFactories(userAuthenticators);
		sshServer.setPort(sshTunnelPort);
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
				Integer expectedPort = tokens.get(username);
				if (expectedPort == null || !expectedPort.equals(address.getPort())) {
					session.close(true);
					return false;
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
		return tokens.get(tokenId);
	}
	
}
