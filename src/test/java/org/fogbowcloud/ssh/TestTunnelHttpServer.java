package org.fogbowcloud.ssh;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import fi.iki.elonen.NanoHTTPD.CookieHandler;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Method;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.ResponseException;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class TestTunnelHttpServer {

	private TunnelHttpServer tunnelHttpServer;
	private TunnelServer tunnelServerMock;

	// Default values.
	private String hostKeyPath = "DEFAULT_VALUE";
	private int lowerPort = 100;
	private int higherPort = 110;
	private String sshTunnelHost = "127.0.0.1";
	private int lowerSshTunnelPort = 200;
	private int higherSshTunnelPort = 204;
	private Long idleTokenTimeout = (long) 600;
	private int portsPerShhServer = 5;
	private int httpPort = 300;

	@Before
	public void setUp() {
		tunnelServerMock = Mockito.mock(TunnelServer.class);
	}

	@After
	public void tearDown() {
	}

	@Test
	public void testPostToken() throws Exception {

		tunnelHttpServer = new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort, higherSshTunnelPort,
				lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer);

		String mockClientIp = "150.160.0.40";
		String mockClientToken = "Token01";
		String uriCalled = "/token/" + mockClientToken;

		IHTTPSession session = this.createMockSession(Method.POST, uriCalled, mockClientIp);

		Mockito.doReturn(lowerPort).when(tunnelServerMock).createPort(mockClientToken);
		Mockito.doReturn(lowerSshTunnelPort).when(tunnelServerMock).getSshTunnelPort();
		Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
		tunnelServers.put(new Integer(lowerSshTunnelPort), tunnelServerMock);

		tunnelHttpServer.setTunnelServers(tunnelServers);
		Response httpResponse = tunnelHttpServer.serve(session);

		String responseData = this.getResponseDataAsString(httpResponse);
		String[] portsSplit = responseData.split(":");

		assertTrue(portsSplit.length == 2);
		assertTrue(Utils.isNumber(portsSplit[0]));
		assertTrue(Utils.isNumber(portsSplit[1]));

		int clientPort = Integer.parseInt(portsSplit[0]);
		int sshServerPort = Integer.parseInt(portsSplit[1]);

		assertEquals(lowerPort, clientPort);
		assertEquals(lowerSshTunnelPort, sshServerPort);

	}
	
	@Test
	public void testGetPortByToken() throws Exception {

		tunnelHttpServer = new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort, higherSshTunnelPort,
				lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer);

		String mockClientIp = "150.160.0.40";
		String mockClientToken = "Token01";
		String uriCalled = "/token/" + mockClientToken;

		IHTTPSession session = this.createMockSession(Method.POST, uriCalled, mockClientIp);

		tunnelServerMock = Mockito.spy(new TunnelServer(sshTunnelHost, lowerSshTunnelPort, lowerPort,
				lowerPort + (portsPerShhServer - 1), idleTokenTimeout, hostKeyPath));

		Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
		tunnelServers.put(new Integer(lowerSshTunnelPort), tunnelServerMock);

		tunnelHttpServer.setTunnelServers(tunnelServers);
		Response httpResponse = tunnelHttpServer.serve(session);

		String responseData = this.getResponseDataAsString(httpResponse);
		String[] portsSplit = responseData.split(":");

		assertTrue(portsSplit.length == 2);
		assertTrue(Utils.isNumber(portsSplit[0]));
		assertTrue(Utils.isNumber(portsSplit[1]));

		int clientPort = Integer.parseInt(portsSplit[0]);
		int sshServerPort = Integer.parseInt(portsSplit[1]);

		assertEquals(lowerPort, clientPort);
		assertEquals(lowerSshTunnelPort, sshServerPort);
		
		session = this.createMockSession(Method.GET, uriCalled, mockClientIp);
		httpResponse = tunnelHttpServer.serve(session);
		responseData = this.getResponseDataAsString(httpResponse);
		assertTrue(Utils.isNumber(responseData));
		clientPort = Integer.parseInt(responseData);

		assertEquals(lowerPort, clientPort);
			
	}

	@Test
	public void testPostTokenNoQuota() throws Exception {

		int quota = 4;

		Queue<Integer> portQueue = new ArrayBlockingQueue<Integer>(quota);
		for (int count = lowerPort; count < lowerPort + quota; count++) {
			portQueue.add(new Integer(count));
		}

		tunnelHttpServer = new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort, higherSshTunnelPort,
				lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer);

		String mockClientIp = "150.160.0.40";
		String mockClientToken = "Token01";
		String uriCalled = "";

		tunnelServerMock = Mockito.spy(new TunnelServer(sshTunnelHost, lowerSshTunnelPort, lowerPort,
				lowerPort + (portsPerShhServer - 1), idleTokenTimeout, hostKeyPath));

		Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
		tunnelServers.put(new Integer(lowerSshTunnelPort), tunnelServerMock);

		tunnelHttpServer.setTunnelServers(tunnelServers);

		IHTTPSession session;
		
		Response httpResponse = null;
		for (int count = 0; count < quota - 1; count++) {
			uriCalled = "/token/" + mockClientToken+count + ":" + quota;
			session = this.createMockSession(Method.POST, uriCalled, mockClientIp);
			httpResponse = tunnelHttpServer.serve(session);
		}
		
		uriCalled = "/token/newToken:" + quota;
		session = this.createMockSession(Method.POST, uriCalled, mockClientIp);
		
		httpResponse = tunnelHttpServer.serve(session);
		String responseData = this.getResponseDataAsString(httpResponse);
		String[] portsSplit = responseData.split(":");

		assertTrue(portsSplit.length == 2);
		assertTrue(Utils.isNumber(portsSplit[0]));
		assertTrue(Utils.isNumber(portsSplit[1]));

		int clientPort = Integer.parseInt(portsSplit[0]);
		int sshServerPort = Integer.parseInt(portsSplit[1]);

		assertEquals(lowerPort + (quota - 1), clientPort);
		assertEquals(lowerSshTunnelPort, sshServerPort);

		uriCalled = "/token/lastToken:" + quota;
		session = this.createMockSession(Method.POST, uriCalled, mockClientIp);
		httpResponse = tunnelHttpServer.serve(session);

		assertEquals(Status.FORBIDDEN, httpResponse.getStatus());

	}
	
	@Test
	public void testPostTokenTowClients() throws Exception {

		int quota = 4;

		Queue<Integer> portQueue = new ArrayBlockingQueue<Integer>(quota);
		for (int count = lowerPort; count < lowerPort + quota; count++) {
			portQueue.add(new Integer(count));
		}

		tunnelHttpServer = new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort, higherSshTunnelPort,
				lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer);

		String mockClientIpA = "150.160.0.40";
		String mockClientIpB = "150.160.0.41";
		String mockClientToken = "Token01";
		String uriCalled = "";

		tunnelServerMock = Mockito.spy(new TunnelServer(sshTunnelHost, lowerSshTunnelPort, lowerPort,
				lowerPort + (portsPerShhServer - 1), idleTokenTimeout, hostKeyPath));

		Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
		tunnelServers.put(new Integer(lowerSshTunnelPort), tunnelServerMock);

		tunnelHttpServer.setTunnelServers(tunnelServers);

		IHTTPSession session;
		
		Response httpResponse = null;
		for (int count = 0; count < quota - 1; count++) {
			uriCalled = "/token/" + mockClientToken+count + ":" + quota;
			session = this.createMockSession(Method.POST, uriCalled, mockClientIpA);
			httpResponse = tunnelHttpServer.serve(session);
		}
		
		uriCalled = "/token/newToken:" + quota;
		session = this.createMockSession(Method.POST, uriCalled, mockClientIpB);
		
		httpResponse = tunnelHttpServer.serve(session);
		String responseData = this.getResponseDataAsString(httpResponse);
		String[] portsSplit = responseData.split(":");

		assertTrue(portsSplit.length == 2);
		assertTrue(Utils.isNumber(portsSplit[0]));
		assertTrue(Utils.isNumber(portsSplit[1]));

		int clientPort = Integer.parseInt(portsSplit[0]);
		int sshServerPort = Integer.parseInt(portsSplit[1]);

		assertEquals(lowerPort + (quota - 1), clientPort);
		assertEquals(lowerSshTunnelPort, sshServerPort);

		uriCalled = "/token/lastToken:" + quota;
		session = this.createMockSession(Method.POST, uriCalled, mockClientIpA);
		httpResponse = tunnelHttpServer.serve(session);
		responseData = this.getResponseDataAsString(httpResponse);
		portsSplit = responseData.split(":");

		clientPort = Integer.parseInt(portsSplit[0]);
		sshServerPort = Integer.parseInt(portsSplit[1]);

		assertEquals(lowerPort + (quota), clientPort);
		assertEquals(lowerSshTunnelPort, sshServerPort);

	}
	
	@Test
	public void testPostTokenNoServer() throws Exception {

		int quota = 4;

		Queue<Integer> portQueue = new ArrayBlockingQueue<Integer>(quota);
		for (int count = lowerPort; count < lowerPort + quota; count++) {
			portQueue.add(new Integer(count));
		}

		tunnelHttpServer = new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort, lowerSshTunnelPort,
				lowerPort, higherPort, idleTokenTimeout, hostKeyPath, 2);

		String mockClientIpA = "150.160.0.40";
		String mockClientIpB = "150.160.0.41";
		String mockClientToken = "Token01";
		String uriCalled = "";

		tunnelServerMock = Mockito.spy(new TunnelServer(sshTunnelHost, lowerSshTunnelPort, lowerPort,
				lowerPort + 1, idleTokenTimeout, hostKeyPath));

		Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
		tunnelServers.put(new Integer(lowerSshTunnelPort), tunnelServerMock);

		tunnelHttpServer.setTunnelServers(tunnelServers);

		IHTTPSession session;
		
		for (int count = 0; count < 2; count++) {
			uriCalled = "/token/" + mockClientToken+count + ":" + quota;
			session = this.createMockSession(Method.POST, uriCalled, mockClientIpA);
			tunnelHttpServer.serve(session);
		}
		
		uriCalled = "/token/lastToken:" + quota;
		session = this.createMockSession(Method.POST, uriCalled, mockClientIpB);
		
		Response httpResponse = tunnelHttpServer.serve(session);
		
		assertEquals(Status.FORBIDDEN, httpResponse.getStatus());

	}

	private String getResponseDataAsString(Response httpResponse) {

		ByteArrayInputStream arrayInputStream = (ByteArrayInputStream) httpResponse.getData();
		Scanner scanner = new Scanner(arrayInputStream);
		scanner.useDelimiter("\\Z");// To read all scanner content in one String
		String data = "";
		if (scanner.hasNext())
			data = scanner.next();

		scanner.close();
		try {
			arrayInputStream.close();
		} catch (IOException e) {
			return "";
		}

		return data;
	}

	private IHTTPSession createMockSession(final Method method, final String uri, String clientIp) {

		String REMOTE_ADDR = "remote-addr";
		String HTTP_CLIENT_IP = "http-client-ip";

		final Map<String, String> headers = new HashMap<String, String>();
		headers.put(REMOTE_ADDR, clientIp);
		headers.put(HTTP_CLIENT_IP, clientIp);

		IHTTPSession httpSession = new IHTTPSession() {

			@Override
			public void parseBody(Map<String, String> arg0) throws IOException, ResponseException {
			}

			@Override
			public String getUri() {
				return uri;
			}

			@Override
			public String getQueryParameterString() {
				return null;
			}

			@Override
			public Map<String, String> getParms() {
				return null;
			}

			@Override
			public Method getMethod() {
				return method;
			}

			@Override
			public InputStream getInputStream() {
				return null;
			}

			@Override
			public Map<String, String> getHeaders() {
				return headers;
			}

			@Override
			public CookieHandler getCookies() {
				return null;
			}

			@Override
			public void execute() throws IOException {
			}
		};

		return httpSession;
	}

}
