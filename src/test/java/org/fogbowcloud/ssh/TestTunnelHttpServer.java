package org.fogbowcloud.ssh;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.fogbowcloud.ssh.db.TokenDataStore;
import org.fogbowcloud.ssh.db.TunnelServerDataStore;
import org.fogbowcloud.ssh.model.Token;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Method;
import fi.iki.elonen.NanoHTTPD.Response;

public class TestTunnelHttpServer {

	private TunnelHttpServer tunnelHttpServer;
	//private Map<Integer, TunnelServer> tunnelServers = new HashMap<Integer, TunnelServer>();
	private TokenDataStore tokenDsMock;
	private TunnelServerDataStore tunnelServerDsMock;
	
	private String sshTunnelHost = "10.0.0.10";
	private Long idleTokenTimeout = (long) 100000;
	private int httpPort = 2223;

	private int lowerSshTunnelPort = 10;
	private int higherSshTunnelPort = 20;
	private int lowerPort = 10000;
	private int higherPort = 20000;

	String hostKeyPath = "/path";
	int portsPerShhServer = 2;
	
	String tempDataBaseFile = "tempdb.db";

	@Before
	public void setup() throws Exception {

		tokenDsMock = Mockito.mock(TokenDataStore.class);
		tunnelServerDsMock = Mockito.mock(TunnelServerDataStore.class);
		
		tunnelHttpServer = Mockito.spy(new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort,
				higherSshTunnelPort, lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer,
				tokenDsMock, tunnelServerDsMock, false, false));

		Mockito.doReturn(true).when(tunnelHttpServer)
				.startTunnelServer(Mockito.any(TunnelServer.class));

	}

	@After
	public void tearDown() throws Exception {
		File file = new File(tempDataBaseFile);
		if(file.exists()){
			file.delete();
		}
	}

	@Test
	public void testCreateNewTunnelServer() throws Exception {

		//IHTTPSession sessionMock = Mockito.mock(IHTTPSession.class);
		tunnelHttpServer.setTunnelServers(new ArrayList<TunnelServer>());
		TunnelServer tunnelServer = tunnelHttpServer.createNewTunnelServer();
		
		assertNotNull(tunnelServer);
		assertEquals(1, tunnelHttpServer.getAllTunnelServers().size());
		assertEquals(lowerSshTunnelPort, tunnelServer.getSshTunnelPort());
		assertEquals(lowerPort, tunnelServer.getLowerPort());
		assertEquals(getMaxPort(tunnelServer.getLowerPort(), portsPerShhServer), tunnelServer.getHigherPort());
		
	}
	
	@Test
	public void testPostNewPort() throws Exception {

		String tokenId = "token01";
		
		IHTTPSession sessionMock = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMock).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenId).when(sessionMock).getUri();

		Response reponse = tunnelHttpServer.serve(sessionMock);
		String responseString = returnResponseString(reponse);
		
		String[] split =  responseString.split(":");
		
		assertNotNull(split);
		assertEquals(2, split.length);
		
		String port = split[0];
		String sshServerPort = split[1]; 
		
		assertEquals(String.valueOf(lowerPort), port);
		assertEquals(String.valueOf(lowerSshTunnelPort), sshServerPort);
		
		
	}
	
	@Test
	public void testGetPort() throws Exception {

		String tokenId = "token01";
		
		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenId).when(sessionMockA).getUri();

		Response reponseA = tunnelHttpServer.serve(sessionMockA);
		String responseString = returnResponseString(reponseA);
		
		String[] split =  responseString.split(":");
		
		assertNotNull(split);
		assertEquals(2, split.length);
		
		String portA = split[0];
		String sshServerPortA = split[1]; 
		
		assertEquals(String.valueOf(lowerPort), portA);
		assertEquals(String.valueOf(lowerSshTunnelPort), sshServerPortA);
		
		IHTTPSession sessionMockB = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.GET).when(sessionMockB).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenId).when(sessionMockB).getUri();
		
		Response reponseB = tunnelHttpServer.serve(sessionMockB);
		String portB = returnResponseString(reponseB);
		
		assertEquals(portA, portB);
		
	}
	
	@Test
	public void testPostSameToken() throws Exception {

		String tokenId = "token01";
		
		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenId).when(sessionMockA).getUri();

		Response reponseA = tunnelHttpServer.serve(sessionMockA);
		String responseString = returnResponseString(reponseA);
		
		String[] split =  responseString.split(":");
		
		assertNotNull(split);
		assertEquals(2, split.length);
		
		String portA = split[0];
		String sshServerPortA = split[1]; 
		
		assertEquals(String.valueOf(lowerPort), portA);
		assertEquals(String.valueOf(lowerSshTunnelPort), sshServerPortA);
		
		Response reponseB = tunnelHttpServer.serve(sessionMockA);
		responseString = returnResponseString(reponseB);
		
		split =  responseString.split(":");
		
		assertNotNull(split);
		assertEquals(2, split.length);
		
		String portB = split[0];
		String sshServerPortB = split[1]; 
		
		assertEquals(portA, portB);
		assertEquals(sshServerPortA, sshServerPortB);
		
	}
	
	@Test
	public void testPostTokenWithDisponibleSshServer() throws Exception {

		String tokenIdA = "tokenA"; //Expect to get 10000
		String tokenIdB = "tokenB"; //Expect to get 10001
		String tokenIdC = "tokenC"; //Expect to get 10004
		String tokenIdD = "tokenD"; //Expect to get 10002
		
		Integer tunnelServerAPort = 10;
		Integer tunnelServerBPort = 11;
		Integer tunnelServerCPort = 12;
		
		String tokenExpectedPort = "10002";
		String tunnelServerExpectedPort = "11";
		
		int lowerPort = this.lowerPort;
		
		List<TunnelServer> tunnelServers = new ArrayList<TunnelServer>();
		
		TunnelServer tunnelServerA = new TunnelServer(sshTunnelHost, tunnelServerAPort, lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>()); // ports 10000 to 10001
		tunnelServerA.createPort(tokenIdA);
		tunnelServerA.createPort(tokenIdB);
		tunnelServers.add(tunnelServerA);
		
		TunnelServer tunnelServerB = new TunnelServer(sshTunnelHost, tunnelServerBPort, ++lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>()); // ports 10002 to 10003
		tunnelServers.add(tunnelServerB);
		
		TunnelServer tunnelServerC = new TunnelServer(sshTunnelHost, tunnelServerCPort, ++lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>()); // ports 10004 to 10005
		tunnelServerC.createPort(tokenIdC);
		tunnelServers.add(tunnelServerC);
		
		tunnelHttpServer.setTunnelServers(tunnelServers);
		
		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdD).when(sessionMockA).getUri();

		Response reponseA = tunnelHttpServer.serve(sessionMockA);
		String responseString = returnResponseString(reponseA);
		
		String[] split =  responseString.split(":");
		
		assertNotNull(split);
		assertEquals(2, split.length);
		
		String portA = split[0];
		String sshServerPortA = split[1]; 
		
		assertEquals(tokenExpectedPort, portA);
		assertEquals(tunnelServerExpectedPort, sshServerPortA);
		
		
	}
	
	@Test
	public void testPostSameTokenWithDisponibleSshServer() throws Exception {

		String tokenIdA = "tokenA"; //Expect to get 10000
		String tokenIdB = "tokenB"; //Expect to get 10002
		String tokenIdC = "tokenC"; //Expect to get 10003
		String tokenIdD = "tokenD"; //Expect to get 10004
		
		Integer tunnelServerAPort = 10;
		Integer tunnelServerBPort = 11;
		Integer tunnelServerCPort = 12;
		Integer tunnelServerDPort = 13;
		
		String tokenExpectedPort = "10004";
		String tunnelServerExpectedPort = "12";
		
		int lowerPort = this.lowerPort;
		
		List<TunnelServer> tunnelServers = new ArrayList<TunnelServer>();
		
		TunnelServer tunnelServerA = new TunnelServer(sshTunnelHost, tunnelServerAPort, lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>()); // ports 10000 to 10001
		tunnelServerA.createPort(tokenIdA);
		tunnelServers.add(tunnelServerA);
		
		TunnelServer tunnelServerB = new TunnelServer(sshTunnelHost, tunnelServerBPort, ++lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>()); // ports 10002 to 10003
		tunnelServerB.createPort(tokenIdB);
		tunnelServerB.createPort(tokenIdC);
		tunnelServers.add(tunnelServerB);
		
		TunnelServer tunnelServerC = new TunnelServer(sshTunnelHost, tunnelServerCPort, ++lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>()); // ports 10004 to 10005
		tunnelServerC.createPort(tokenIdD);
		tunnelServers.add(tunnelServerC);
		
		TunnelServer tunnelServerD = new TunnelServer(sshTunnelHost, tunnelServerDPort, ++lowerPort, ++lowerPort,
				idleTokenTimeout, hostKeyPath, new ArrayList<Token>());
		tunnelServers.add(tunnelServerD);
		
		tunnelHttpServer.setTunnelServers(tunnelServers);
		
		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdD).when(sessionMockA).getUri();

		Response reponseA = tunnelHttpServer.serve(sessionMockA);
		String responseString = returnResponseString(reponseA);
		
		String[] split =  responseString.split(":");
		
		assertNotNull(split);
		assertEquals(2, split.length);
		
		String portA = split[0];
		String sshServerPortA = split[1]; 
		
		assertEquals(tokenExpectedPort, portA);
		assertEquals(tunnelServerExpectedPort, sshServerPortA);
		
	}
	
	@Test
	public void testGetAllTokens() throws Exception {

		String inMemoryDs = "jdbc:sqlite:"+tempDataBaseFile;
		
		tokenDsMock = new TokenDataStore(inMemoryDs);
		tunnelServerDsMock = new TunnelServerDataStore(inMemoryDs);
		
		tunnelHttpServer.setTokenDs(tokenDsMock);
		tunnelHttpServer.setTunnelServerDs(tunnelServerDsMock);
		
		String tokenIdA = "tokenA"; //Expect to get 10000
		String tokenIdB = "tokenB"; //Expect to get 10001
		String tokenIdC = "tokenC"; //Expect to get 10002
		String tokenIdD = "tokenD"; //Expect to get 10003
		
		String expectedPortA = "10000";
		String expectedPortB = "10001";
		String expectedPortC = "10002";
		String expectedPortD = "10003";

		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdA).when(sessionMockA).getUri();
		
		IHTTPSession sessionMockB = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockB).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdB).when(sessionMockB).getUri();
		
		IHTTPSession sessionMockC = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockC).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdC).when(sessionMockC).getUri();
		
		IHTTPSession sessionMockD = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockD).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdD).when(sessionMockD).getUri();

		tunnelHttpServer.serve(sessionMockA);
		tunnelHttpServer.serve(sessionMockB);
		tunnelHttpServer.serve(sessionMockC);
		tunnelHttpServer.serve(sessionMockD);
		
		IHTTPSession sessionGetAll = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.GET).when(sessionGetAll).getMethod();
		Mockito.doReturn("localhost:2223/informations/").when(sessionGetAll).getUri();
		
		Response reponseAllTokens = tunnelHttpServer.serve(sessionGetAll);
		String responseString = returnResponseString(reponseAllTokens);
		JSONArray tokensArray = new JSONArray(responseString);
		
		boolean tokenAFound = false;
		boolean tokenBFound = false;
		boolean tokenCFound = false;
		boolean tokenDFound = false;
		
		boolean allTokensFound = false;
		
		for(int index = 0; index < tokensArray.length(); index++){
			
			JSONObject token = tokensArray.getJSONObject(index);
			String tokenId = token.getString("token");
			Integer tokenPort = token.getInt("port");
			
			if(tokenIdA.equals(tokenId) && expectedPortA.equals(String.valueOf(tokenPort))){
				tokenAFound = true;
			}
			if(tokenIdB.equals(tokenId) && expectedPortB.equals(String.valueOf(tokenPort))){
				tokenBFound = true;
			}
			if(tokenIdC.equals(tokenId) && expectedPortC.equals(String.valueOf(tokenPort))){
				tokenCFound = true;
			}
			if(tokenIdD.equals(tokenId) && expectedPortD.equals(String.valueOf(tokenPort))){
				tokenDFound = true;
			}
		}
		
		allTokensFound = tokenAFound && tokenBFound && tokenCFound && tokenDFound;
		
		assertTrue(allTokensFound);
			
	}
	
	
	@Test
	public void testDataBase() throws Exception {
	
		String inMemoryDs = "jdbc:sqlite:"+tempDataBaseFile;
		
		tokenDsMock = new TokenDataStore(inMemoryDs);
		tunnelServerDsMock = new TunnelServerDataStore(inMemoryDs);
		
		tunnelHttpServer.setTokenDs(tokenDsMock);
		tunnelHttpServer.setTunnelServerDs(tunnelServerDsMock);
		
		String tokenIdA = "tokenA"; //Expect to get 10000
		String tokenIdB = "tokenB"; //Expect to get 10001
		String tokenIdC = "tokenC"; //Expect to get 10002
		String tokenIdD = "tokenD"; //Expect to get 10003
		String tokenIdE = "tokenE"; //Expect to get 10004
		
		String expectedPortA = "10000";
		String expectedPortB = "10001";
		String expectedPortC = "10002";
		String expectedPortD = "10003";
		String expectedPortE = "10004";
		
		String expectedSShServerAB = "10";
		String expectedSShServerCD = "11";

		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdA).when(sessionMockA).getUri();
		
		IHTTPSession sessionMockB = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockB).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdB).when(sessionMockB).getUri();
		
		IHTTPSession sessionMockC = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockC).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdC).when(sessionMockC).getUri();
		
		IHTTPSession sessionMockD = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockD).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdD).when(sessionMockD).getUri();
		
		IHTTPSession sessionMockE = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockE).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdE).when(sessionMockE).getUri();

		tunnelHttpServer.serve(sessionMockA);
		tunnelHttpServer.serve(sessionMockB);
		tunnelHttpServer.serve(sessionMockC);
		
		Token tokenA = tokenDsMock.getTokenPortByPort(Integer.parseInt(expectedPortA));
		List<Token> tokens = tokenDsMock.getAllTokenPorts();
		
		assertNotNull(tokenA);
		assertNotNull(tokens);
		assertEquals(tokenIdA, tokenA.getTokenId());
		assertEquals(expectedPortA, String.valueOf(tokenA.getPort()));
		assertEquals(expectedSShServerAB, String.valueOf(tokenA.getSshServerPort()));
		assertEquals(3, tokens.size());
		
		//Test Restart the server to recover database
		tunnelHttpServer = Mockito.spy(new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort,
				higherSshTunnelPort, lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer,
				tokenDsMock, tunnelServerDsMock, false, false));

		Mockito.doReturn(true).when(tunnelHttpServer)
				.startTunnelServer(Mockito.any(TunnelServer.class));
		
		IHTTPSession sessionMockAGet = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.GET).when(sessionMockAGet).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdA).when(sessionMockAGet).getUri();
		
		Response reponseA = tunnelHttpServer.serve(sessionMockAGet);
		String responseString = returnResponseString(reponseA);
		
		assertNotNull(responseString);
		assertEquals(expectedPortA, responseString);

		Response reponseD = tunnelHttpServer.serve(sessionMockD);
		responseString = returnResponseString(reponseD);
		String[] split =  responseString.split(":");
		
		List<TunnelServer> tunnels = tunnelServerDsMock.getAllTunnelServers();
		
		assertNotNull(split);
		assertEquals(2, split.length);
		assertEquals(expectedPortD, split[0]);
		assertEquals(expectedSShServerCD, split[1]);
		assertNotNull(tunnels);
		assertEquals(2, tunnels.size());
		
		//Test release port
//		sessionMockC = Mockito.mock(IHTTPSession.class);
//		Mockito.doReturn(Method.DELETE).when(sessionMockC).getMethod();
//		Mockito.doReturn("localhost:2223/token/"+tokenIdC+"/"+expectedPortC).when(sessionMockC).getUri();
//		tunnelHttpServer.serve(sessionMockC);
//		
//		Response reponseE = tunnelHttpServer.serve(sessionMockE);
//		responseString = returnResponseString(reponseE);
//		split =  responseString.split(":");
//		
//		tunnels = tunnelServerDsMock.getAllTunnelServers();
//		
//		assertNotNull(split);
//		assertEquals(2, split.length);
//		assertEquals(expectedPortE, split[0]);
//		assertEquals(expectedSShServerCD, split[1]);
//		assertNotNull(tunnels);
//		assertEquals(2, tunnels.size());
		
	}
	
	
	@Test
	public void testCleanDataBase() throws Exception {
	
		String inMemoryDs = "jdbc:sqlite:"+tempDataBaseFile;
		
		tokenDsMock = new TokenDataStore(inMemoryDs);
		tunnelServerDsMock = new TunnelServerDataStore(inMemoryDs);
		
		tunnelHttpServer.setTokenDs(tokenDsMock);
		tunnelHttpServer.setTunnelServerDs(tunnelServerDsMock);
		
		String tokenIdA = "tokenA"; //Expect to get 10000
		String tokenIdB = "tokenB"; //Expect to get 10001
		String tokenIdC = "tokenC"; //Expect to get 10002
		
		String expectedPortA = "10000";
		
		String expectedSShServerAB = "10";

		IHTTPSession sessionMockA = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockA).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdA).when(sessionMockA).getUri();
		
		IHTTPSession sessionMockB = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockB).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdB).when(sessionMockB).getUri();
		
		IHTTPSession sessionMockC = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.POST).when(sessionMockC).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdC).when(sessionMockC).getUri();

		tunnelHttpServer.serve(sessionMockA);
		tunnelHttpServer.serve(sessionMockB);
		tunnelHttpServer.serve(sessionMockC);
		
		Token tokenA = tokenDsMock.getTokenPortByPort(Integer.parseInt(expectedPortA));
		List<Token> tokens = tokenDsMock.getAllTokenPorts();
		
		assertNotNull(tokenA);
		assertNotNull(tokens);
		assertEquals(tokenIdA, tokenA.getTokenId());
		assertEquals(expectedPortA, String.valueOf(tokenA.getPort()));
		assertEquals(expectedSShServerAB, String.valueOf(tokenA.getSshServerPort()));
		assertEquals(3, tokens.size());
		
		boolean cleanDataStore = true;
		
		//Test Restart the server to recover database
		tunnelHttpServer = Mockito.spy(new TunnelHttpServer(httpPort, sshTunnelHost, lowerSshTunnelPort,
				higherSshTunnelPort, lowerPort, higherPort, idleTokenTimeout, hostKeyPath, portsPerShhServer,
				tokenDsMock, tunnelServerDsMock, false, cleanDataStore));

		Mockito.doReturn(true).when(tunnelHttpServer)
				.startTunnelServer(Mockito.any(TunnelServer.class));
		
		IHTTPSession sessionMockAGet = Mockito.mock(IHTTPSession.class);
		Mockito.doReturn(Method.GET).when(sessionMockAGet).getMethod();
		Mockito.doReturn("localhost:2223/token/"+tokenIdA).when(sessionMockAGet).getUri();
		
		Response reponseA = tunnelHttpServer.serve(sessionMockAGet);
		String responseString = returnResponseString(reponseA);
		
		assertNotNull(responseString);
		assertEquals("404 Port Not Found", responseString);

		List<TunnelServer> tunnels = tunnelServerDsMock.getAllTunnelServers();
		tokens = tokenDsMock.getAllTokenPorts();
		
		assertEquals(0, tunnels.size());
		assertEquals(0, tokens.size());
	}

	private String returnResponseString(Response reponse) throws IOException {
		StringWriter writer = new StringWriter();
		IOUtils.copy(reponse.getData(), writer, Charsets.UTF_8);
		String theString = writer.toString();
		return theString;
	}

	
	private int getMaxPort(int actualPort, int numberOfPorts){
		for(int count = 1; count < numberOfPorts; count++){
			actualPort++;
		}
		return actualPort;
	}

}
