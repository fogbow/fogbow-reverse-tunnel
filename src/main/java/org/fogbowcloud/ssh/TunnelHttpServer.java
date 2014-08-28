package org.fogbowcloud.ssh;

import java.io.IOException;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;

public class TunnelHttpServer extends NanoHTTPD {

	private TunnelServer tunneling;

	public TunnelHttpServer(int httpPort, int sshTunnelPort, 
			int lowerPort, int higherPort, String hostKeyPath) {
		super(httpPort);
		try {
			this.tunneling = new TunnelServer(sshTunnelPort, 
					lowerPort, higherPort, hostKeyPath);
			this.tunneling.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public Response serve(IHTTPSession session) {
		Method method = session.getMethod();
		String uri = session.getUri();
		String[] splitUri = uri.split("\\/");
		if (splitUri.length != 3) {
			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
		}
		if (!splitUri[1].equals("token")) {
			return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
		}
		String tokenId = splitUri[2];

		if (method.equals(Method.GET)) {
			Integer port = this.tunneling.getPort(tokenId);
			if (port == null) {
				return new NanoHTTPD.Response(Status.NOT_FOUND, 
						MIME_PLAINTEXT, "404 Port Not Found");
			}
			return new NanoHTTPD.Response(port.toString());
		}
		
		if (method.equals(Method.POST)) {
			Integer port = this.tunneling.createPort(tokenId);
			if (port == null) {
				return new NanoHTTPD.Response(Status.INTERNAL_ERROR, 
						MIME_PLAINTEXT, "Internal error");
			}
			return new NanoHTTPD.Response(port.toString());
		}

		return new NanoHTTPD.Response(Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "");
	}

}
