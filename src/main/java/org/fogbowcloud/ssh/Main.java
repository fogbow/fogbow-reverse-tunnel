package org.fogbowcloud.ssh;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Main {

	public static void main(String[] args) throws IOException {
		Properties properties = new Properties();
		FileInputStream input = new FileInputStream(args[0]);
		properties.load(input);

		String tunnelPort = properties.getProperty("tunnel_port");
		String tunnelHost = properties.getProperty("tunnel_host");
		String httpPort = properties.getProperty("http_port");
		String externalPortRange = properties.getProperty("external_port_range");
		String[] externalRangeSplit = externalPortRange.split(":");
		String externalHostKeyPath = properties.getProperty("host_key_path");
		
		TunnelHttpServer tunnelHttpServer = new TunnelHttpServer(
				Integer.parseInt(httpPort),
				tunnelHost,
				Integer.parseInt(tunnelPort),
				Integer.parseInt(externalRangeSplit[0]), 
				Integer.parseInt(externalRangeSplit[1]),
				externalHostKeyPath);
		tunnelHttpServer.start();
	}
	
}
