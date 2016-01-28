package org.fogbowcloud.ssh;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Main {

	public static void main(String[] args) throws IOException {
		Properties properties = new Properties();
		FileInputStream input = new FileInputStream(args[0]);
		properties.load(input);

		String tunnelPortRange = properties.getProperty("tunnel_port_range");  
		String[] tunnelPortRangeSplit =  tunnelPortRange.split(":");
		String tunnelHost = properties.getProperty("tunnel_host");
		String httpPort = properties.getProperty("http_port");
		String externalPortRange = properties.getProperty("external_port_range");
		String[] externalRangeSplit = externalPortRange.split(":");
		String externalHostKeyPath = properties.getProperty("host_key_path");
		String idleTokenTimeoutStr = properties.getProperty("idle_token_timeout");
		String portsPerShhServer = properties.getProperty("ports_per_ssh_server");
		Long idleTokenTimeout = null;
		if (idleTokenTimeoutStr != null) {
			idleTokenTimeout = Long.parseLong(idleTokenTimeoutStr) * 1000;
		}
		
		TunnelHttpServer tunnelHttpServer = new TunnelHttpServer(
				Integer.parseInt(httpPort),
				tunnelHost,
				Integer.parseInt(tunnelPortRangeSplit[0]), 
				Integer.parseInt(tunnelPortRangeSplit[1]),
				Integer.parseInt(externalRangeSplit[0]), 
				Integer.parseInt(externalRangeSplit[1]),
				idleTokenTimeout,
				externalHostKeyPath,
				Integer.parseInt(portsPerShhServer));
		tunnelHttpServer.start();
		
	}
	
}