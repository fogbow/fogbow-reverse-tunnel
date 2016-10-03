package org.fogbowcloud.ssh;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Main {

	private static final String TRUE = "true";

	public static void main(String[] args) throws IOException {
		
		String fileName = args[0];
		if(fileName == null || !(new File(fileName)).exists()){
			System.out.println("Erro. Properties file do not exist.");
			System.exit(1);
		}
		
		boolean cleanDataStore = false;
		
		if(args.length > 1){
			String clear = args[1];
			if(TRUE.equals(clear)){
				cleanDataStore = true;
			}
		}
		
		Properties properties = new Properties();
		FileInputStream input = new FileInputStream(fileName);
		properties.load(input);

		String tunnelPortRange = properties.getProperty("tunnel_port_range");
		String[] tunnelPortRangeSplit = tunnelPortRange.split(":");
		String tunnelHost = properties.getProperty("tunnel_host");
		String httpPort = properties.getProperty("http_port");
		String externalPortRange = properties.getProperty("external_port_range");
		String[] externalRangeSplit = externalPortRange.split(":");
		String externalHostKeyPath = properties.getProperty("host_key_path");
		String idleTokenTimeoutStr = properties.getProperty("idle_token_timeout");
		String portsPerShhServer = properties.getProperty("ports_per_ssh_server");
		String tokenPortDataStoreUrl = properties.getProperty("token_port_data_store_url");
		Long idleTokenTimeout = null;
		if (idleTokenTimeoutStr != null) {
			idleTokenTimeout = Long.parseLong(idleTokenTimeoutStr) * 1000;
		}

		String checkSSHServersIntervalStr = properties.getProperty("check_ssh_servers_interval");
		int checkSSHServersInterval = Integer.parseInt(checkSSHServersIntervalStr);

		TunnelHttpServer tunnelHttpServer;
		
		try {
			tunnelHttpServer = new TunnelHttpServer(Integer.parseInt(httpPort), tunnelHost,
					Integer.parseInt(tunnelPortRangeSplit[0]), Integer.parseInt(tunnelPortRangeSplit[1]),
					Integer.parseInt(externalRangeSplit[0]), Integer.parseInt(externalRangeSplit[1]), idleTokenTimeout,
					externalHostKeyPath, Integer.parseInt(portsPerShhServer), checkSSHServersInterval,
					tokenPortDataStoreUrl, cleanDataStore);

			tunnelHttpServer.start();

		} catch (Exception e) {
			System.out.println("Erro on initialization of HttpServer, ERROR: " + e.getMessage());
			System.exit(1);
		}

	}

}