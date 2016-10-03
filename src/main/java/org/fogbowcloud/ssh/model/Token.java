package org.fogbowcloud.ssh.model;

public class Token {
	
	private String tokenId;
	private Integer port;
	private Integer sshServerPort;
	private Long lastIdleCheck = 0L;
	
	public Token(String tokenId, Integer port, Integer sshServerPort) {
		this.tokenId = tokenId;
		this.sshServerPort = sshServerPort;
		this.port = port;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public Integer getPort() {
		return port;
	}

	public void setPort(Integer port) {
		this.port = port;
	}

	public Long getLastIdleCheck() {
		return lastIdleCheck;
	}

	public void setLastIdleCheck(Long lastIdleCheck) {
		this.lastIdleCheck = lastIdleCheck;
	}

	public Integer getSshServerPort() {
		return sshServerPort;
	}

	public void setSshServerPort(Integer sshServerPort) {
		this.sshServerPort = sshServerPort;
	}
	
}
