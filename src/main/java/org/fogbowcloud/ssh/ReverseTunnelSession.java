package org.fogbowcloud.ssh;

import org.apache.sshd.common.Service;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.session.ServerSession;

public class ReverseTunnelSession extends ServerSession {

	public ReverseTunnelSession(ServerFactoryManager server, IoSession ioSession)
			throws Exception {
		super(server, ioSession);
	}
	
	@Override
	protected void doHandleMessage(Buffer buffer) throws Exception {
		super.doHandleMessage(buffer);
		resetIdleTimeout();
	}
	
	public Service getService() {
		return currentService;
	}

}
