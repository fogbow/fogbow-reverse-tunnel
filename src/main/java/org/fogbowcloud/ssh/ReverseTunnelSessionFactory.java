package org.fogbowcloud.ssh;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.server.session.SessionFactory;

public class ReverseTunnelSessionFactory extends SessionFactory {
    
	protected AbstractSession doCreateSession(IoSession ioSession) throws Exception {
        return new ReverseTunnelSession(server, ioSession);
    }
	
}
