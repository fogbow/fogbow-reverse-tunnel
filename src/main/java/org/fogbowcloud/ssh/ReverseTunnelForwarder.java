package org.fogbowcloud.ssh;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.ClientChannel;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.ForwardingFilter;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.TcpipForwarder;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.nio2.Nio2Acceptor;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.Readable;

public class ReverseTunnelForwarder extends CloseableUtils.AbstractInnerCloseable implements TcpipForwarder, IoHandler {

	private final ConnectionService service;
    private final Session session;
    private final Set<SshdSocketAddress> localForwards = new HashSet<SshdSocketAddress>();
    private final Map<InetSocketAddress, SshdSocketAddress> sessionToLocalForwards = new HashMap<InetSocketAddress, SshdSocketAddress>();
    protected IoAcceptor acceptor;

    public ReverseTunnelForwarder(ConnectionService service) {
		this.service = service;
        this.session = service.getSession();
    }
    
    public Set<SshdSocketAddress> getLocalForwards() {
		return localForwards;
	}

    //
    // TcpIpForwarder implementation
    //

    public synchronized SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        return local;
    }

    public synchronized void stopLocalPortForwarding(SshdSocketAddress local) throws IOException {
    }

    public synchronized SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException {
        return remote;
    }

    public synchronized void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
    }

    public synchronized SshdSocketAddress getForwardedPort(int remotePort) {
        return null;
    }

    public synchronized SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException {
    	log.debug("Starting remote port forwarding");
        if (local == null) {
            throw new IllegalArgumentException("Local address is null");
        }
        if (local.getPort() < 0) {
            throw new IllegalArgumentException("Invalid local port: " + local.getPort());
        }
        final ForwardingFilter filter = session.getFactoryManager().getTcpipForwardingFilter();
        if (filter == null || !filter.canListen(local, session)) {
            throw new IOException("Rejected address: " + local);
        }
        SshdSocketAddress bound = doBind(local);
        localForwards.add(bound);
        InetSocketAddress remoteSocketAddress = (InetSocketAddress) session.getIoSession().getRemoteAddress();
        sessionToLocalForwards.put(remoteSocketAddress, bound);
        return bound;
    }

    public synchronized void localPortForwardingCancelled(SshdSocketAddress local) throws IOException {
        if (localForwards.remove(local) && acceptor != null) {
        	Nio2Acceptor a = (Nio2Acceptor) acceptor;
        	a.doCloseImmediately();
            acceptor.unbind(local.toInetSocketAddress());
            if (acceptor.getBoundAddresses().isEmpty()) {
                acceptor.close(true);
                acceptor = null;
            }
        }
        if (local == null) {
        	return;
        }
    }

    public synchronized void close() {
        close(true);
    }

    @Override
    protected synchronized Closeable getInnerCloseable() {
        return builder().close(acceptor).build();
    }
    
    @Override
    protected void doCloseImmediately() {
    	try {
    		InetSocketAddress localSocketAddress = (InetSocketAddress) session.getIoSession().getRemoteAddress();
    		localPortForwardingCancelled(sessionToLocalForwards.get(localSocketAddress));
    		sessionToLocalForwards.remove(localSocketAddress);
		} catch (IOException e) {
			e.printStackTrace();
		}
    	super.doCloseImmediately();
    }

    //
    // IoHandler implementation
    //

    public void sessionCreated(final IoSession session) throws Exception {
    	SshdSocketAddress remoteAddress = null;
    	for (SshdSocketAddress localForward : localForwards) {
			if (localForward.getPort() == ((InetSocketAddress)session.getLocalAddress()).getPort()) {
				remoteAddress = localForward;
			}
		}
        final ReverseTunnelTcpipChannel channel = new ReverseTunnelTcpipChannel(session, remoteAddress);
        session.setAttribute(ReverseTunnelTcpipChannel.class, channel);
        this.service.registerChannel(channel);
        channel.open().addListener(new SshFutureListener<OpenFuture>() {
            public void operationComplete(OpenFuture future) {
                Throwable t = future.getException();
                if (t != null) {
                    ReverseTunnelForwarder.this.service.unregisterChannel(channel);
                    channel.close(false);
                }
            }
        });
    }

    public void sessionClosed(IoSession session) throws Exception {
    	ReverseTunnelTcpipChannel channel = (ReverseTunnelTcpipChannel) session.getAttribute(ReverseTunnelTcpipChannel.class);
        if (channel != null) {
            log.debug("IoSession {} closed, will now close the channel", session);
            channel.close(false);
        }
    }

    public void messageReceived(IoSession session, Readable message) throws Exception {
    	ReverseTunnelTcpipChannel channel = (ReverseTunnelTcpipChannel) session.getAttribute(ReverseTunnelTcpipChannel.class);
        Buffer buffer = new Buffer();
        buffer.putBuffer(message);
        channel.waitFor(ClientChannel.OPENED | ClientChannel.CLOSED, Long.MAX_VALUE);
        channel.getInvertedIn().write(buffer.array(), buffer.rpos(), buffer.available());
        channel.getInvertedIn().flush();
    }

    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        cause.printStackTrace();
        session.close(false);
    }

    //
    // Private methods
    //

    private SshdSocketAddress doBind(SshdSocketAddress address) throws IOException {
        if (acceptor == null) {
            acceptor = session.getFactoryManager().getIoServiceFactory().createAcceptor(this);
        }
        Set<SocketAddress> before = acceptor.getBoundAddresses();
        try {
            acceptor.bind(address.toInetSocketAddress());
            Set<SocketAddress> after = acceptor.getBoundAddresses();
            after.removeAll(before);
            if (after.isEmpty()) {
                throw new IOException("Error binding to " + address + ": no local addresses bound");
            }
            if (after.size() > 1) {
                throw new IOException("Multiple local addresses have been bound for " + address);
            }
            InetSocketAddress result = (InetSocketAddress) after.iterator().next();
            return new SshdSocketAddress(address.getHostName(), result.getPort());
        } catch (IOException bindErr) {
            if (acceptor.getBoundAddresses().isEmpty()) {
                close();
            }
            throw bindErr;
        }
    }

}
