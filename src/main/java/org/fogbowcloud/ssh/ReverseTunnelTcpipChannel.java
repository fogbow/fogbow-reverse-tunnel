package org.fogbowcloud.ssh;

import java.io.IOException;
import java.net.InetSocketAddress;

import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.Buffer;

public class ReverseTunnelTcpipChannel extends AbstractClientChannel {

    private final IoSession serverSession;
    private final SshdSocketAddress remote;

    public ReverseTunnelTcpipChannel(IoSession serverSession, SshdSocketAddress remote) {
        super("forwarded-tcpip");
        this.serverSession = serverSession;
        this.remote = remote;
    }


    public OpenFuture getOpenFuture() {
        return openFuture;
    }

    public synchronized OpenFuture open() throws IOException {
        InetSocketAddress src = (InetSocketAddress) serverSession.getRemoteAddress();
        InetSocketAddress dst = (InetSocketAddress) serverSession.getLocalAddress();
        if (remote != null) {
        	dst = remote.toInetSocketAddress();
        }
 
        if (closeFuture.isClosed()) {
            throw new SshException("Session has been closed");
        }
        
        openFuture = new DefaultOpenFuture(lock);
        log.info("Send SSH_MSG_CHANNEL_OPEN on channel {}", this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN);
        buffer.putString(type);
        buffer.putInt(id);
        buffer.putInt(localWindow.getSize());
        buffer.putInt(localWindow.getPacketSize());
        buffer.putString(dst.getAddress().getHostAddress());
        buffer.putInt(dst.getPort());
        buffer.putString(src.getAddress().getHostAddress());
        buffer.putInt(src.getPort());
        writePacket(buffer);
        return openFuture;
    }

    @Override
    protected synchronized void doOpen() throws IOException {
        if (streaming == Streaming.Async) {
            throw new IllegalArgumentException("Asynchronous streaming isn't supported yet on this channel");
        }
        invertedIn = out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.SSH_MSG_CHANNEL_DATA);
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().sequential(serverSession, super.getInnerCloseable()).build();
    }

    protected synchronized void doWriteData(byte[] data, int off, int len) throws IOException {
        // Make sure we copy the data as the incoming buffer may be reused
        Buffer buf = new Buffer(data, off, len);
        buf = new Buffer(buf.getCompactData());
        localWindow.consumeAndCheck(len);
        serverSession.write(buf);
    }
	
}
