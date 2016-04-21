package org.xbill.DNS;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

final class TCPClient extends Client {
    void connect(java.net.SocketAddress r6) throws java.io.IOException {
        /* JADX: method processing error */
/*
Error: java.util.NoSuchElementException
	at java.util.HashMap$HashIterator.nextEntry(HashMap.java:808)
	at java.util.HashMap$KeyIterator.next(HashMap.java:833)
	at jadx.core.dex.visitors.blocksmaker.BlockFinallyExtract.applyRemove(BlockFinallyExtract.java:535)
	at jadx.core.dex.visitors.blocksmaker.BlockFinallyExtract.extractFinally(BlockFinallyExtract.java:175)
	at jadx.core.dex.visitors.blocksmaker.BlockFinallyExtract.processExceptionHandler(BlockFinallyExtract.java:79)
	at jadx.core.dex.visitors.blocksmaker.BlockFinallyExtract.visit(BlockFinallyExtract.java:51)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:31)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:17)
	at jadx.core.ProcessClass.process(ProcessClass.java:37)
	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:286)
	at jadx.api.JavaClass.decompile(JavaClass.java:62)
	at jadx.api.JadxDecompiler$1.run(JadxDecompiler.java:173)
*/
        /*
        r5 = this;
        r4 = 0;
        r1 = r5.key;
        r0 = r1.channel();
        r0 = (java.nio.channels.SocketChannel) r0;
        r1 = r0.connect(r6);
        if (r1 == 0) goto L_0x0010;
    L_0x000f:
        return;
    L_0x0010:
        r1 = r5.key;
        r2 = 8;
        r1.interestOps(r2);
    L_0x0017:
        r1 = r0.finishConnect();	 Catch:{ all -> 0x002d }
        if (r1 != 0) goto L_0x003c;	 Catch:{ all -> 0x002d }
    L_0x001d:
        r1 = r5.key;	 Catch:{ all -> 0x002d }
        r1 = r1.isConnectable();	 Catch:{ all -> 0x002d }
        if (r1 != 0) goto L_0x0017;	 Catch:{ all -> 0x002d }
    L_0x0025:
        r1 = r5.key;	 Catch:{ all -> 0x002d }
        r2 = r5.endTime;	 Catch:{ all -> 0x002d }
        org.xbill.DNS.Client.blockUntil(r1, r2);	 Catch:{ all -> 0x002d }
        goto L_0x0017;
    L_0x002d:
        r1 = move-exception;
        r2 = r5.key;
        r2 = r2.isValid();
        if (r2 == 0) goto L_0x003b;
    L_0x0036:
        r2 = r5.key;
        r2.interestOps(r4);
    L_0x003b:
        throw r1;
    L_0x003c:
        r1 = r5.key;
        r1 = r1.isValid();
        if (r1 == 0) goto L_0x000f;
    L_0x0044:
        r1 = r5.key;
        r1.interestOps(r4);
        goto L_0x000f;
        */
        throw new UnsupportedOperationException("Method not decompiled: org.xbill.DNS.TCPClient.connect(java.net.SocketAddress):void");
    }

    public TCPClient(long endTime) throws IOException {
        super(SocketChannel.open(), endTime);
    }

    void bind(SocketAddress addr) throws IOException {
        ((SocketChannel) this.key.channel()).socket().bind(addr);
    }

    void send(byte[] data) throws IOException {
        SocketChannel channel = (SocketChannel) this.key.channel();
        Client.verboseLog("TCP write", data);
        byte[] lengthArray = new byte[]{(byte) (data.length >>> 8), (byte) (data.length & Type.ANY)};
        ByteBuffer[] buffers = new ByteBuffer[]{ByteBuffer.wrap(lengthArray), ByteBuffer.wrap(data)};
        int nsent = 0;
        this.key.interestOps(4);
        while (nsent < data.length + 2) {
            try {
                if (this.key.isWritable()) {
                    long n = channel.write(buffers);
                    if (n < 0) {
                        throw new EOFException();
                    }
                    nsent += (int) n;
                    if (nsent < data.length + 2 && System.currentTimeMillis() > this.endTime) {
                        throw new SocketTimeoutException();
                    }
                }
                Client.blockUntil(this.key, this.endTime);
            } finally {
                if (this.key.isValid()) {
                    this.key.interestOps(0);
                }
            }
        }
    }

    private byte[] _recv(int length) throws IOException {
        SocketChannel channel = (SocketChannel) this.key.channel();
        int nrecvd = 0;
        byte[] data = new byte[length];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        this.key.interestOps(1);
        while (nrecvd < length) {
            if (this.key.isReadable()) {
                long n = (long) channel.read(buffer);
                if (n < 0) {
                    throw new EOFException();
                }
                nrecvd += (int) n;
                if (nrecvd < length) {
                    try {
                        if (System.currentTimeMillis() > this.endTime) {
                            throw new SocketTimeoutException();
                        }
                    } catch (Throwable th) {
                        if (this.key.isValid()) {
                            this.key.interestOps(0);
                        }
                    }
                } else {
                    continue;
                }
            } else {
                Client.blockUntil(this.key, this.endTime);
            }
        }
        if (this.key.isValid()) {
            this.key.interestOps(0);
        }
        return data;
    }

    byte[] recv() throws IOException {
        byte[] buf = _recv(2);
        byte[] data = _recv(((buf[0] & Type.ANY) << 8) + (buf[1] & Type.ANY));
        Client.verboseLog("TCP read", data);
        return data;
    }

    static byte[] sendrecv(SocketAddress local, SocketAddress remote, byte[] data, long endTime) throws IOException {
        TCPClient client = new TCPClient(endTime);
        if (local != null) {
            try {
                client.bind(local);
            } catch (Throwable th) {
                client.cleanup();
            }
        }
        client.connect(remote);
        client.send(data);
        byte[] recv = client.recv();
        client.cleanup();
        return recv;
    }

    static byte[] sendrecv(SocketAddress addr, byte[] data, long endTime) throws IOException {
        return sendrecv(null, addr, data, endTime);
    }
}
