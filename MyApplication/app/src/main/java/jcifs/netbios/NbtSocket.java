package jcifs.netbios;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import jcifs.Config;
import jcifs.util.LogStream;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Service;

public class NbtSocket extends Socket {
    private static final int BUFFER_SIZE = 512;
    private static final int DEFAULT_SO_TIMEOUT = 5000;
    private static final int SSN_SRVC_PORT = 139;
    private static LogStream log = LogStream.getInstance();
    private NbtAddress address;
    private Name calledName;
    private int soTimeout;

    public NbtSocket(NbtAddress address, int port) throws IOException {
        this(address, port, null, 0);
    }

    public NbtSocket(NbtAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
        this(address, null, port, localAddr, localPort);
    }

    public NbtSocket(NbtAddress address, String calledName, int port, InetAddress localAddr, int localPort) throws IOException {
        InetAddress inetAddress = address.getInetAddress();
        if (port == 0) {
            port = SSN_SRVC_PORT;
        }
        super(inetAddress, port, localAddr, localPort);
        this.address = address;
        if (calledName == null) {
            this.calledName = address.hostName;
        } else {
            this.calledName = new Name(calledName, 32, null);
        }
        this.soTimeout = Config.getInt("jcifs.netbios.soTimeout", DEFAULT_SO_TIMEOUT);
        connect();
    }

    public NbtAddress getNbtAddress() {
        return this.address;
    }

    public InputStream getInputStream() throws IOException {
        return new SocketInputStream(super.getInputStream());
    }

    public OutputStream getOutputStream() throws IOException {
        return new SocketOutputStream(super.getOutputStream());
    }

    public int getPort() {
        return super.getPort();
    }

    public InetAddress getLocalAddress() {
        return super.getLocalAddress();
    }

    public int getLocalPort() {
        return super.getLocalPort();
    }

    public String toString() {
        return new StringBuffer().append("NbtSocket[addr=").append(this.address).append(",port=").append(super.getPort()).append(",localport=").append(super.getLocalPort()).append("]").toString();
    }

    private void connect() throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        try {
            InputStream in = super.getInputStream();
            super.getOutputStream().write(buffer, 0, new SessionRequestPacket(this.calledName, NbtAddress.localhost.hostName).writeWireFormat(buffer, 0));
            setSoTimeout(this.soTimeout);
            switch (SessionServicePacket.readPacketType(in, buffer, 0)) {
                case NbtException.CONNECTION_REFUSED /*-1*/:
                    throw new NbtException(2, -1);
                case Service.CISCO_FNA /*130*/:
                    LogStream logStream = log;
                    if (LogStream.level > 2) {
                        log.println(new StringBuffer().append("session established ok with ").append(this.address).toString());
                        return;
                    }
                    return;
                case Service.CISCO_TNA /*131*/:
                    int errorCode = in.read() & Type.ANY;
                    close();
                    throw new NbtException(2, errorCode);
                default:
                    close();
                    throw new NbtException(2, 0);
            }
        } catch (IOException ioe) {
            close();
            throw ioe;
        }
    }

    public void close() throws IOException {
        LogStream logStream = log;
        if (LogStream.level > 3) {
            log.println(new StringBuffer().append("close: ").append(this).toString());
        }
        super.close();
    }
}
