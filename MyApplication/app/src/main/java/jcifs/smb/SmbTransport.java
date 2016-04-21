package jcifs.smb;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;
import jcifs.UniAddress;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.MsrpcDfsRootEnum;
import jcifs.netbios.Name;
import jcifs.netbios.NbtAddress;
import jcifs.netbios.NbtException;
import jcifs.netbios.SessionRequestPacket;
import jcifs.util.Encdec;
import jcifs.util.Hexdump;
import jcifs.util.LogStream;
import jcifs.util.transport.Request;
import jcifs.util.transport.Response;
import jcifs.util.transport.Transport;
import jcifs.util.transport.TransportException;
import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Service;

public class SmbTransport extends Transport implements SmbConstants {
    static final byte[] BUF = new byte[Message.MAXLENGTH];
    static final SmbComNegotiate NEGOTIATE_REQUEST = new SmbComNegotiate();
    static HashMap dfsRoots = null;
    static LogStream log = LogStream.getInstance();
    UniAddress address;
    int capabilities = SmbConstants.CAPABILITIES;
    SigningDigest digest = null;
    int flags2 = SmbConstants.FLAGS2;
    InputStream in;
    SmbComBlankResponse key = new SmbComBlankResponse();
    InetAddress localAddr;
    int localPort;
    int maxMpxCount = SmbConstants.MAX_MPX_COUNT;
    int mid;
    OutputStream out;
    int port;
    int rcv_buf_size = SmbConstants.RCV_BUF_SIZE;
    LinkedList referrals = new LinkedList();
    byte[] sbuf = new byte[Type.ANY];
    ServerData server = new ServerData(this);
    long sessionExpiration = (System.currentTimeMillis() + ((long) SmbConstants.SO_TIMEOUT));
    int sessionKey = 0;
    LinkedList sessions = new LinkedList();
    int snd_buf_size = SmbConstants.SND_BUF_SIZE;
    Socket socket;
    String tconHostName;
    boolean useUnicode = SmbConstants.USE_UNICODE;

    class ServerData {
        int capabilities;
        boolean encryptedPasswords;
        byte[] encryptionKey;
        int encryptionKeyLength;
        byte flags;
        int flags2;
        int maxBufferSize;
        int maxMpxCount;
        int maxNumberVcs;
        int maxRawSize;
        String oemDomainName;
        int security;
        int securityMode;
        long serverTime;
        int serverTimeZone;
        int sessionKey;
        boolean signaturesEnabled;
        boolean signaturesRequired;
        private final SmbTransport this$0;

        ServerData(SmbTransport this$0) {
            this.this$0 = this$0;
        }
    }

    static synchronized SmbTransport getSmbTransport(UniAddress address, int port) {
        SmbTransport smbTransport;
        synchronized (SmbTransport.class) {
            smbTransport = getSmbTransport(address, port, SmbConstants.LADDR, SmbConstants.LPORT);
        }
        return smbTransport;
    }

    static synchronized SmbTransport getSmbTransport(UniAddress address, int port, InetAddress localAddr, int localPort) {
        Object conn;
        synchronized (SmbTransport.class) {
            synchronized (SmbConstants.CONNECTIONS) {
                SmbTransport conn2;
                if (SmbConstants.SSN_LIMIT != 1) {
                    ListIterator iter = SmbConstants.CONNECTIONS.listIterator();
                    while (iter.hasNext()) {
                        conn2 = (SmbTransport) iter.next();
                        if (conn2.matches(address, port, localAddr, localPort) && (SmbConstants.SSN_LIMIT == 0 || conn2.sessions.size() < SmbConstants.SSN_LIMIT)) {
                            conn = conn2;
                            break;
                        }
                    }
                }
                conn2 = new SmbTransport(address, port, localAddr, localPort);
                SmbConstants.CONNECTIONS.add(0, conn2);
                SmbTransport conn3 = conn2;
            }
        }
        return conn;
    }

    SmbTransport(UniAddress address, int port, InetAddress localAddr, int localPort) {
        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;
    }

    synchronized SmbSession getSmbSession() {
        return getSmbSession(new NtlmPasswordAuthentication(null, null, null));
    }

    synchronized SmbSession getSmbSession(NtlmPasswordAuthentication auth) {
        Object ssn;
        SmbSession ssn2;
        ListIterator iter = this.sessions.listIterator();
        while (iter.hasNext()) {
            ssn2 = (SmbSession) iter.next();
            if (ssn2.matches(auth)) {
                ssn2.auth = auth;
                ssn = ssn2;
                break;
            }
        }
        if (SmbConstants.SO_TIMEOUT > 0) {
            long j = this.sessionExpiration;
            long now = System.currentTimeMillis();
            if (j < now) {
                this.sessionExpiration = ((long) SmbConstants.SO_TIMEOUT) + now;
                iter = this.sessions.listIterator();
                while (iter.hasNext()) {
                    ssn2 = (SmbSession) iter.next();
                    if (ssn2.expiration < now) {
                        ssn2.logoff(false);
                    }
                }
            }
        }
        ssn2 = new SmbSession(this.address, this.port, this.localAddr, this.localPort, auth);
        ssn2.transport = this;
        this.sessions.add(ssn2);
        SmbSession ssn3 = ssn2;
        return ssn;
    }

    boolean matches(UniAddress address, int port, InetAddress localAddr, int localPort) {
        return address.equals(this.address) && ((port == 0 || port == this.port || (port == SmbConstants.DEFAULT_PORT && this.port == Service.NETBIOS_SSN)) && ((localAddr == this.localAddr || (localAddr != null && localAddr.equals(this.localAddr))) && localPort == this.localPort));
    }

    boolean hasCapability(int cap) throws SmbException {
        try {
            connect((long) SmbConstants.RESPONSE_TIMEOUT);
            return (this.capabilities & cap) == cap;
        } catch (Throwable ioe) {
            throw new SmbException(ioe.getMessage(), ioe);
        }
    }

    boolean isSignatureSetupRequired(NtlmPasswordAuthentication auth) {
        return ((this.flags2 & 4) == 0 || this.digest != null || auth == NtlmPasswordAuthentication.NULL || NtlmPasswordAuthentication.NULL.equals(auth)) ? false : true;
    }

    void ssn139() throws IOException {
        Name calledName = new Name(this.address.firstCalledName(), 32, null);
        String nextCalledName;
        do {
            if (this.localAddr == null) {
                this.socket = new Socket(this.address.getHostAddress(), Service.NETBIOS_SSN);
            } else {
                this.socket = new Socket(this.address.getHostAddress(), Service.NETBIOS_SSN, this.localAddr, this.localPort);
            }
            this.socket.setSoTimeout(SmbConstants.SO_TIMEOUT);
            this.out = this.socket.getOutputStream();
            this.in = this.socket.getInputStream();
            this.out.write(this.sbuf, 0, new SessionRequestPacket(calledName, NbtAddress.getLocalName()).writeWireFormat(this.sbuf, 0));
            if (Transport.readn(this.in, this.sbuf, 0, 4) < 4) {
                try {
                    this.socket.close();
                } catch (IOException e) {
                }
                throw new SmbException("EOF during NetBIOS session request");
            }
            switch (this.sbuf[0] & Type.ANY) {
                case NbtException.CONNECTION_REFUSED /*-1*/:
                    disconnect(true);
                    throw new NbtException(2, -1);
                case Service.CISCO_FNA /*130*/:
                    LogStream logStream = log;
                    if (LogStream.level >= 4) {
                        log.println(new StringBuffer().append("session established ok with ").append(this.address).toString());
                        return;
                    }
                    return;
                case Service.CISCO_TNA /*131*/:
                    int errorCode = this.in.read() & Type.ANY;
                    switch (errorCode) {
                        case Flags.FLAG8 /*128*/:
                        case Service.CISCO_FNA /*130*/:
                            this.socket.close();
                            nextCalledName = this.address.nextCalledName();
                            calledName.name = nextCalledName;
                            break;
                        default:
                            disconnect(true);
                            throw new NbtException(2, errorCode);
                    }
                default:
                    disconnect(true);
                    throw new NbtException(2, 0);
            }
        } while (nextCalledName != null);
        throw new IOException(new StringBuffer().append("Failed to establish session with ").append(this.address).toString());
    }

    private void negotiate(int port, ServerMessageBlock resp) throws IOException {
        synchronized (this.sbuf) {
            if (port == Service.NETBIOS_SSN) {
                ssn139();
            } else {
                if (port == 0) {
                    port = SmbConstants.DEFAULT_PORT;
                }
                if (this.localAddr == null) {
                    this.socket = new Socket(this.address.getHostAddress(), port);
                } else {
                    this.socket = new Socket(this.address.getHostAddress(), port, this.localAddr, this.localPort);
                }
                this.socket.setSoTimeout(SmbConstants.SO_TIMEOUT);
                this.out = this.socket.getOutputStream();
                this.in = this.socket.getInputStream();
            }
            int i = this.mid + 1;
            this.mid = i;
            if (i == 32000) {
                this.mid = 1;
            }
            NEGOTIATE_REQUEST.mid = this.mid;
            int n = NEGOTIATE_REQUEST.encode(this.sbuf, 4);
            Encdec.enc_uint32be(n & Message.MAXLENGTH, this.sbuf, 0);
            LogStream logStream = log;
            if (LogStream.level >= 4) {
                log.println(NEGOTIATE_REQUEST);
                logStream = log;
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, this.sbuf, 4, n);
                }
            }
            this.out.write(this.sbuf, 0, n + 4);
            this.out.flush();
            if (peekKey() == null) {
                throw new IOException("transport closed in negotiate");
            }
            int size = Encdec.dec_uint16be(this.sbuf, 2) & Message.MAXLENGTH;
            if (size < 33 || size + 4 > this.sbuf.length) {
                throw new IOException(new StringBuffer().append("Invalid payload size: ").append(size).toString());
            }
            Transport.readn(this.in, this.sbuf, 36, size - 32);
            resp.decode(this.sbuf, 4);
            logStream = log;
            if (LogStream.level >= 4) {
                log.println(resp);
                logStream = log;
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, this.sbuf, 4, n);
                }
            }
        }
    }

    public void connect() throws SmbException {
        try {
            super.connect((long) SmbConstants.RESPONSE_TIMEOUT);
        } catch (Throwable te) {
            throw new SmbException(te.getMessage(), te);
        }
    }

    protected void doConnect() throws IOException {
        int i = SmbConstants.DEFAULT_PORT;
        SmbComNegotiateResponse resp = new SmbComNegotiateResponse(this.server);
        try {
            negotiate(this.port, resp);
        } catch (ConnectException e) {
            if (this.port == 0 || this.port == SmbConstants.DEFAULT_PORT) {
                i = Service.NETBIOS_SSN;
            }
            this.port = i;
            negotiate(this.port, resp);
        } catch (NoRouteToHostException e2) {
            if (this.port == 0 || this.port == SmbConstants.DEFAULT_PORT) {
                i = Service.NETBIOS_SSN;
            }
            this.port = i;
            negotiate(this.port, resp);
        }
        if (resp.dialectIndex > 10) {
            throw new SmbException("This client does not support the negotiated dialect.");
        } else if (this.server.encryptionKeyLength == 8 || SmbConstants.LM_COMPATIBILITY != 0) {
            this.tconHostName = this.address.getHostName();
            if (this.server.signaturesRequired || (this.server.signaturesEnabled && SmbConstants.SIGNPREF)) {
                this.flags2 |= 4;
            } else {
                this.flags2 &= 65531;
            }
            this.maxMpxCount = Math.min(this.maxMpxCount, this.server.maxMpxCount);
            if (this.maxMpxCount < 1) {
                this.maxMpxCount = 1;
            }
            this.snd_buf_size = Math.min(this.snd_buf_size, this.server.maxBufferSize);
            this.capabilities &= this.server.capabilities;
            if ((this.capabilities & 4) != 0) {
                return;
            }
            if (SmbConstants.FORCE_UNICODE) {
                this.capabilities |= 4;
                return;
            }
            this.useUnicode = false;
            this.flags2 &= 32767;
        } else {
            throw new SmbException("Encryption key length is not 8 as expected. This could indicate that the server requires NTLMv2. JCIFS does not fully support NTLMv2 but you can try setting jcifs.smb.lmCompatibility = 3.");
        }
    }

    protected void doDisconnect(boolean hard) throws IOException {
        ListIterator iter = this.sessions.listIterator();
        while (iter.hasNext()) {
            ((SmbSession) iter.next()).logoff(hard);
        }
        this.socket.shutdownOutput();
        this.out.close();
        this.in.close();
        this.socket.close();
        this.digest = null;
    }

    protected void makeKey(Request request) throws IOException {
        int i = this.mid + 1;
        this.mid = i;
        if (i == 32000) {
            this.mid = 1;
        }
        ((ServerMessageBlock) request).mid = this.mid;
    }

    protected Request peekKey() throws IOException {
        while (Transport.readn(this.in, this.sbuf, 0, 4) >= 4) {
            if (this.sbuf[0] != (byte) -123) {
                if (Transport.readn(this.in, this.sbuf, 4, 32) < 32) {
                    return null;
                }
                LogStream logStream = log;
                if (LogStream.level >= 4) {
                    log.println(new StringBuffer().append("New data read: ").append(this).toString());
                    Hexdump.hexdump(log, this.sbuf, 4, 32);
                }
                while (true) {
                    if (this.sbuf[0] == (byte) 0 && this.sbuf[1] == (byte) 0 && this.sbuf[4] == (byte) -1 && this.sbuf[5] == (byte) 83 && this.sbuf[6] == (byte) 77 && this.sbuf[7] == (byte) 66) {
                        this.key.mid = Encdec.dec_uint16le(this.sbuf, 34) & Message.MAXLENGTH;
                        return this.key;
                    }
                    for (int i = 0; i < 35; i++) {
                        this.sbuf[i] = this.sbuf[i + 1];
                    }
                    int b = this.in.read();
                    if (b == -1) {
                        return null;
                    }
                    this.sbuf[35] = (byte) b;
                }
            }
        }
        return null;
    }

    protected void doSend(Request request) throws IOException {
        synchronized (BUF) {
            ServerMessageBlock smb = (ServerMessageBlock) request;
            int n = smb.encode(BUF, 4);
            Encdec.enc_uint32be(Message.MAXLENGTH & n, BUF, 0);
            LogStream logStream = log;
            if (LogStream.level >= 4) {
                do {
                    log.println(smb);
                    if (!(smb instanceof AndXServerMessageBlock)) {
                        break;
                    }
                    smb = ((AndXServerMessageBlock) smb).andx;
                } while (smb != null);
                logStream = log;
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, BUF, 4, n);
                }
            }
            this.out.write(BUF, 0, n + 4);
        }
    }

    protected void doSend0(Request request) throws IOException {
        try {
            doSend(request);
        } catch (IOException ioe) {
            LogStream logStream = log;
            if (LogStream.level > 2) {
                ioe.printStackTrace(log);
            }
            try {
                disconnect(true);
            } catch (IOException ioe2) {
                ioe2.printStackTrace(log);
            }
            throw ioe;
        }
    }

    protected void doRecv(Response response) throws IOException {
        ServerMessageBlock resp = (ServerMessageBlock) response;
        resp.useUnicode = this.useUnicode;
        synchronized (BUF) {
            System.arraycopy(this.sbuf, 0, BUF, 0, 36);
            int size = Encdec.dec_uint16be(BUF, 2) & Message.MAXLENGTH;
            if (size < 33 || size + 4 > this.rcv_buf_size) {
                throw new IOException(new StringBuffer().append("Invalid payload size: ").append(size).toString());
            }
            int errorCode = Encdec.dec_uint32le(BUF, 9) & -1;
            if (resp.command == (byte) 46 && (errorCode == 0 || errorCode == -2147483643)) {
                SmbComReadAndXResponse r = (SmbComReadAndXResponse) resp;
                Transport.readn(this.in, BUF, 36, 27);
                int off = 32 + 27;
                resp.decode(BUF, 4);
                if (r.dataLength > 0) {
                    Transport.readn(this.in, BUF, 63, r.dataOffset - 59);
                    Transport.readn(this.in, r.b, r.off, r.dataLength);
                }
            } else {
                Transport.readn(this.in, BUF, 36, size - 32);
                resp.decode(BUF, 4);
                if (resp instanceof SmbComTransactionResponse) {
                    ((SmbComTransactionResponse) resp).nextElement();
                }
            }
            if (this.digest != null && resp.errorCode == 0) {
                this.digest.verify(BUF, 4, resp);
            }
            LogStream logStream = log;
            if (LogStream.level >= 4) {
                log.println(response);
                logStream = log;
                if (LogStream.level >= 6) {
                    Hexdump.hexdump(log, BUF, 4, size);
                }
            }
        }
    }

    protected void doSkip() throws IOException {
        int size = Encdec.dec_uint16be(this.sbuf, 2) & Message.MAXLENGTH;
        if (size < 33 || size + 4 > this.rcv_buf_size) {
            this.in.skip((long) this.in.available());
        } else {
            this.in.skip((long) (size - 32));
        }
    }

    void checkStatus(ServerMessageBlock req, ServerMessageBlock resp) throws SmbException {
        resp.errorCode = SmbException.getStatusByCode(resp.errorCode);
        switch (resp.errorCode) {
            case -2147483643:
            case Tokenizer.EOF /*0*/:
                if (resp.verifyFailed) {
                    throw new SmbException("Signature verification failed.");
                }
                return;
            case NtStatus.NT_STATUS_ACCESS_DENIED /*-1073741790*/:
            case NtStatus.NT_STATUS_WRONG_PASSWORD /*-1073741718*/:
            case NtStatus.NT_STATUS_LOGON_FAILURE /*-1073741715*/:
            case NtStatus.NT_STATUS_ACCOUNT_RESTRICTION /*-1073741714*/:
            case NtStatus.NT_STATUS_INVALID_LOGON_HOURS /*-1073741713*/:
            case NtStatus.NT_STATUS_INVALID_WORKSTATION /*-1073741712*/:
            case NtStatus.NT_STATUS_PASSWORD_EXPIRED /*-1073741711*/:
            case NtStatus.NT_STATUS_ACCOUNT_DISABLED /*-1073741710*/:
            case NtStatus.NT_STATUS_TRUSTED_DOMAIN_FAILURE /*-1073741428*/:
            case NtStatus.NT_STATUS_ACCOUNT_LOCKED_OUT /*-1073741260*/:
                throw new SmbAuthException(resp.errorCode);
            case NtStatus.NT_STATUS_PATH_NOT_COVERED /*-1073741225*/:
                if (req.auth == null) {
                    throw new SmbException(resp.errorCode, null);
                }
                DfsReferral[] drs = getDfsReferrals(req.auth, req.path, 1);
                SmbFile.dfs.insert(req.path, drs[0]);
                throw drs[0];
            default:
                throw new SmbException(resp.errorCode, null);
        }
    }

    void send(ServerMessageBlock request, ServerMessageBlock response) throws SmbException {
        connect();
        request.flags2 |= this.flags2;
        request.useUnicode = this.useUnicode;
        request.response = response;
        if (request.digest == null) {
            request.digest = this.digest;
        }
        if (response == null) {
            try {
                doSend0(request);
                return;
            } catch (SmbException se) {
                throw se;
            } catch (Throwable ie) {
                throw new SmbException(ie.getMessage(), ie);
            } catch (Throwable ioe) {
                throw new SmbException(ioe.getMessage(), ioe);
            }
        }
        if (request instanceof SmbComTransaction) {
            response.command = request.command;
            SmbComTransaction req = (SmbComTransaction) request;
            SmbComTransactionResponse resp = (SmbComTransactionResponse) response;
            req.maxBufferSize = this.snd_buf_size;
            resp.reset();
            try {
                BufferCache.getBuffers(req, resp);
                req.nextElement();
                if (req.hasMoreElements()) {
                    SmbComBlankResponse interim = new SmbComBlankResponse();
                    super.sendrecv(req, interim, (long) SmbConstants.RESPONSE_TIMEOUT);
                    if (interim.errorCode != 0) {
                        checkStatus(req, interim);
                    }
                    req.nextElement();
                } else {
                    makeKey(req);
                }
                synchronized (this.response_map) {
                    response.received = false;
                    resp.isReceived = false;
                    try {
                        this.response_map.put(req, resp);
                        do {
                            doSend0(req);
                            if (!req.hasMoreElements()) {
                                break;
                            }
                        } while (req.nextElement() != null);
                        long timeout = (long) SmbConstants.RESPONSE_TIMEOUT;
                        resp.expiration = System.currentTimeMillis() + timeout;
                        while (resp.hasMoreElements()) {
                            this.response_map.wait(timeout);
                            timeout = resp.expiration - System.currentTimeMillis();
                            if (timeout <= 0) {
                                throw new TransportException(new StringBuffer().append(this).append(" timedout waiting for response to ").append(req).toString());
                            }
                        }
                        if (response.errorCode != 0) {
                            checkStatus(req, resp);
                        }
                        this.response_map.remove(req);
                    } catch (Throwable ie2) {
                        throw new TransportException(ie2);
                    } catch (Throwable th) {
                        this.response_map.remove(req);
                    }
                }
                BufferCache.releaseBuffer(req.txn_buf);
                BufferCache.releaseBuffer(resp.txn_buf);
            } catch (Throwable th2) {
                BufferCache.releaseBuffer(req.txn_buf);
                BufferCache.releaseBuffer(resp.txn_buf);
            }
        } else {
            response.command = request.command;
            super.sendrecv(request, response, (long) SmbConstants.RESPONSE_TIMEOUT);
        }
        checkStatus(request, response);
    }

    public String toString() {
        return new StringBuffer().append(super.toString()).append("[").append(this.address).append(":").append(this.port).append("]").toString();
    }

    void dfsPathSplit(String path, String[] result) {
        int ri;
        int i;
        int rlast = result.length - 1;
        int b = 0;
        int len = path.length();
        int i2 = 0;
        int ri2 = 0;
        while (ri2 != rlast) {
            if (i2 == len || path.charAt(i2) == '\\') {
                ri = ri2 + 1;
                result[ri2] = path.substring(b, i2);
                b = i2 + 1;
            } else {
                ri = ri2;
            }
            i = i2 + 1;
            if (i2 >= len) {
                while (ri < result.length) {
                    ri2 = ri + 1;
                    result[ri] = BuildConfig.VERSION_NAME;
                    ri = ri2;
                }
                return;
            }
            i2 = i;
            ri2 = ri;
        }
        result[rlast] = path.substring(b);
        i = i2;
        ri = ri2;
    }

    DfsReferral[] getDfsReferrals(NtlmPasswordAuthentication auth, String path, int rn) throws SmbException {
        SmbTree ipc = getSmbSession(auth).getSmbTree("IPC$", null);
        Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse();
        ipc.send(new Trans2GetDfsReferral(path), resp);
        if (rn == 0 || resp.numReferrals < rn) {
            rn = resp.numReferrals;
        }
        DfsReferral[] drs = new DfsReferral[rn];
        String[] arr = new String[4];
        long expiration = System.currentTimeMillis() + (Dfs.TTL * 1000);
        for (int di = 0; di < drs.length; di++) {
            DfsReferral dr = new DfsReferral();
            dr.resolveHashes = auth.hashesExternal;
            dr.ttl = (long) resp.referrals[di].ttl;
            dr.expiration = expiration;
            if (path.equals(BuildConfig.VERSION_NAME)) {
                dr.server = resp.referrals[di].path.substring(1).toLowerCase();
            } else {
                dfsPathSplit(resp.referrals[di].node, arr);
                dr.server = arr[1];
                dr.share = arr[2];
                dr.path = arr[3];
            }
            dr.pathConsumed = resp.pathConsumed;
            drs[di] = dr;
        }
        return drs;
    }

    FileEntry[] getDfsRoots(String domainName, NtlmPasswordAuthentication auth) throws IOException {
        DcerpcHandle handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(UniAddress.getByName(getSmbTransport(UniAddress.getByName(domainName), 0).getDfsReferrals(auth, new StringBuffer().append("\\").append(domainName).toString(), 1)[0].server).getHostAddress()).append("[\\PIPE\\netdfs]").toString(), auth);
        try {
            MsrpcDfsRootEnum rpc = new MsrpcDfsRootEnum(domainName);
            handle.sendrecv(rpc);
            if (rpc.retval != 0) {
                throw new SmbException(rpc.retval, true);
            }
            FileEntry[] entries = rpc.getEntries();
            return entries;
        } finally {
            try {
                handle.close();
            } catch (IOException ioe) {
                LogStream logStream = log;
                if (LogStream.level >= 4) {
                    ioe.printStackTrace(log);
                }
            }
        }
    }
}
