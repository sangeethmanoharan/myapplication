package jcifs.smb;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import jcifs.Config;
import jcifs.UniAddress;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.msrpc.MsrpcDfsRootEnum;
import jcifs.dcerpc.msrpc.MsrpcShareEnum;
import jcifs.dcerpc.msrpc.MsrpcShareGetInfo;
import jcifs.netbios.NbtAddress;
import jcifs.util.LogStream;
import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.KEYRecord.Flags;

public class SmbFile extends URLConnection implements SmbConstants {
    public static final int ATTR_ARCHIVE = 32;
    static final int ATTR_COMPRESSED = 2048;
    public static final int ATTR_DIRECTORY = 16;
    static final int ATTR_GET_MASK = 32767;
    public static final int ATTR_HIDDEN = 2;
    static final int ATTR_NORMAL = 128;
    public static final int ATTR_READONLY = 1;
    static final int ATTR_SET_MASK = 12455;
    public static final int ATTR_SYSTEM = 4;
    static final int ATTR_TEMPORARY = 256;
    public static final int ATTR_VOLUME = 8;
    static final int DEFAULT_ATTR_EXPIRATION_PERIOD = 5000;
    public static final int FILE_NO_SHARE = 0;
    public static final int FILE_SHARE_DELETE = 4;
    public static final int FILE_SHARE_READ = 1;
    public static final int FILE_SHARE_WRITE = 2;
    static final int HASH_DOT = ".".hashCode();
    static final int HASH_DOT_DOT = "..".hashCode();
    static final int O_APPEND = 4;
    static final int O_CREAT = 16;
    static final int O_EXCL = 32;
    static final int O_RDONLY = 1;
    static final int O_RDWR = 3;
    static final int O_TRUNC = 64;
    static final int O_WRONLY = 2;
    public static final int TYPE_COMM = 64;
    public static final int TYPE_FILESYSTEM = 1;
    public static final int TYPE_NAMED_PIPE = 16;
    public static final int TYPE_PRINTER = 32;
    public static final int TYPE_SERVER = 4;
    public static final int TYPE_SHARE = 8;
    public static final int TYPE_WORKGROUP = 2;
    static long attrExpirationPeriod = Config.getLong("jcifs.smb.client.attrExpirationPeriod", 5000);
    protected static Dfs dfs = new Dfs();
    static LogStream log = LogStream.getInstance();
    int addressIndex;
    UniAddress[] addresses;
    private long attrExpiration;
    private int attributes;
    NtlmPasswordAuthentication auth;
    private SmbComBlankResponse blank_resp;
    private String canon;
    private long createTime;
    private DfsReferral dfsReferral;
    int fid;
    private boolean isExists;
    private long lastModified;
    boolean opened;
    private String share;
    private int shareAccess;
    private long size;
    private long sizeExpiration;
    SmbTree tree;
    int tree_num;
    int type;
    String unc;

    class WriterThread extends Thread {
        byte[] b;
        SmbFile dest;
        SmbException e = null;
        int n;
        int off;
        boolean ready;
        SmbComWrite req;
        SmbComWriteAndX reqx;
        ServerMessageBlock resp;
        private final SmbFile this$0;
        boolean useNTSmbs;

        WriterThread(SmbFile this$0) throws SmbException {
            super("JCIFS-WriterThread");
            this.this$0 = this$0;
            this.useNTSmbs = this$0.tree.session.transport.hasCapability(SmbFile.TYPE_NAMED_PIPE);
            if (this.useNTSmbs) {
                this.reqx = new SmbComWriteAndX();
                this.resp = new SmbComWriteAndXResponse();
            } else {
                this.req = new SmbComWrite();
                this.resp = new SmbComWriteResponse();
            }
            this.ready = false;
        }

        synchronized void write(byte[] b, int n, SmbFile dest, int off) {
            this.b = b;
            this.n = n;
            this.dest = dest;
            this.off = off;
            this.ready = false;
            notify();
        }

        public void run() {
            synchronized (this) {
                while (true) {
                    try {
                        notify();
                        this.ready = true;
                        while (this.ready) {
                            wait();
                        }
                        if (this.n == -1) {
                            return;
                        } else if (this.useNTSmbs) {
                            this.reqx.setParam(this.dest.fid, (long) this.off, this.n, this.b, SmbFile.HASH_DOT_DOT, this.n);
                            this.dest.send(this.reqx, this.resp);
                        } else {
                            this.req.setParam(this.dest.fid, (long) this.off, this.n, this.b, SmbFile.HASH_DOT_DOT, this.n);
                            this.dest.send(this.req, this.resp);
                        }
                    } catch (SmbException e) {
                        this.e = e;
                        notify();
                        return;
                    } catch (Throwable x) {
                        this.e = new SmbException("WriterThread", x);
                        notify();
                        return;
                    }
                }
            }
        }
    }

    static {
        try {
            Class.forName("jcifs.Config");
        } catch (ClassNotFoundException cnfe) {
            cnfe.printStackTrace();
        }
    }

    public SmbFile(String url) throws MalformedURLException {
        this(new URL(null, url, Handler.SMB_HANDLER));
    }

    public SmbFile(SmbFile context, String name) throws MalformedURLException, UnknownHostException {
        this(context.isWorkgroup0() ? new URL(null, new StringBuffer().append("smb://").append(name).toString(), Handler.SMB_HANDLER) : new URL(context.url, name, Handler.SMB_HANDLER), context.auth);
    }

    public SmbFile(String context, String name) throws MalformedURLException {
        this(new URL(new URL(null, context, Handler.SMB_HANDLER), name, Handler.SMB_HANDLER));
    }

    public SmbFile(String url, NtlmPasswordAuthentication auth) throws MalformedURLException {
        this(new URL(null, url, Handler.SMB_HANDLER), auth);
    }

    public SmbFile(String url, NtlmPasswordAuthentication auth, int shareAccess) throws MalformedURLException {
        this(new URL(null, url, Handler.SMB_HANDLER), auth);
        if ((shareAccess & -8) != 0) {
            throw new RuntimeException("Illegal shareAccess parameter");
        }
        this.shareAccess = shareAccess;
    }

    public SmbFile(String context, String name, NtlmPasswordAuthentication auth) throws MalformedURLException {
        this(new URL(new URL(null, context, Handler.SMB_HANDLER), name, Handler.SMB_HANDLER), auth);
    }

    public SmbFile(String context, String name, NtlmPasswordAuthentication auth, int shareAccess) throws MalformedURLException {
        this(new URL(new URL(null, context, Handler.SMB_HANDLER), name, Handler.SMB_HANDLER), auth);
        if ((shareAccess & -8) != 0) {
            throw new RuntimeException("Illegal shareAccess parameter");
        }
        this.shareAccess = shareAccess;
    }

    public SmbFile(SmbFile context, String name, int shareAccess) throws MalformedURLException, UnknownHostException {
        this(context.isWorkgroup0() ? new URL(null, new StringBuffer().append("smb://").append(name).toString(), Handler.SMB_HANDLER) : new URL(context.url, name, Handler.SMB_HANDLER), context.auth);
        if ((shareAccess & -8) != 0) {
            throw new RuntimeException("Illegal shareAccess parameter");
        }
        this.shareAccess = shareAccess;
    }

    public SmbFile(URL url) {
        this(url, new NtlmPasswordAuthentication(url.getUserInfo()));
    }

    public SmbFile(URL url, NtlmPasswordAuthentication auth) {
        super(url);
        this.shareAccess = 7;
        this.blank_resp = null;
        this.dfsReferral = null;
        this.tree = null;
        if (auth == null) {
            auth = new NtlmPasswordAuthentication(url.getUserInfo());
        }
        this.auth = auth;
        getUncPath0();
    }

    SmbFile(SmbFile context, String name, int type, int attributes, long createTime, long lastModified, long size) throws MalformedURLException, UnknownHostException {
        URL url;
        if (context.isWorkgroup0()) {
            url = new URL(null, new StringBuffer().append("smb://").append(name).append("/").toString(), Handler.SMB_HANDLER);
        } else {
            url = new URL(context.url, new StringBuffer().append(name).append((attributes & TYPE_NAMED_PIPE) > 0 ? "/" : BuildConfig.VERSION_NAME).toString());
        }
        this(url);
        this.auth = context.auth;
        if (context.share != null) {
            this.tree = context.tree;
            this.dfsReferral = context.dfsReferral;
        }
        int last = name.length() - 1;
        if (name.charAt(last) == '/') {
            name = name.substring(HASH_DOT_DOT, last);
        }
        if (context.share == null) {
            this.unc = "\\";
        } else if (context.unc.equals("\\")) {
            this.unc = new StringBuffer().append('\\').append(name).toString();
        } else {
            this.unc = new StringBuffer().append(context.unc).append('\\').append(name).toString();
        }
        this.type = type;
        this.attributes = attributes;
        this.createTime = createTime;
        this.lastModified = lastModified;
        this.size = size;
        this.isExists = true;
        long currentTimeMillis = System.currentTimeMillis() + attrExpirationPeriod;
        this.sizeExpiration = currentTimeMillis;
        this.attrExpiration = currentTimeMillis;
    }

    private SmbComBlankResponse blank_resp() {
        if (this.blank_resp == null) {
            this.blank_resp = new SmbComBlankResponse();
        }
        return this.blank_resp;
    }

    void resolveDfs(ServerMessageBlock request) throws SmbException {
        connect0();
        DfsReferral dr = dfs.resolve(getServerWithDfs(), this.tree.share, this.unc, this.auth);
        if (dr != null) {
            try {
                this.tree = SmbTransport.getSmbTransport(UniAddress.getByName(dr.server), this.url.getPort()).getSmbSession(this.auth).getSmbTree(dr.share, null);
                LogStream logStream = log;
                if (LogStream.level >= O_RDWR) {
                    log.println(dr);
                }
                this.dfsReferral = dr;
                String dunc = this.unc.substring(dr.pathConsumed);
                if (dunc.equals(BuildConfig.VERSION_NAME)) {
                    dunc = "\\";
                }
                if (!dr.path.equals(BuildConfig.VERSION_NAME)) {
                    dunc = new StringBuffer().append("\\").append(dr.path).append(dunc).toString();
                }
                this.unc = dunc;
                if (!(request == null || request.path == null || !request.path.endsWith("\\") || dunc.endsWith("\\"))) {
                    dunc = new StringBuffer().append(dunc).append("\\").toString();
                }
                if (request != null) {
                    request.path = dunc;
                    request.flags2 |= Flags.EXTEND;
                }
            } catch (Throwable uhe) {
                throw new SmbException(dr.server, uhe);
            }
        } else if (this.tree.inDomainDfs && !(request instanceof NtTransQuerySecurityDesc) && !(request instanceof SmbComClose) && !(request instanceof SmbComFindClose2)) {
            throw new SmbException((int) NtStatus.NT_STATUS_NOT_FOUND, false);
        } else if (request != null) {
            request.flags2 &= -4097;
        }
    }

    void send(ServerMessageBlock request, ServerMessageBlock response) throws SmbException {
        while (true) {
            resolveDfs(request);
            try {
                this.tree.send(request, response);
                break;
            } catch (DfsReferral dre) {
                if (dre.resolveHashes) {
                    throw dre;
                }
                request.reset();
            }
        }
    }

    static String queryLookup(String query, String param) {
        char[] in = query.toCharArray();
        int eq = HASH_DOT_DOT;
        int st = HASH_DOT_DOT;
        for (int i = HASH_DOT_DOT; i < in.length; i += TYPE_FILESYSTEM) {
            int ch = in[i];
            if (ch == 38) {
                if (eq <= st || !new String(in, st, eq - st).equalsIgnoreCase(param)) {
                    st = i + TYPE_FILESYSTEM;
                } else {
                    eq += TYPE_FILESYSTEM;
                    return new String(in, eq, i - eq);
                }
            } else if (ch == 61) {
                eq = i;
            }
        }
        if (eq <= st || !new String(in, st, eq - st).equalsIgnoreCase(param)) {
            return null;
        }
        eq += TYPE_FILESYSTEM;
        return new String(in, eq, in.length - eq);
    }

    UniAddress getAddress() throws UnknownHostException {
        if (this.addressIndex == 0) {
            return getFirstAddress();
        }
        return this.addresses[this.addressIndex - 1];
    }

    UniAddress getFirstAddress() throws UnknownHostException {
        this.addressIndex = HASH_DOT_DOT;
        String host = this.url.getHost();
        String path = this.url.getPath();
        String query = this.url.getQuery();
        if (query != null) {
            String server = queryLookup(query, "server");
            if (server != null && server.length() > 0) {
                this.addresses = new UniAddress[TYPE_FILESYSTEM];
                this.addresses[HASH_DOT_DOT] = UniAddress.getByName(server);
                return getNextAddress();
            }
        }
        if (host.length() == 0) {
            try {
                NbtAddress addr = NbtAddress.getByName(NbtAddress.MASTER_BROWSER_NAME, TYPE_FILESYSTEM, null);
                this.addresses = new UniAddress[TYPE_FILESYSTEM];
                this.addresses[HASH_DOT_DOT] = UniAddress.getByName(addr.getHostAddress());
            } catch (UnknownHostException uhe) {
                NtlmPasswordAuthentication.initDefaults();
                if (NtlmPasswordAuthentication.DEFAULT_DOMAIN.equals("?")) {
                    throw uhe;
                }
                this.addresses = UniAddress.getAllByName(NtlmPasswordAuthentication.DEFAULT_DOMAIN, true);
            }
        } else if (path.length() == 0 || path.equals("/")) {
            this.addresses = UniAddress.getAllByName(host, true);
        } else {
            this.addresses = UniAddress.getAllByName(host, false);
        }
        return getNextAddress();
    }

    UniAddress getNextAddress() {
        if (this.addressIndex >= this.addresses.length) {
            return null;
        }
        UniAddress[] uniAddressArr = this.addresses;
        int i = this.addressIndex;
        this.addressIndex = i + TYPE_FILESYSTEM;
        return uniAddressArr[i];
    }

    boolean hasNextAddress() {
        return this.addressIndex < this.addresses.length;
    }

    void connect0() throws SmbException {
        try {
            connect();
        } catch (Throwable uhe) {
            throw new SmbException("Failed to connect to server", uhe);
        } catch (SmbException se) {
            throw se;
        } catch (Throwable ioe) {
            throw new SmbException("Failed to connect to server", ioe);
        }
    }

    void doConnect() throws IOException {
        SmbTransport trans;
        boolean z;
        boolean z2 = false;
        UniAddress addr = getAddress();
        if (this.tree != null) {
            trans = this.tree.session.transport;
        } else {
            trans = SmbTransport.getSmbTransport(addr, this.url.getPort());
            this.tree = trans.getSmbSession(this.auth).getSmbTree(this.share, null);
        }
        String hostName = getServerWithDfs();
        SmbTree smbTree = this.tree;
        if (dfs.resolve(hostName, this.tree.share, null, this.auth) != null) {
            z = true;
        } else {
            z = false;
        }
        smbTree.inDomainDfs = z;
        if (this.tree.inDomainDfs) {
            this.tree.treeConnected = true;
        }
        LogStream logStream;
        try {
            logStream = log;
            if (LogStream.level >= O_RDWR) {
                log.println(new StringBuffer().append("doConnect: ").append(addr).toString());
            }
            this.tree.treeConnect(null, null);
        } catch (SmbAuthException sae) {
            if (this.share == null) {
                this.tree = trans.getSmbSession(NtlmPasswordAuthentication.NULL).getSmbTree(null, null);
                this.tree.treeConnect(null, null);
                return;
            }
            NtlmPasswordAuthentication a = NtlmAuthenticator.requestNtlmPasswordAuthentication(this.url.toString(), sae);
            if (a != null) {
                this.auth = a;
                this.tree = trans.getSmbSession(this.auth).getSmbTree(this.share, null);
                SmbTree smbTree2 = this.tree;
                if (dfs.resolve(hostName, this.tree.share, null, this.auth) != null) {
                    z2 = true;
                }
                smbTree2.inDomainDfs = z2;
                if (this.tree.inDomainDfs) {
                    this.tree.treeConnected = true;
                }
                this.tree.treeConnect(null, null);
                return;
            }
            logStream = log;
            if (LogStream.level >= TYPE_FILESYSTEM && hasNextAddress()) {
                sae.printStackTrace(log);
            }
            throw sae;
        }
    }

    public void connect() throws IOException {
        if (!isConnected()) {
            getUncPath0();
            getFirstAddress();
            while (true) {
                try {
                    doConnect();
                    break;
                } catch (SmbException se) {
                    if (getNextAddress() == null) {
                        throw se;
                    }
                    LogStream logStream = log;
                    if (LogStream.level >= O_RDWR) {
                        se.printStackTrace(log);
                    }
                }
            }
        }
    }

    boolean isConnected() {
        return this.tree != null && this.tree.treeConnected;
    }

    int open0(int flags, int access, int attrs, int options) throws SmbException {
        connect0();
        LogStream logStream = log;
        if (LogStream.level >= O_RDWR) {
            log.println(new StringBuffer().append("open0: ").append(this.unc).toString());
        }
        if (this.tree.session.transport.hasCapability(TYPE_NAMED_PIPE)) {
            SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse();
            SmbComNTCreateAndX request = new SmbComNTCreateAndX(this.unc, flags, access, this.shareAccess, attrs, options, null);
            if (this instanceof SmbNamedPipe) {
                request.flags0 |= 22;
                request.desiredAccess |= SmbConstants.READ_CONTROL;
                response.isExtended = true;
            }
            send(request, response);
            int f = response.fid;
            this.attributes = response.extFileAttributes & ATTR_GET_MASK;
            this.attrExpiration = System.currentTimeMillis() + attrExpirationPeriod;
            this.isExists = true;
            return f;
        }
        SmbComOpenAndXResponse response2 = new SmbComOpenAndXResponse();
        send(new SmbComOpenAndX(this.unc, access, flags, null), response2);
        return response2.fid;
    }

    void open(int flags, int access, int attrs, int options) throws SmbException {
        if (!isOpen()) {
            this.fid = open0(flags, access, attrs, options);
            this.opened = true;
            this.tree_num = this.tree.tree_num;
        }
    }

    boolean isOpen() {
        return this.opened && isConnected() && this.tree_num == this.tree.tree_num;
    }

    void close(int f, long lastWriteTime) throws SmbException {
        LogStream logStream = log;
        if (LogStream.level >= O_RDWR) {
            log.println(new StringBuffer().append("close: ").append(f).toString());
        }
        send(new SmbComClose(f, lastWriteTime), blank_resp());
    }

    void close(long lastWriteTime) throws SmbException {
        if (isOpen()) {
            close(this.fid, lastWriteTime);
            this.opened = false;
        }
    }

    void close() throws SmbException {
        close(0);
    }

    public Principal getPrincipal() {
        return this.auth;
    }

    public String getName() {
        getUncPath0();
        if (this.canon.length() > TYPE_FILESYSTEM) {
            int i = this.canon.length() - 2;
            while (this.canon.charAt(i) != '/') {
                i--;
            }
            return this.canon.substring(i + TYPE_FILESYSTEM);
        } else if (this.share != null) {
            return new StringBuffer().append(this.share).append('/').toString();
        } else {
            if (this.url.getHost().length() > 0) {
                return new StringBuffer().append(this.url.getHost()).append('/').toString();
            }
            return "smb://";
        }
    }

    public String getParent() {
        String str = this.url.getAuthority();
        if (str.length() <= 0) {
            return "smb://";
        }
        StringBuffer sb = new StringBuffer("smb://");
        sb.append(str);
        getUncPath0();
        if (this.canon.length() > TYPE_FILESYSTEM) {
            sb.append(this.canon);
        } else {
            sb.append('/');
        }
        str = sb.toString();
        int i = str.length() - 2;
        while (str.charAt(i) != '/') {
            i--;
        }
        return str.substring(HASH_DOT_DOT, i + TYPE_FILESYSTEM);
    }

    public String getPath() {
        return this.url.toString();
    }

    String getUncPath0() {
        if (this.unc == null) {
            int o;
            char[] in = this.url.getPath().toCharArray();
            char[] out = new char[in.length];
            int length = in.length;
            int state = HASH_DOT_DOT;
            int i = HASH_DOT_DOT;
            int o2 = HASH_DOT_DOT;
            while (i < length) {
                switch (state) {
                    case HASH_DOT_DOT /*?: ONE_ARG  (wrap: int
  0x000a: INVOKE  (r1_3 int) = (wrap: java.lang.String
  0x0008: CONST_STR  (r1_2 java.lang.String) =  "..") java.lang.String.hashCode():int type: VIRTUAL)*/:
                        if (in[i] == '/') {
                            o = o2 + TYPE_FILESYSTEM;
                            out[o2] = in[i];
                            state = TYPE_FILESYSTEM;
                            break;
                        }
                        return null;
                    case TYPE_FILESYSTEM /*1*/:
                        if (in[i] != '/') {
                            if (in[i] != '.' || (i + TYPE_FILESYSTEM < length && in[i + TYPE_FILESYSTEM] != '/')) {
                                if (i + TYPE_FILESYSTEM < length && in[i] == '.' && in[i + TYPE_FILESYSTEM] == '.' && (i + TYPE_WORKGROUP >= length || in[i + TYPE_WORKGROUP] == '/')) {
                                    i += TYPE_WORKGROUP;
                                    if (o2 != TYPE_FILESYSTEM) {
                                        o = o2;
                                        do {
                                            o--;
                                            if (o <= TYPE_FILESYSTEM) {
                                                break;
                                            }
                                        } while (out[o - 1] != '/');
                                        break;
                                    }
                                    o = o2;
                                    break;
                                }
                                state = TYPE_WORKGROUP;
                            } else {
                                i += TYPE_FILESYSTEM;
                                o = o2;
                                break;
                            }
                        }
                        o = o2;
                        break;
                        break;
                    case TYPE_WORKGROUP /*2*/:
                        if (in[i] == '/') {
                            state = TYPE_FILESYSTEM;
                        }
                        o = o2 + TYPE_FILESYSTEM;
                        out[o2] = in[i];
                        break;
                    default:
                        o = o2;
                        break;
                }
                i += TYPE_FILESYSTEM;
                o2 = o;
            }
            this.canon = new String(out, HASH_DOT_DOT, o2);
            if (o2 > TYPE_FILESYSTEM) {
                o = o2 - 1;
                i = this.canon.indexOf(47, TYPE_FILESYSTEM);
                if (i < 0) {
                    this.share = this.canon.substring(TYPE_FILESYSTEM);
                    this.unc = "\\";
                } else if (i == o) {
                    this.share = this.canon.substring(TYPE_FILESYSTEM, i);
                    this.unc = "\\";
                } else {
                    this.share = this.canon.substring(TYPE_FILESYSTEM, i);
                    String str = this.canon;
                    if (out[o] != '/') {
                        o += TYPE_FILESYSTEM;
                    }
                    this.unc = str.substring(i, o);
                    this.unc = this.unc.replace('/', '\\');
                }
            } else {
                this.share = null;
                this.unc = "\\";
            }
        }
        return this.unc;
    }

    public String getUncPath() {
        getUncPath0();
        if (this.share == null) {
            return new StringBuffer().append("\\\\").append(this.url.getHost()).toString();
        }
        return new StringBuffer().append("\\\\").append(this.url.getHost()).append(this.canon.replace('/', '\\')).toString();
    }

    public String getCanonicalPath() {
        String str = this.url.getAuthority();
        getUncPath0();
        if (str.length() > 0) {
            return new StringBuffer().append("smb://").append(this.url.getAuthority()).append(this.canon).toString();
        }
        return "smb://";
    }

    public String getShare() {
        return this.share;
    }

    String getServerWithDfs() {
        if (this.dfsReferral != null) {
            return this.dfsReferral.server;
        }
        return getServer();
    }

    public String getServer() {
        String str = this.url.getHost();
        if (str.length() == 0) {
            return null;
        }
        return str;
    }

    public int getType() throws SmbException {
        if (this.type == 0) {
            if (getUncPath0().length() > TYPE_FILESYSTEM) {
                this.type = TYPE_FILESYSTEM;
            } else if (this.share != null) {
                connect0();
                if (this.share.equals("IPC$")) {
                    this.type = TYPE_NAMED_PIPE;
                } else if (this.tree.service.equals("LPT1:")) {
                    this.type = TYPE_PRINTER;
                } else if (this.tree.service.equals("COMM")) {
                    this.type = TYPE_COMM;
                } else {
                    this.type = TYPE_SHARE;
                }
            } else if (this.url.getAuthority() == null || this.url.getAuthority().length() == 0) {
                this.type = TYPE_WORKGROUP;
            } else {
                try {
                    UniAddress addr = getAddress();
                    if (addr.getAddress() instanceof NbtAddress) {
                        int code = ((NbtAddress) addr.getAddress()).getNameType();
                        if (code == 29 || code == 27) {
                            this.type = TYPE_WORKGROUP;
                            return this.type;
                        }
                    }
                    this.type = TYPE_SERVER;
                } catch (Throwable uhe) {
                    throw new SmbException(this.url.toString(), uhe);
                }
            }
        }
        return this.type;
    }

    boolean isWorkgroup0() throws UnknownHostException {
        if (this.type == TYPE_WORKGROUP || this.url.getHost().length() == 0) {
            this.type = TYPE_WORKGROUP;
            return true;
        }
        getUncPath0();
        if (this.share == null) {
            UniAddress addr = getAddress();
            if (addr.getAddress() instanceof NbtAddress) {
                int code = ((NbtAddress) addr.getAddress()).getNameType();
                if (code == 29 || code == 27) {
                    this.type = TYPE_WORKGROUP;
                    return true;
                }
            }
            this.type = TYPE_SERVER;
        }
        return false;
    }

    Info queryPath(String path, int infoLevel) throws SmbException {
        connect0();
        LogStream logStream = log;
        if (LogStream.level >= O_RDWR) {
            log.println(new StringBuffer().append("queryPath: ").append(path).toString());
        }
        if (this.tree.session.transport.hasCapability(TYPE_NAMED_PIPE)) {
            Trans2QueryPathInformationResponse response = new Trans2QueryPathInformationResponse(infoLevel);
            send(new Trans2QueryPathInformation(path, infoLevel), response);
            return response.info;
        }
        response = new SmbComQueryInformationResponse(((long) (this.tree.session.transport.server.serverTimeZone * 1000)) * 60);
        send(new SmbComQueryInformation(path), response);
        return response;
    }

    public boolean exists() throws SmbException {
        if (this.attrExpiration > System.currentTimeMillis()) {
            return this.isExists;
        }
        this.attributes = 17;
        this.createTime = 0;
        this.lastModified = 0;
        this.isExists = false;
        try {
            if (this.url.getHost().length() != 0) {
                if (this.share == null) {
                    if (getType() == TYPE_WORKGROUP) {
                        UniAddress.getByName(this.url.getHost(), true);
                    } else {
                        UniAddress.getByName(this.url.getHost()).getHostName();
                    }
                } else if (getUncPath0().length() == TYPE_FILESYSTEM || this.share.equalsIgnoreCase("IPC$")) {
                    connect0();
                } else {
                    Info info = queryPath(getUncPath0(), 257);
                    this.attributes = info.getAttributes();
                    this.createTime = info.getCreateTime();
                    this.lastModified = info.getLastWriteTime();
                }
            }
            this.isExists = true;
        } catch (UnknownHostException e) {
        } catch (SmbException se) {
            switch (se.getNtStatus()) {
                case NtStatus.NT_STATUS_NO_SUCH_FILE /*-1073741809*/:
                case NtStatus.NT_STATUS_OBJECT_NAME_INVALID /*-1073741773*/:
                case NtStatus.NT_STATUS_OBJECT_NAME_NOT_FOUND /*-1073741772*/:
                case NtStatus.NT_STATUS_OBJECT_PATH_NOT_FOUND /*-1073741766*/:
                    break;
                default:
                    throw se;
            }
        }
        this.attrExpiration = System.currentTimeMillis() + attrExpirationPeriod;
        return this.isExists;
    }

    public boolean canRead() throws SmbException {
        if (getType() == TYPE_NAMED_PIPE) {
            return true;
        }
        return exists();
    }

    public boolean canWrite() throws SmbException {
        if (getType() == TYPE_NAMED_PIPE) {
            return true;
        }
        if (exists() && (this.attributes & TYPE_FILESYSTEM) == 0) {
            return true;
        }
        return false;
    }

    public boolean isDirectory() throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            return true;
        }
        if (!exists()) {
            return false;
        }
        if ((this.attributes & TYPE_NAMED_PIPE) != TYPE_NAMED_PIPE) {
            return false;
        }
        return true;
    }

    public boolean isFile() throws SmbException {
        boolean z = true;
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            return false;
        }
        exists();
        if ((this.attributes & TYPE_NAMED_PIPE) != 0) {
            z = false;
        }
        return z;
    }

    public boolean isHidden() throws SmbException {
        boolean z = true;
        if (this.share == null) {
            return false;
        }
        if (getUncPath0().length() != TYPE_FILESYSTEM) {
            exists();
            if ((this.attributes & TYPE_WORKGROUP) != TYPE_WORKGROUP) {
                z = false;
            }
            return z;
        } else if (this.share.endsWith("$")) {
            return true;
        } else {
            return false;
        }
    }

    public String getDfsPath() throws SmbException {
        resolveDfs(null);
        if (this.dfsReferral == null) {
            return null;
        }
        String path = new StringBuffer().append("smb:/").append(this.dfsReferral.server).append("/").append(this.dfsReferral.share).append(this.unc).toString().replace('\\', '/');
        if (isDirectory()) {
            return new StringBuffer().append(path).append('/').toString();
        }
        return path;
    }

    public long createTime() throws SmbException {
        if (getUncPath0().length() <= TYPE_FILESYSTEM) {
            return 0;
        }
        exists();
        return this.createTime;
    }

    public long lastModified() throws SmbException {
        if (getUncPath0().length() <= TYPE_FILESYSTEM) {
            return 0;
        }
        exists();
        return this.lastModified;
    }

    public String[] list() throws SmbException {
        return list("*", 22, null, null);
    }

    public String[] list(SmbFilenameFilter filter) throws SmbException {
        return list("*", 22, filter, null);
    }

    public SmbFile[] listFiles() throws SmbException {
        return listFiles("*", 22, null, null);
    }

    public SmbFile[] listFiles(String wildcard) throws SmbException {
        return listFiles(wildcard, 22, null, null);
    }

    public SmbFile[] listFiles(SmbFilenameFilter filter) throws SmbException {
        return listFiles("*", 22, filter, null);
    }

    public SmbFile[] listFiles(SmbFileFilter filter) throws SmbException {
        return listFiles("*", 22, null, filter);
    }

    String[] list(String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException {
        ArrayList list = new ArrayList();
        doEnum(list, false, wildcard, searchAttributes, fnf, ff);
        return (String[]) list.toArray(new String[list.size()]);
    }

    SmbFile[] listFiles(String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException {
        ArrayList list = new ArrayList();
        doEnum(list, true, wildcard, searchAttributes, fnf, ff);
        return (SmbFile[]) list.toArray(new SmbFile[list.size()]);
    }

    void doEnum(ArrayList list, boolean files, String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException {
        if (ff != null && (ff instanceof DosFileFilter)) {
            DosFileFilter dff = (DosFileFilter) ff;
            if (dff.wildcard != null) {
                wildcard = dff.wildcard;
            }
            searchAttributes = dff.attributes;
        }
        try {
            if (this.url.getHost().length() == 0 || getType() == TYPE_WORKGROUP) {
                doNetServerEnum(list, files, wildcard, searchAttributes, fnf, ff);
            } else if (this.share == null) {
                doShareEnum(list, files, wildcard, searchAttributes, fnf, ff);
            } else {
                doFindFirstNext(list, files, wildcard, searchAttributes, fnf, ff);
            }
        } catch (Throwable uhe) {
            throw new SmbException(this.url.toString(), uhe);
        } catch (Throwable mue) {
            throw new SmbException(this.url.toString(), mue);
        }
    }

    void doShareEnum(ArrayList list, boolean files, String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException, UnknownHostException, MalformedURLException {
        LogStream logStream;
        String p = this.url.getPath();
        Throwable last = null;
        if (p.lastIndexOf(47) != p.length() - 1) {
            throw new SmbException(new StringBuffer().append(this.url.toString()).append(" directory must end with '/'").toString());
        } else if (getType() != TYPE_SERVER) {
            throw new SmbException(new StringBuffer().append("The requested list operations is invalid: ").append(this.url.toString()).toString());
        } else {
            FileEntry[] entries;
            int ei;
            FileEntry e;
            HashMap map = new HashMap();
            if (dfs.isTrustedDomain(getServer(), this.auth)) {
                try {
                    entries = doDfsRootEnum();
                    for (ei = HASH_DOT_DOT; ei < entries.length; ei += TYPE_FILESYSTEM) {
                        e = entries[ei];
                        if (!map.containsKey(e)) {
                            map.put(e, e);
                        }
                    }
                } catch (IOException ioe) {
                    logStream = log;
                    if (LogStream.level >= TYPE_SERVER) {
                        ioe.printStackTrace(log);
                    }
                }
            }
            UniAddress addr = getFirstAddress();
            loop1:
            while (addr != null) {
                try {
                    doConnect();
                    try {
                        entries = doMsrpcShareEnum();
                    } catch (IOException ioe2) {
                        logStream = log;
                        if (LogStream.level >= O_RDWR) {
                            ioe2.printStackTrace(log);
                        }
                        entries = doNetShareEnum();
                    }
                    for (ei = HASH_DOT_DOT; ei < entries.length; ei += TYPE_FILESYSTEM) {
                        e = entries[ei];
                        if (!map.containsKey(e)) {
                            map.put(e, e);
                        }
                    }
                    break loop1;
                } catch (Throwable ioe3) {
                    logStream = log;
                    if (LogStream.level >= O_RDWR) {
                        ioe3.printStackTrace(log);
                    }
                    last = ioe3;
                    addr = getNextAddress();
                }
            }
            if (last == null || !map.isEmpty()) {
                for (FileEntry e2 : map.keySet()) {
                    String name = e2.getName();
                    if ((fnf == null || fnf.accept(this, name)) && name.length() > 0) {
                        SmbFile f = new SmbFile(this, name, e2.getType(), 17, 0, 0, 0);
                        if (ff == null || ff.accept(f)) {
                            if (files) {
                                list.add(f);
                            } else {
                                list.add(name);
                            }
                        }
                    }
                }
            } else if (last instanceof SmbException) {
                throw ((SmbException) last);
            } else {
                throw new SmbException(this.url.toString(), last);
            }
        }
    }

    FileEntry[] doDfsRootEnum() throws IOException {
        DcerpcHandle handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(getAddress().getHostAddress()).append("[\\PIPE\\netdfs]").toString(), this.auth);
        try {
            MsrpcDfsRootEnum rpc = new MsrpcDfsRootEnum(getServer());
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
                if (LogStream.level >= TYPE_SERVER) {
                    ioe.printStackTrace(log);
                }
            }
        }
    }

    FileEntry[] doMsrpcShareEnum() throws IOException {
        MsrpcShareEnum rpc = new MsrpcShareEnum(this.url.getHost());
        DcerpcHandle handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(getAddress().getHostAddress()).append("[\\PIPE\\srvsvc]").toString(), this.auth);
        try {
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
                if (LogStream.level >= TYPE_SERVER) {
                    ioe.printStackTrace(log);
                }
            }
        }
    }

    FileEntry[] doNetShareEnum() throws SmbException {
        SmbComTransaction req = new NetShareEnum();
        SmbComTransactionResponse resp = new NetShareEnumResponse();
        send(req, resp);
        if (resp.status == 0) {
            return resp.results;
        }
        throw new SmbException(resp.status, true);
    }

    void doNetServerEnum(ArrayList list, boolean files, String wildcard, int searchAttributes, SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException, UnknownHostException, MalformedURLException {
        ServerMessageBlock resp;
        int listType = this.url.getHost().length() == 0 ? HASH_DOT_DOT : getType();
        ServerMessageBlock netServerEnum2;
        if (listType == 0) {
            connect0();
            netServerEnum2 = new NetServerEnum2(this.tree.session.transport.server.oemDomainName, SmbConstants.GENERIC_READ);
            resp = new NetServerEnum2Response();
        } else if (listType == TYPE_WORKGROUP) {
            netServerEnum2 = new NetServerEnum2(this.url.getHost(), -1);
            resp = new NetServerEnum2Response();
        } else {
            throw new SmbException(new StringBuffer().append("The requested list operations is invalid: ").append(this.url.toString()).toString());
        }
        boolean more;
        do {
            send(req, resp);
            if (resp.status == 0 || resp.status == WinError.ERROR_MORE_DATA) {
                more = resp.status == WinError.ERROR_MORE_DATA;
                int n = more ? resp.numEntries - 1 : resp.numEntries;
                for (int i = HASH_DOT_DOT; i < n; i += TYPE_FILESYSTEM) {
                    FileEntry e = resp.results[i];
                    String name = e.getName();
                    if ((fnf == null || fnf.accept(this, name)) && name.length() > 0) {
                        SmbFile f = new SmbFile(this, name, e.getType(), 17, 0, 0, 0);
                        if (ff == null || ff.accept(f)) {
                            if (files) {
                                list.add(f);
                            } else {
                                list.add(name);
                            }
                        }
                    }
                }
                if (getType() == TYPE_WORKGROUP) {
                    req.subCommand = (byte) -41;
                    req.reset(HASH_DOT_DOT, ((NetServerEnum2Response) resp).lastName);
                    resp.reset();
                } else {
                    return;
                }
            }
            throw new SmbException(resp.status, true);
        } while (more);
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    void doFindFirstNext(java.util.ArrayList r25, boolean r26, java.lang.String r27, int r28, jcifs.smb.SmbFilenameFilter r29, jcifs.smb.SmbFileFilter r30) throws jcifs.smb.SmbException, java.net.UnknownHostException, java.net.MalformedURLException {
        /*
        r24 = this;
        r19 = r24.getUncPath0();
        r0 = r24;
        r5 = r0.url;
        r18 = r5.getPath();
        r5 = 47;
        r0 = r18;
        r5 = r0.lastIndexOf(r5);
        r7 = r18.length();
        r7 = r7 + -1;
        if (r5 == r7) goto L_0x003d;
    L_0x001c:
        r5 = new jcifs.smb.SmbException;
        r7 = new java.lang.StringBuffer;
        r7.<init>();
        r0 = r24;
        r8 = r0.url;
        r8 = r8.toString();
        r7 = r7.append(r8);
        r8 = " directory must end with '/'";
        r7 = r7.append(r8);
        r7 = r7.toString();
        r5.<init>(r7);
        throw r5;
    L_0x003d:
        r20 = new jcifs.smb.Trans2FindFirst2;
        r0 = r20;
        r1 = r19;
        r2 = r27;
        r3 = r28;
        r0.<init>(r1, r2, r3);
        r21 = new jcifs.smb.Trans2FindFirst2Response;
        r21.<init>();
        r5 = log;
        r5 = jcifs.util.LogStream.level;
        r7 = 3;
        if (r5 < r7) goto L_0x0072;
    L_0x0056:
        r5 = log;
        r7 = new java.lang.StringBuffer;
        r7.<init>();
        r8 = "doFindFirstNext: ";
        r7 = r7.append(r8);
        r0 = r20;
        r8 = r0.path;
        r7 = r7.append(r8);
        r7 = r7.toString();
        r5.println(r7);
    L_0x0072:
        r0 = r24;
        r1 = r20;
        r2 = r21;
        r0.send(r1, r2);
        r0 = r21;
        r0 = r0.sid;
        r23 = r0;
        r20 = new jcifs.smb.Trans2FindNext2;
        r0 = r21;
        r5 = r0.resumeKey;
        r0 = r21;
        r7 = r0.lastName;
        r0 = r20;
        r1 = r23;
        r0.<init>(r1, r5, r7);
        r5 = 2;
        r0 = r21;
        r0.subCommand = r5;
    L_0x0097:
        r17 = 0;
    L_0x0099:
        r0 = r21;
        r5 = r0.numEntries;
        r0 = r17;
        if (r0 >= r5) goto L_0x0117;
    L_0x00a1:
        r0 = r21;
        r5 = r0.results;
        r15 = r5[r17];
        r6 = r15.getName();
        r5 = r6.length();
        r7 = 3;
        if (r5 >= r7) goto L_0x00d5;
    L_0x00b2:
        r16 = r6.hashCode();
        r5 = HASH_DOT;
        r0 = r16;
        if (r0 == r5) goto L_0x00c2;
    L_0x00bc:
        r5 = HASH_DOT_DOT;
        r0 = r16;
        if (r0 != r5) goto L_0x00d5;
    L_0x00c2:
        r5 = ".";
        r5 = r6.equals(r5);
        if (r5 != 0) goto L_0x00d2;
    L_0x00ca:
        r5 = "..";
        r5 = r6.equals(r5);
        if (r5 == 0) goto L_0x00d5;
    L_0x00d2:
        r17 = r17 + 1;
        goto L_0x0099;
    L_0x00d5:
        if (r29 == 0) goto L_0x00e1;
    L_0x00d7:
        r0 = r29;
        r1 = r24;
        r5 = r0.accept(r1, r6);
        if (r5 == 0) goto L_0x00d2;
    L_0x00e1:
        r5 = r6.length();
        if (r5 <= 0) goto L_0x00d2;
    L_0x00e7:
        r4 = new jcifs.smb.SmbFile;
        r7 = 1;
        r8 = r15.getAttributes();
        r9 = r15.createTime();
        r11 = r15.lastModified();
        r13 = r15.length();
        r5 = r24;
        r4.<init>(r5, r6, r7, r8, r9, r11, r13);
        if (r30 == 0) goto L_0x0109;
    L_0x0101:
        r0 = r30;
        r5 = r0.accept(r4);
        if (r5 == 0) goto L_0x00d2;
    L_0x0109:
        if (r26 == 0) goto L_0x0111;
    L_0x010b:
        r0 = r25;
        r0.add(r4);
        goto L_0x00d2;
    L_0x0111:
        r0 = r25;
        r0.add(r6);
        goto L_0x00d2;
    L_0x0117:
        r0 = r21;
        r5 = r0.isEndOfSearch;
        if (r5 != 0) goto L_0x0123;
    L_0x011d:
        r0 = r21;
        r5 = r0.numEntries;
        if (r5 != 0) goto L_0x0134;
    L_0x0123:
        r5 = new jcifs.smb.SmbComFindClose2;	 Catch:{ SmbException -> 0x014f }
        r0 = r23;
        r5.<init>(r0);	 Catch:{ SmbException -> 0x014f }
        r7 = r24.blank_resp();	 Catch:{ SmbException -> 0x014f }
        r0 = r24;
        r0.send(r5, r7);	 Catch:{ SmbException -> 0x014f }
    L_0x0133:
        return;
    L_0x0134:
        r0 = r21;
        r5 = r0.resumeKey;
        r0 = r21;
        r7 = r0.lastName;
        r0 = r20;
        r0.reset(r5, r7);
        r21.reset();
        r0 = r24;
        r1 = r20;
        r2 = r21;
        r0.send(r1, r2);
        goto L_0x0097;
    L_0x014f:
        r22 = move-exception;
        r5 = log;
        r5 = jcifs.util.LogStream.level;
        r7 = 4;
        if (r5 < r7) goto L_0x0133;
    L_0x0157:
        r5 = log;
        r0 = r22;
        r0.printStackTrace(r5);
        goto L_0x0133;
        */
        throw new UnsupportedOperationException("Method not decompiled: jcifs.smb.SmbFile.doFindFirstNext(java.util.ArrayList, boolean, java.lang.String, int, jcifs.smb.SmbFilenameFilter, jcifs.smb.SmbFileFilter):void");
    }

    public void renameTo(SmbFile dest) throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM || dest.getUncPath0().length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        resolveDfs(null);
        dest.resolveDfs(null);
        if (this.tree.equals(dest.tree)) {
            LogStream logStream = log;
            if (LogStream.level >= O_RDWR) {
                log.println(new StringBuffer().append("renameTo: ").append(this.unc).append(" -> ").append(dest.unc).toString());
            }
            this.sizeExpiration = 0;
            this.attrExpiration = 0;
            dest.attrExpiration = 0;
            send(new SmbComRename(this.unc, dest.unc), blank_resp());
            return;
        }
        throw new SmbException("Invalid operation for workgroups, servers, or shares");
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    void copyTo0(jcifs.smb.SmbFile r26, byte[][] r27, int r28, jcifs.smb.SmbFile.WriterThread r29, jcifs.smb.SmbComReadAndX r30, jcifs.smb.SmbComReadAndXResponse r31) throws jcifs.smb.SmbException {
        /*
        r25 = this;
        r0 = r25;
        r4 = r0.attrExpiration;
        r6 = java.lang.System.currentTimeMillis();
        r4 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1));
        if (r4 >= 0) goto L_0x0057;
    L_0x000c:
        r4 = 17;
        r0 = r25;
        r0.attributes = r4;
        r4 = 0;
        r0 = r25;
        r0.createTime = r4;
        r4 = 0;
        r0 = r25;
        r0.lastModified = r4;
        r4 = 0;
        r0 = r25;
        r0.isExists = r4;
        r4 = r25.getUncPath0();
        r5 = 257; // 0x101 float:3.6E-43 double:1.27E-321;
        r0 = r25;
        r18 = r0.queryPath(r4, r5);
        r4 = r18.getAttributes();
        r0 = r25;
        r0.attributes = r4;
        r4 = r18.getCreateTime();
        r0 = r25;
        r0.createTime = r4;
        r4 = r18.getLastWriteTime();
        r0 = r25;
        r0.lastModified = r4;
        r4 = 1;
        r0 = r25;
        r0.isExists = r4;
        r4 = java.lang.System.currentTimeMillis();
        r6 = attrExpirationPeriod;
        r4 = r4 + r6;
        r0 = r25;
        r0.attrExpiration = r4;
    L_0x0057:
        r4 = r25.isDirectory();
        if (r4 == 0) goto L_0x00f9;
    L_0x005d:
        r21 = r26.getUncPath0();
        r4 = r21.length();
        r5 = 1;
        if (r4 <= r5) goto L_0x007c;
    L_0x0068:
        r26.mkdir();	 Catch:{ SmbException -> 0x00c3 }
        r0 = r25;
        r4 = r0.attributes;	 Catch:{ SmbException -> 0x00c3 }
        r0 = r25;
        r5 = r0.createTime;	 Catch:{ SmbException -> 0x00c3 }
        r0 = r25;
        r7 = r0.lastModified;	 Catch:{ SmbException -> 0x00c3 }
        r3 = r26;
        r3.setPathInformation(r4, r5, r7);	 Catch:{ SmbException -> 0x00c3 }
    L_0x007c:
        r4 = "*";
        r5 = 22;
        r6 = 0;
        r7 = 0;
        r0 = r25;
        r15 = r0.listFiles(r4, r5, r6, r7);
        r16 = 0;
    L_0x008a:
        r4 = r15.length;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r0 = r16;
        if (r0 >= r4) goto L_0x0153;
    L_0x008f:
        r3 = new jcifs.smb.SmbFile;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r5 = r4.getName();	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r6 = r4.type;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r7 = r4.attributes;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r8 = r4.createTime;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r10 = r4.lastModified;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r12 = r4.size;	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r26;
        r3.<init>(r4, r5, r6, r7, r8, r10, r12);	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r4 = r15[r16];	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r5 = r3;
        r6 = r27;
        r7 = r28;
        r8 = r29;
        r9 = r30;
        r10 = r31;
        r4.copyTo0(r5, r6, r7, r8, r9, r10);	 Catch:{ UnknownHostException -> 0x00d7, MalformedURLException -> 0x00e8 }
        r16 = r16 + 1;
        goto L_0x008a;
    L_0x00c3:
        r23 = move-exception;
        r4 = r23.getNtStatus();
        r5 = -1073741790; // 0xffffffffc0000022 float:-2.000008 double:NaN;
        if (r4 == r5) goto L_0x007c;
    L_0x00cd:
        r4 = r23.getNtStatus();
        r5 = -1073741771; // 0xffffffffc0000035 float:-2.0000126 double:NaN;
        if (r4 == r5) goto L_0x007c;
    L_0x00d6:
        throw r23;
    L_0x00d7:
        r24 = move-exception;
        r4 = new jcifs.smb.SmbException;
        r0 = r25;
        r5 = r0.url;
        r5 = r5.toString();
        r0 = r24;
        r4.<init>(r5, r0);
        throw r4;
    L_0x00e8:
        r19 = move-exception;
        r4 = new jcifs.smb.SmbException;
        r0 = r25;
        r5 = r0.url;
        r5 = r5.toString();
        r0 = r19;
        r4.<init>(r5, r0);
        throw r4;
    L_0x00f9:
        r4 = 1;
        r5 = 0;
        r6 = 128; // 0x80 float:1.8E-43 double:6.3E-322;
        r7 = 0;
        r0 = r25;
        r0.open(r4, r5, r6, r7);	 Catch:{ Exception -> 0x0143 }
        r4 = 82;
        r5 = 258; // 0x102 float:3.62E-43 double:1.275E-321;
        r0 = r25;
        r6 = r0.attributes;	 Catch:{ SmbAuthException -> 0x0154 }
        r7 = 0;
        r0 = r26;
        r0.open(r4, r5, r6, r7);	 Catch:{ SmbAuthException -> 0x0154 }
    L_0x0111:
        r20 = 0;
        r16 = r20;
    L_0x0115:
        r0 = r25;
        r4 = r0.fid;	 Catch:{ Exception -> 0x0143 }
        r0 = r20;
        r5 = (long) r0;	 Catch:{ Exception -> 0x0143 }
        r0 = r30;
        r1 = r28;
        r0.setParam(r4, r5, r1);	 Catch:{ Exception -> 0x0143 }
        r4 = r27[r16];	 Catch:{ Exception -> 0x0143 }
        r5 = 0;
        r0 = r31;
        r0.setParam(r4, r5);	 Catch:{ Exception -> 0x0143 }
        r0 = r25;
        r1 = r30;
        r2 = r31;
        r0.send(r1, r2);	 Catch:{ Exception -> 0x0143 }
        monitor-enter(r29);	 Catch:{ Exception -> 0x0143 }
        r0 = r29;
        r4 = r0.e;	 Catch:{ all -> 0x0140 }
        if (r4 == 0) goto L_0x0181;
    L_0x013b:
        r0 = r29;
        r4 = r0.e;	 Catch:{ all -> 0x0140 }
        throw r4;	 Catch:{ all -> 0x0140 }
    L_0x0140:
        r4 = move-exception;
        monitor-exit(r29);	 Catch:{ all -> 0x0140 }
        throw r4;	 Catch:{ Exception -> 0x0143 }
    L_0x0143:
        r14 = move-exception;
        r4 = log;	 Catch:{ all -> 0x017b }
        r4 = jcifs.util.LogStream.level;	 Catch:{ all -> 0x017b }
        r5 = 1;
        if (r4 <= r5) goto L_0x0150;
    L_0x014b:
        r4 = log;	 Catch:{ all -> 0x017b }
        r14.printStackTrace(r4);	 Catch:{ all -> 0x017b }
    L_0x0150:
        r25.close();
    L_0x0153:
        return;
    L_0x0154:
        r22 = move-exception;
        r0 = r26;
        r4 = r0.attributes;	 Catch:{ Exception -> 0x0143 }
        r4 = r4 & 1;
        if (r4 == 0) goto L_0x0180;
    L_0x015d:
        r0 = r26;
        r4 = r0.attributes;	 Catch:{ Exception -> 0x0143 }
        r5 = r4 & -2;
        r6 = 0;
        r8 = 0;
        r4 = r26;
        r4.setPathInformation(r5, r6, r8);	 Catch:{ Exception -> 0x0143 }
        r4 = 82;
        r5 = 258; // 0x102 float:3.62E-43 double:1.275E-321;
        r0 = r25;
        r6 = r0.attributes;	 Catch:{ Exception -> 0x0143 }
        r7 = 0;
        r0 = r26;
        r0.open(r4, r5, r6, r7);	 Catch:{ Exception -> 0x0143 }
        goto L_0x0111;
    L_0x017b:
        r4 = move-exception;
        r25.close();
        throw r4;
    L_0x0180:
        throw r22;	 Catch:{ Exception -> 0x0143 }
    L_0x0181:
        r0 = r29;
        r4 = r0.ready;	 Catch:{ all -> 0x0140 }
        if (r4 != 0) goto L_0x019c;
    L_0x0187:
        r29.wait();	 Catch:{ InterruptedException -> 0x018b }
        goto L_0x0181;
    L_0x018b:
        r17 = move-exception;
        r4 = new jcifs.smb.SmbException;	 Catch:{ all -> 0x0140 }
        r0 = r26;
        r5 = r0.url;	 Catch:{ all -> 0x0140 }
        r5 = r5.toString();	 Catch:{ all -> 0x0140 }
        r0 = r17;
        r4.<init>(r5, r0);	 Catch:{ all -> 0x0140 }
        throw r4;	 Catch:{ all -> 0x0140 }
    L_0x019c:
        r0 = r29;
        r4 = r0.e;	 Catch:{ all -> 0x0140 }
        if (r4 == 0) goto L_0x01a7;
    L_0x01a2:
        r0 = r29;
        r4 = r0.e;	 Catch:{ all -> 0x0140 }
        throw r4;	 Catch:{ all -> 0x0140 }
    L_0x01a7:
        r0 = r31;
        r4 = r0.dataLength;	 Catch:{ all -> 0x0140 }
        if (r4 > 0) goto L_0x01d9;
    L_0x01ad:
        monitor-exit(r29);	 Catch:{ all -> 0x0140 }
        r4 = new jcifs.smb.Trans2SetFileInformation;	 Catch:{ Exception -> 0x0143 }
        r0 = r26;
        r5 = r0.fid;	 Catch:{ Exception -> 0x0143 }
        r0 = r25;
        r6 = r0.attributes;	 Catch:{ Exception -> 0x0143 }
        r0 = r25;
        r7 = r0.createTime;	 Catch:{ Exception -> 0x0143 }
        r0 = r25;
        r9 = r0.lastModified;	 Catch:{ Exception -> 0x0143 }
        r4.<init>(r5, r6, r7, r9);	 Catch:{ Exception -> 0x0143 }
        r5 = new jcifs.smb.Trans2SetFileInformationResponse;	 Catch:{ Exception -> 0x0143 }
        r5.<init>();	 Catch:{ Exception -> 0x0143 }
        r0 = r26;
        r0.send(r4, r5);	 Catch:{ Exception -> 0x0143 }
        r4 = 0;
        r0 = r26;
        r0.close(r4);	 Catch:{ Exception -> 0x0143 }
        r25.close();
        goto L_0x0153;
    L_0x01d9:
        r4 = r27[r16];	 Catch:{ all -> 0x0140 }
        r0 = r31;
        r5 = r0.dataLength;	 Catch:{ all -> 0x0140 }
        r0 = r29;
        r1 = r26;
        r2 = r20;
        r0.write(r4, r5, r1, r2);	 Catch:{ all -> 0x0140 }
        monitor-exit(r29);	 Catch:{ all -> 0x0140 }
        r4 = 1;
        r0 = r16;
        if (r0 != r4) goto L_0x01f8;
    L_0x01ee:
        r16 = 0;
    L_0x01f0:
        r0 = r31;
        r4 = r0.dataLength;	 Catch:{ Exception -> 0x0143 }
        r20 = r20 + r4;
        goto L_0x0115;
    L_0x01f8:
        r16 = 1;
        goto L_0x01f0;
        */
        throw new UnsupportedOperationException("Method not decompiled: jcifs.smb.SmbFile.copyTo0(jcifs.smb.SmbFile, byte[][], int, jcifs.smb.SmbFile$WriterThread, jcifs.smb.SmbComReadAndX, jcifs.smb.SmbComReadAndXResponse):void");
    }

    public void copyTo(SmbFile dest) throws SmbException {
        if (this.share == null || dest.share == null) {
            throw new SmbException("Invalid operation for workgroups or servers");
        }
        SmbComReadAndX req = new SmbComReadAndX();
        SmbComReadAndXResponse resp = new SmbComReadAndXResponse();
        connect0();
        dest.connect0();
        resolveDfs(null);
        try {
            if (getAddress().equals(dest.getAddress()) && this.canon.regionMatches(true, HASH_DOT_DOT, dest.canon, HASH_DOT_DOT, Math.min(this.canon.length(), dest.canon.length()))) {
                throw new SmbException("Source and destination paths overlap.");
            }
        } catch (UnknownHostException e) {
        }
        WriterThread w = new WriterThread(this);
        w.setDaemon(true);
        w.start();
        SmbTransport t1 = this.tree.session.transport;
        SmbTransport t2 = dest.tree.session.transport;
        if (t1.snd_buf_size < t2.snd_buf_size) {
            t2.snd_buf_size = t1.snd_buf_size;
        } else {
            t1.snd_buf_size = t2.snd_buf_size;
        }
        int bsize = Math.min(t1.rcv_buf_size - 70, t1.snd_buf_size - 70);
        try {
            copyTo0(dest, (byte[][]) Array.newInstance(Byte.TYPE, new int[]{TYPE_WORKGROUP, bsize}), bsize, w, req, resp);
        } finally {
            w.write(null, -1, null, HASH_DOT_DOT);
        }
    }

    public void delete() throws SmbException {
        exists();
        getUncPath0();
        delete(this.unc);
    }

    void delete(String fileName) throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        if (System.currentTimeMillis() > this.attrExpiration) {
            this.attributes = 17;
            this.createTime = 0;
            this.lastModified = 0;
            this.isExists = false;
            Info info = queryPath(getUncPath0(), 257);
            this.attributes = info.getAttributes();
            this.createTime = info.getCreateTime();
            this.lastModified = info.getLastWriteTime();
            this.attrExpiration = System.currentTimeMillis() + attrExpirationPeriod;
            this.isExists = true;
        }
        if ((this.attributes & TYPE_FILESYSTEM) != 0) {
            setReadWrite();
        }
        LogStream logStream = log;
        if (LogStream.level >= O_RDWR) {
            log.println(new StringBuffer().append("delete: ").append(fileName).toString());
        }
        if ((this.attributes & TYPE_NAMED_PIPE) != 0) {
            try {
                SmbFile[] l = listFiles("*", 22, null, null);
                for (int i = HASH_DOT_DOT; i < l.length; i += TYPE_FILESYSTEM) {
                    l[i].delete();
                }
            } catch (SmbException se) {
                if (se.getNtStatus() != NtStatus.NT_STATUS_NO_SUCH_FILE) {
                    throw se;
                }
            }
            send(new SmbComDeleteDirectory(fileName), blank_resp());
        } else {
            send(new SmbComDelete(fileName), blank_resp());
        }
        this.sizeExpiration = 0;
        this.attrExpiration = 0;
    }

    public long length() throws SmbException {
        if (this.sizeExpiration > System.currentTimeMillis()) {
            return this.size;
        }
        if (getType() == TYPE_SHARE) {
            Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(TYPE_FILESYSTEM);
            send(new Trans2QueryFSInformation(TYPE_FILESYSTEM), response);
            this.size = response.info.getCapacity();
        } else if (getUncPath0().length() <= TYPE_FILESYSTEM || this.type == TYPE_NAMED_PIPE) {
            this.size = 0;
        } else {
            this.size = queryPath(getUncPath0(), 258).getSize();
        }
        this.sizeExpiration = System.currentTimeMillis() + attrExpirationPeriod;
        return this.size;
    }

    public long getDiskFreeSpace() throws SmbException {
        if (getType() != TYPE_SHARE && this.type != TYPE_FILESYSTEM) {
            return 0;
        }
        try {
            return queryFSInformation(1007);
        } catch (SmbException ex) {
            switch (ex.getNtStatus()) {
                case NtStatus.NT_STATUS_UNSUCCESSFUL /*-1073741823*/:
                case NtStatus.NT_STATUS_INVALID_INFO_CLASS /*-1073741821*/:
                    return queryFSInformation(TYPE_FILESYSTEM);
                default:
                    throw ex;
            }
        }
    }

    private long queryFSInformation(int level) throws SmbException {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(level);
        send(new Trans2QueryFSInformation(level), response);
        if (this.type == TYPE_SHARE) {
            this.size = response.info.getCapacity();
            this.sizeExpiration = System.currentTimeMillis() + attrExpirationPeriod;
        }
        return response.info.getFree();
    }

    public void mkdir() throws SmbException {
        String path = getUncPath0();
        if (path.length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        LogStream logStream = log;
        if (LogStream.level >= O_RDWR) {
            log.println(new StringBuffer().append("mkdir: ").append(path).toString());
        }
        send(new SmbComCreateDirectory(path), blank_resp());
        this.sizeExpiration = 0;
        this.attrExpiration = 0;
    }

    public void mkdirs() throws SmbException {
        try {
            SmbFile parent = new SmbFile(getParent(), this.auth);
            if (!parent.exists()) {
                parent.mkdirs();
            }
            mkdir();
        } catch (IOException e) {
        }
    }

    public void createNewFile() throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        close(open0(51, HASH_DOT_DOT, ATTR_NORMAL, HASH_DOT_DOT), 0);
    }

    void setPathInformation(int attrs, long ctime, long mtime) throws SmbException {
        exists();
        int dir = this.attributes & TYPE_NAMED_PIPE;
        int f = open0(TYPE_FILESYSTEM, ATTR_TEMPORARY, dir, dir != 0 ? TYPE_FILESYSTEM : TYPE_COMM);
        send(new Trans2SetFileInformation(f, attrs | dir, ctime, mtime), new Trans2SetFileInformationResponse());
        close(f, 0);
        this.attrExpiration = 0;
    }

    public void setCreateTime(long time) throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        setPathInformation(HASH_DOT_DOT, time, 0);
    }

    public void setLastModified(long time) throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        setPathInformation(HASH_DOT_DOT, 0, time);
    }

    public int getAttributes() throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            return HASH_DOT_DOT;
        }
        exists();
        return this.attributes & ATTR_GET_MASK;
    }

    public void setAttributes(int attrs) throws SmbException {
        if (getUncPath0().length() == TYPE_FILESYSTEM) {
            throw new SmbException("Invalid operation for workgroups, servers, or shares");
        }
        setPathInformation(attrs & ATTR_SET_MASK, 0, 0);
    }

    public void setReadOnly() throws SmbException {
        setAttributes(getAttributes() | TYPE_FILESYSTEM);
    }

    public void setReadWrite() throws SmbException {
        setAttributes(getAttributes() & -2);
    }

    public URL toURL() throws MalformedURLException {
        return this.url;
    }

    public int hashCode() {
        int hash;
        try {
            hash = getAddress().hashCode();
        } catch (UnknownHostException e) {
            hash = getServer().toUpperCase().hashCode();
        }
        getUncPath0();
        return this.canon.toUpperCase().hashCode() + hash;
    }

    protected boolean pathNamesPossiblyEqual(String path1, String path2) {
        int p1 = path1.lastIndexOf(47);
        int p2 = path2.lastIndexOf(47);
        int l1 = path1.length() - p1;
        int l2 = path2.length() - p2;
        if (l1 > TYPE_FILESYSTEM && path1.charAt(p1 + TYPE_FILESYSTEM) == '.') {
            return true;
        }
        if (l2 > TYPE_FILESYSTEM && path2.charAt(p2 + TYPE_FILESYSTEM) == '.') {
            return true;
        }
        if (l1 == l2 && path1.regionMatches(true, p1, path2, p2, l1)) {
            return true;
        }
        return false;
    }

    public boolean equals(Object obj) {
        if (obj instanceof SmbFile) {
            SmbFile f = (SmbFile) obj;
            if (this == f) {
                return true;
            }
            if (pathNamesPossiblyEqual(this.url.getPath(), f.url.getPath())) {
                getUncPath0();
                f.getUncPath0();
                if (this.canon.equalsIgnoreCase(f.canon)) {
                    try {
                        return getAddress().equals(f.getAddress());
                    } catch (UnknownHostException e) {
                        return getServer().equalsIgnoreCase(f.getServer());
                    }
                }
            }
        }
        return false;
    }

    public String toString() {
        return this.url.toString();
    }

    public int getContentLength() {
        try {
            return (int) (length() & 4294967295L);
        } catch (SmbException e) {
            return HASH_DOT_DOT;
        }
    }

    public long getDate() {
        try {
            return lastModified();
        } catch (SmbException e) {
            return 0;
        }
    }

    public long getLastModified() {
        try {
            return lastModified();
        } catch (SmbException e) {
            return 0;
        }
    }

    public InputStream getInputStream() throws IOException {
        return new SmbFileInputStream(this);
    }

    public OutputStream getOutputStream() throws IOException {
        return new SmbFileOutputStream(this);
    }

    private void processAces(ACE[] aces, boolean resolveSids) throws IOException {
        String server = getServerWithDfs();
        int ai;
        if (resolveSids) {
            SID[] sids = new SID[aces.length];
            for (ai = HASH_DOT_DOT; ai < aces.length; ai += TYPE_FILESYSTEM) {
                sids[ai] = aces[ai].sid;
            }
            for (int off = HASH_DOT_DOT; off < sids.length; off += 10) {
                int len = sids.length - off;
                if (len > TYPE_COMM) {
                    len = TYPE_COMM;
                }
                SID.resolveSids(server, this.auth, sids, off, len);
            }
            return;
        }
        for (ai = HASH_DOT_DOT; ai < aces.length; ai += TYPE_FILESYSTEM) {
            aces[ai].sid.origin_server = server;
            aces[ai].sid.origin_auth = this.auth;
        }
    }

    public ACE[] getSecurity(boolean resolveSids) throws IOException {
        int f = open0(TYPE_FILESYSTEM, SmbConstants.READ_CONTROL, HASH_DOT_DOT, isDirectory() ? TYPE_FILESYSTEM : HASH_DOT_DOT);
        NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(f, TYPE_SERVER);
        NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();
        try {
            send(request, response);
            ACE[] aces = response.securityDescriptor.aces;
            if (aces != null) {
                processAces(aces, resolveSids);
            }
            return aces;
        } finally {
            close(f, 0);
        }
    }

    public ACE[] getShareSecurity(boolean resolveSids) throws IOException {
        String p = this.url.getPath();
        resolveDfs(null);
        String server = getServerWithDfs();
        MsrpcShareGetInfo rpc = new MsrpcShareGetInfo(server, this.tree.share);
        DcerpcHandle handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(server).append("[\\PIPE\\srvsvc]").toString(), this.auth);
        try {
            handle.sendrecv(rpc);
            if (rpc.retval != 0) {
                throw new SmbException(rpc.retval, true);
            }
            ACE[] aces = rpc.getSecurity();
            if (aces != null) {
                processAces(aces, resolveSids);
            }
            return aces;
        } finally {
            try {
                handle.close();
            } catch (IOException ioe) {
                LogStream logStream = log;
                if (LogStream.level >= TYPE_FILESYSTEM) {
                    ioe.printStackTrace(log);
                }
            }
        }
    }

    public ACE[] getSecurity() throws IOException {
        return getSecurity(false);
    }
}
