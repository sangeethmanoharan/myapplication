package jcifs.smb;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.Vector;
import jcifs.Config;
import jcifs.UniAddress;
import jcifs.netbios.NbtAddress;
import jcifs.util.LogStream;
import lksystems.wifiintruder.BuildConfig;

public final class SmbSession {
    private static final int CACHE_POLICY = (Config.getInt("jcifs.netbios.cachePolicy", 600) * 60);
    private static final String DOMAIN = Config.getProperty("jcifs.smb.client.domain", null);
    private static final String LOGON_SHARE = Config.getProperty("jcifs.smb.client.logonShare", null);
    private static final int LOOKUP_RESP_LIMIT = Config.getInt("jcifs.netbios.lookupRespLimit", 3);
    private static final String USERNAME = Config.getProperty("jcifs.smb.client.username", null);
    static NbtAddress[] dc_list = null;
    static int dc_list_counter;
    static long dc_list_expiration;
    private UniAddress address;
    NtlmPasswordAuthentication auth;
    long expiration;
    private InetAddress localAddr;
    private int localPort;
    private int port;
    private boolean sessionSetup;
    SmbTransport transport = null;
    Vector trees;
    private int uid;

    private static NtlmChallenge interrogate(NbtAddress addr) throws SmbException {
        UniAddress dc = new UniAddress(addr);
        SmbTransport trans = SmbTransport.getSmbTransport(dc, 0);
        if (USERNAME == null) {
            trans.connect();
            LogStream logStream = SmbTransport.log;
            if (LogStream.level >= 3) {
                SmbTransport.log.println("Default credentials (jcifs.smb.client.username/password) not specified. SMB signing may not work propertly.  Skipping DC interrogation.");
            }
        } else {
            trans.getSmbSession(NtlmPasswordAuthentication.DEFAULT).getSmbTree(LOGON_SHARE, null).treeConnect(null, null);
        }
        return new NtlmChallenge(trans.server.encryptionKey, dc);
    }

    public static NtlmChallenge getChallengeForDomain() throws SmbException, UnknownHostException {
        LogStream logStream;
        int i;
        if (DOMAIN == null) {
            throw new SmbException("A domain was not specified");
        }
        synchronized (DOMAIN) {
            NtlmChallenge interrogate;
            long now = System.currentTimeMillis();
            int retry = 1;
            loop0:
            while (true) {
                if (dc_list_expiration < now) {
                    NbtAddress[] list = NbtAddress.getAllByName(DOMAIN, 28, null, null);
                    dc_list_expiration = (((long) CACHE_POLICY) * 1000) + now;
                    if (list == null || list.length <= 0) {
                        dc_list_expiration = 900000 + now;
                        logStream = SmbTransport.log;
                        if (LogStream.level >= 2) {
                            SmbTransport.log.println("Failed to retrieve DC list from WINS");
                        }
                    } else {
                        dc_list = list;
                    }
                }
                int max = Math.min(dc_list.length, LOOKUP_RESP_LIMIT);
                int j = 0;
                while (j < max) {
                    int i2 = dc_list_counter;
                    dc_list_counter = i2 + 1;
                    i = i2 % max;
                    if (dc_list[i] != null) {
                        try {
                            interrogate = interrogate(dc_list[i]);
                            break loop0;
                        } catch (SmbException se) {
                            logStream = SmbTransport.log;
                            if (LogStream.level >= 2) {
                                SmbTransport.log.println(new StringBuffer().append("Failed validate DC: ").append(dc_list[i]).toString());
                                logStream = SmbTransport.log;
                                if (LogStream.level > 2) {
                                    se.printStackTrace(SmbTransport.log);
                                }
                            }
                            dc_list[i] = null;
                        }
                    } else {
                        j++;
                    }
                }
                dc_list_expiration = 0;
                int retry2 = retry - 1;
                if (retry <= 0) {
                    dc_list_expiration = 900000 + now;
                    throw new UnknownHostException(new StringBuffer().append("Failed to negotiate with a suitable domain controller for ").append(DOMAIN).toString());
                }
                retry = retry2;
            }
            return interrogate;
        }
    }

    public static byte[] getChallenge(UniAddress dc) throws SmbException, UnknownHostException {
        return getChallenge(dc, 0);
    }

    public static byte[] getChallenge(UniAddress dc, int port) throws SmbException, UnknownHostException {
        SmbTransport trans = SmbTransport.getSmbTransport(dc, port);
        trans.connect();
        return trans.server.encryptionKey;
    }

    public static void logon(UniAddress dc, NtlmPasswordAuthentication auth) throws SmbException {
        logon(dc, 0, auth);
    }

    public static void logon(UniAddress dc, int port, NtlmPasswordAuthentication auth) throws SmbException {
        SmbTree tree = SmbTransport.getSmbTransport(dc, port).getSmbSession(auth).getSmbTree(LOGON_SHARE, null);
        if (LOGON_SHARE == null) {
            tree.treeConnect(null, null);
        } else {
            tree.send(new Trans2FindFirst2("\\", "*", 16), new Trans2FindFirst2Response());
        }
    }

    SmbSession(UniAddress address, int port, InetAddress localAddr, int localPort, NtlmPasswordAuthentication auth) {
        this.address = address;
        this.port = port;
        this.localAddr = localAddr;
        this.localPort = localPort;
        this.auth = auth;
        this.trees = new Vector();
    }

    synchronized SmbTree getSmbTree(String share, String service) {
        Object t;
        SmbTree t2;
        if (share == null) {
            share = "IPC$";
        }
        Enumeration e = this.trees.elements();
        while (e.hasMoreElements()) {
            t2 = (SmbTree) e.nextElement();
            if (t2.matches(share, service)) {
                t = t2;
                break;
            }
        }
        t2 = new SmbTree(this, share, service);
        this.trees.addElement(t2);
        SmbTree t3 = t2;
        return t;
    }

    boolean matches(NtlmPasswordAuthentication auth) {
        return this.auth == auth || this.auth.equals(auth);
    }

    synchronized SmbTransport transport() {
        if (this.transport == null) {
            this.transport = SmbTransport.getSmbTransport(this.address, this.port, this.localAddr, this.localPort);
        }
        return this.transport;
    }

    void send(ServerMessageBlock request, ServerMessageBlock response) throws SmbException {
        if (response != null) {
            response.received = false;
        }
        synchronized (this.transport.setupDiscoLock) {
            this.expiration = System.currentTimeMillis() + ((long) SmbConstants.SO_TIMEOUT);
            sessionSetup(request, response);
            if (response == null || !response.received) {
                request.uid = this.uid;
                request.auth = this.auth;
                try {
                    this.transport.send(request, response);
                    return;
                } catch (SmbException se) {
                    if (request instanceof SmbComTreeConnectAndX) {
                        logoff(true);
                    }
                    request.digest = null;
                    throw se;
                }
            }
        }
    }

    void sessionSetup(ServerMessageBlock andx, ServerMessageBlock andxResponse) throws SmbException {
        SmbException ex = null;
        synchronized (transport()) {
            if (this.sessionSetup) {
                return;
            }
            this.transport.connect();
            SmbTransport smbTransport = this.transport;
            LogStream logStream = SmbTransport.log;
            if (LogStream.level >= 4) {
                smbTransport = this.transport;
                SmbTransport.log.println(new StringBuffer().append("sessionSetup: accountName=").append(this.auth.username).append(",primaryDomain=").append(this.auth.domain).toString());
            }
            SmbComSessionSetupAndX request = new SmbComSessionSetupAndX(this, andx);
            SmbComSessionSetupAndXResponse response = new SmbComSessionSetupAndXResponse(andxResponse);
            if (this.transport.isSignatureSetupRequired(this.auth)) {
                if (!this.auth.hashesExternal || NtlmPasswordAuthentication.DEFAULT_PASSWORD == BuildConfig.VERSION_NAME) {
                    request.digest = new SigningDigest(this.transport, this.auth);
                } else {
                    this.transport.getSmbSession(NtlmPasswordAuthentication.DEFAULT).getSmbTree(LOGON_SHARE, null).treeConnect(null, null);
                }
            }
            request.auth = this.auth;
            try {
                this.transport.send(request, response);
            } catch (SmbAuthException sae) {
                throw sae;
            } catch (SmbException se) {
                ex = se;
            }
            if (!response.isLoggedInAsGuest || "GUEST".equalsIgnoreCase(this.auth.username)) {
                this.uid = response.uid;
                this.sessionSetup = true;
                if (request.digest != null) {
                    this.transport.digest = request.digest;
                }
                if (ex != null) {
                    throw ex;
                }
                return;
            }
            throw new SmbAuthException(NtStatus.NT_STATUS_LOGON_FAILURE);
        }
    }

    void logoff(boolean inError) {
        synchronized (transport()) {
            if (this.sessionSetup) {
                Enumeration e = this.trees.elements();
                while (e.hasMoreElements()) {
                    ((SmbTree) e.nextElement()).treeDisconnect(inError);
                }
                if (!inError) {
                    if (this.transport.server.security != 0) {
                        SmbComLogoffAndX request = new SmbComLogoffAndX(null);
                        request.uid = this.uid;
                        try {
                            this.transport.send(request, null);
                        } catch (SmbException e2) {
                        }
                    }
                }
                this.sessionSetup = false;
                return;
            }
        }
    }

    public String toString() {
        return new StringBuffer().append("SmbSession[accountName=").append(this.auth.username).append(",primaryDomain=").append(this.auth.domain).append(",uid=").append(this.uid).append(",sessionSetup=").append(this.sessionSetup).append("]").toString();
    }
}
