package jcifs.smb;

import jcifs.util.LogStream;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;

class SmbTree {
    private static int tree_conn_counter;
    boolean inDfs;
    boolean inDomainDfs;
    String service = "?????";
    String service0;
    SmbSession session;
    String share;
    private int tid;
    boolean treeConnected;
    int tree_num;

    SmbTree(SmbSession session, String share, String service) {
        this.session = session;
        this.share = share.toUpperCase();
        if (!(service == null || service.startsWith("??"))) {
            this.service = service;
        }
        this.service0 = this.service;
    }

    boolean matches(String share, String service) {
        return this.share.equalsIgnoreCase(share) && (service == null || service.startsWith("??") || this.service.equalsIgnoreCase(service));
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof SmbTree)) {
            return false;
        }
        SmbTree tree = (SmbTree) obj;
        return matches(tree.share, tree.service);
    }

    void send(ServerMessageBlock request, ServerMessageBlock response) throws SmbException {
        if (response != null) {
            response.received = false;
        }
        treeConnect(request, response);
        if (request == null) {
            return;
        }
        if (response == null || !response.received) {
            if (!this.service.equals("A:")) {
                switch (request.command) {
                    case (byte) -94:
                    case Type.MF /*4*/:
                    case Service.MPM /*45*/:
                    case Service.MPM_SND /*46*/:
                    case Service.NI_FTP /*47*/:
                    case Service.AUTH /*113*/:
                        break;
                    case Service.TIME /*37*/:
                    case Type.NSEC3 /*50*/:
                        switch (((SmbComTransaction) request).subCommand & Type.ANY) {
                            case Tokenizer.EOF /*0*/:
                            case Protocol.CHAOS /*16*/:
                            case Type.NAPTR /*35*/:
                            case Type.A6 /*38*/:
                            case 83:
                            case 84:
                            case Service.X400_SND /*104*/:
                            case 215:
                                break;
                            default:
                                throw new SmbException(new StringBuffer().append("Invalid operation for ").append(this.service).append(" service").toString());
                        }
                    default:
                        throw new SmbException(new StringBuffer().append("Invalid operation for ").append(this.service).append(" service").append(request).toString());
                }
            }
            request.tid = this.tid;
            if (this.inDfs && !this.service.equals("IPC") && request.path != null && request.path.length() > 0) {
                request.flags2 = Flags.EXTEND;
                request.path = new StringBuffer().append('\\').append(this.session.transport().tconHostName).append('\\').append(this.share).append(request.path).toString();
            }
            try {
                this.session.send(request, response);
            } catch (SmbException se) {
                if (se.getNtStatus() == NtStatus.NT_STATUS_NETWORK_NAME_DELETED) {
                    treeDisconnect(true);
                }
                throw se;
            }
        }
    }

    void treeConnect(ServerMessageBlock andx, ServerMessageBlock andxResponse) throws SmbException {
        SmbTransport transport = this.session.transport();
        synchronized (transport.setupDiscoLock) {
            synchronized (transport) {
                if (this.treeConnected) {
                    return;
                }
                this.session.transport.connect();
                String unc = new StringBuffer().append("\\\\").append(this.session.transport.tconHostName).append('\\').append(this.share).toString();
                this.service = this.service0;
                SmbTransport smbTransport = this.session.transport;
                LogStream logStream = SmbTransport.log;
                if (LogStream.level >= 4) {
                    smbTransport = this.session.transport;
                    SmbTransport.log.println(new StringBuffer().append("treeConnect: unc=").append(unc).append(",service=").append(this.service).toString());
                }
                SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(andxResponse);
                this.session.send(new SmbComTreeConnectAndX(this.session, unc, this.service, andx), response);
                this.tid = response.tid;
                this.service = response.service;
                this.inDfs = response.shareIsInDfs;
                this.treeConnected = true;
                int i = tree_conn_counter;
                tree_conn_counter = i + 1;
                this.tree_num = i;
            }
        }
    }

    void treeDisconnect(boolean inError) {
        synchronized (this.session.transport) {
            if (!(!this.treeConnected || inError || this.tid == 0)) {
                try {
                    send(new SmbComTreeDisconnect(), null);
                } catch (SmbException se) {
                    r1 = this.session.transport;
                    LogStream logStream = SmbTransport.log;
                    if (LogStream.level > 1) {
                        SmbTransport smbTransport;
                        smbTransport = this.session.transport;
                        se.printStackTrace(SmbTransport.log);
                    }
                }
            }
            this.treeConnected = false;
            this.inDfs = false;
            this.inDomainDfs = false;
        }
    }

    public String toString() {
        return new StringBuffer().append("SmbTree[share=").append(this.share).append(",service=").append(this.service).append(",tid=").append(this.tid).append(",inDfs=").append(this.inDfs).append(",inDomainDfs=").append(this.inDomainDfs).append(",treeConnected=").append(this.treeConnected).append("]").toString();
    }
}
