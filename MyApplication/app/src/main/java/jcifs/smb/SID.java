package jcifs.smb;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.dcerpc.UnicodeString;
import jcifs.dcerpc.msrpc.LsaPolicyHandle;
import jcifs.dcerpc.msrpc.MsrpcEnumerateAliasesInDomain;
import jcifs.dcerpc.msrpc.MsrpcGetMembersInAlias;
import jcifs.dcerpc.msrpc.MsrpcLookupSids;
import jcifs.dcerpc.msrpc.MsrpcQueryInformationPolicy;
import jcifs.dcerpc.msrpc.SamrAliasHandle;
import jcifs.dcerpc.msrpc.SamrDomainHandle;
import jcifs.dcerpc.msrpc.SamrPolicyHandle;
import jcifs.dcerpc.msrpc.lsarpc.LsarDomainInfo;
import jcifs.dcerpc.msrpc.lsarpc.LsarSidArray;
import jcifs.dcerpc.msrpc.samr.SamrSamArray;
import jcifs.dcerpc.msrpc.samr.SamrSamEntry;
import jcifs.dcerpc.rpc.sid_t;
import jcifs.dcerpc.rpc.unicode_string;
import jcifs.util.Hexdump;
import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Type;

public class SID extends sid_t {
    public static SID CREATOR_OWNER = null;
    public static SID EVERYONE = null;
    public static final int SID_FLAG_RESOLVE_SIDS = 1;
    public static final int SID_TYPE_ALIAS = 4;
    public static final int SID_TYPE_DELETED = 6;
    public static final int SID_TYPE_DOMAIN = 3;
    public static final int SID_TYPE_DOM_GRP = 2;
    public static final int SID_TYPE_INVALID = 7;
    static final String[] SID_TYPE_NAMES = new String[]{"0", "User", "Domain group", "Domain", "Local group", "Builtin group", "Deleted", "Invalid", "Unknown"};
    public static final int SID_TYPE_UNKNOWN = 8;
    public static final int SID_TYPE_USER = 1;
    public static final int SID_TYPE_USE_NONE = 0;
    public static final int SID_TYPE_WKN_GRP = 5;
    public static SID SYSTEM;
    static Map sid_cache = Collections.synchronizedMap(new HashMap());
    String acctName = null;
    String domainName = null;
    NtlmPasswordAuthentication origin_auth = null;
    String origin_server = null;
    int type;

    static {
        EVERYONE = null;
        CREATOR_OWNER = null;
        SYSTEM = null;
        try {
            EVERYONE = new SID("S-1-1-0");
            CREATOR_OWNER = new SID("S-1-3-0");
            SYSTEM = new SID("S-1-5-18");
        } catch (SmbException e) {
        }
    }

    static void resolveSids(DcerpcHandle handle, LsaPolicyHandle policyHandle, SID[] sids) throws IOException {
        MsrpcLookupSids rpc = new MsrpcLookupSids(policyHandle, sids);
        handle.sendrecv(rpc);
        switch (rpc.retval) {
            case NtStatus.NT_STATUS_NONE_MAPPED /*-1073741709*/:
            case SID_TYPE_USE_NONE /*0*/:
            case 263:
                for (int si = SID_TYPE_USE_NONE; si < sids.length; si += SID_TYPE_USER) {
                    sids[si].type = rpc.names.names[si].sid_type;
                    sids[si].domainName = null;
                    switch (sids[si].type) {
                        case SID_TYPE_USER /*1*/:
                        case SID_TYPE_DOM_GRP /*2*/:
                        case SID_TYPE_DOMAIN /*3*/:
                        case SID_TYPE_ALIAS /*4*/:
                        case SID_TYPE_WKN_GRP /*5*/:
                            unicode_string ustr = rpc.domains.domains[rpc.names.names[si].sid_index].name;
                            sids[si].domainName = new UnicodeString(ustr, false).toString();
                            break;
                        default:
                            break;
                    }
                    sids[si].acctName = new UnicodeString(rpc.names.names[si].name, false).toString();
                    sids[si].origin_server = null;
                    sids[si].origin_auth = null;
                }
                return;
            default:
                throw new SmbException(rpc.retval, false);
        }
    }

    static void resolveSids0(String authorityServerName, NtlmPasswordAuthentication auth, SID[] sids) throws IOException {
        Throwable th;
        DcerpcHandle handle = null;
        LsaPolicyHandle policyHandle = null;
        try {
            handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(authorityServerName).append("[\\PIPE\\lsarpc]").toString(), auth);
            String server = authorityServerName;
            int dot = server.indexOf(46);
            if (dot > 0 && !Character.isDigit(server.charAt(SID_TYPE_USE_NONE))) {
                server = server.substring(SID_TYPE_USE_NONE, dot);
            }
            LsaPolicyHandle policyHandle2 = new LsaPolicyHandle(handle, new StringBuffer().append("\\\\").append(server).toString(), Flags.FLAG4);
            try {
                resolveSids(handle, policyHandle2, sids);
                if (handle != null) {
                    if (policyHandle2 != null) {
                        policyHandle2.close();
                    }
                    handle.close();
                }
            } catch (Throwable th2) {
                th = th2;
                policyHandle = policyHandle2;
                if (handle != null) {
                    if (policyHandle != null) {
                        policyHandle.close();
                    }
                    handle.close();
                }
                throw th;
            }
        } catch (Throwable th3) {
            th = th3;
            if (handle != null) {
                if (policyHandle != null) {
                    policyHandle.close();
                }
                handle.close();
            }
            throw th;
        }
    }

    public static void resolveSids(String authorityServerName, NtlmPasswordAuthentication auth, SID[] sids, int offset, int length) throws IOException {
        int si;
        ArrayList list = new ArrayList(sids.length);
        for (si = SID_TYPE_USE_NONE; si < length; si += SID_TYPE_USER) {
            SID sid = (SID) sid_cache.get(sids[offset + si]);
            if (sid != null) {
                sids[offset + si].type = sid.type;
                sids[offset + si].domainName = sid.domainName;
                sids[offset + si].acctName = sid.acctName;
            } else {
                list.add(sids[offset + si]);
            }
        }
        if (list.size() > 0) {
            sids = (SID[]) list.toArray(new SID[SID_TYPE_USE_NONE]);
            resolveSids0(authorityServerName, auth, sids);
            for (si = SID_TYPE_USE_NONE; si < sids.length; si += SID_TYPE_USER) {
                sid_cache.put(sids[si], sids[si]);
            }
        }
    }

    public static void resolveSids(String authorityServerName, NtlmPasswordAuthentication auth, SID[] sids) throws IOException {
        int si;
        ArrayList list = new ArrayList(sids.length);
        for (si = SID_TYPE_USE_NONE; si < sids.length; si += SID_TYPE_USER) {
            SID sid = (SID) sid_cache.get(sids[si]);
            if (sid != null) {
                sids[si].type = sid.type;
                sids[si].domainName = sid.domainName;
                sids[si].acctName = sid.acctName;
            } else {
                list.add(sids[si]);
            }
        }
        if (list.size() > 0) {
            sids = (SID[]) list.toArray(new SID[SID_TYPE_USE_NONE]);
            resolveSids0(authorityServerName, auth, sids);
            for (si = SID_TYPE_USE_NONE; si < sids.length; si += SID_TYPE_USER) {
                sid_cache.put(sids[si], sids[si]);
            }
        }
    }

    public static SID getServerSid(String server, NtlmPasswordAuthentication auth) throws IOException {
        Throwable th;
        DcerpcHandle handle = null;
        LsaPolicyHandle policyHandle = null;
        LsarDomainInfo info = new LsarDomainInfo();
        try {
            handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(server).append("[\\PIPE\\lsarpc]").toString(), auth);
            LsaPolicyHandle policyHandle2 = new LsaPolicyHandle(handle, null, SID_TYPE_USER);
            try {
                MsrpcQueryInformationPolicy rpc = new MsrpcQueryInformationPolicy(policyHandle2, (short) 5, info);
                handle.sendrecv(rpc);
                if (rpc.retval != 0) {
                    throw new SmbException(rpc.retval, false);
                }
                SID sid = new SID(info.sid, SID_TYPE_DOMAIN, new UnicodeString(info.name, false).toString(), null, false);
                if (handle != null) {
                    if (policyHandle2 != null) {
                        policyHandle2.close();
                    }
                    handle.close();
                }
                return sid;
            } catch (Throwable th2) {
                th = th2;
                policyHandle = policyHandle2;
                if (handle != null) {
                    if (policyHandle != null) {
                        policyHandle.close();
                    }
                    handle.close();
                }
                throw th;
            }
        } catch (Throwable th3) {
            th = th3;
            if (handle != null) {
                if (policyHandle != null) {
                    policyHandle.close();
                }
                handle.close();
            }
            throw th;
        }
    }

    public SID(byte[] src, int si) {
        int si2 = si + SID_TYPE_USER;
        this.revision = src[si];
        si = si2 + SID_TYPE_USER;
        this.sub_authority_count = src[si2];
        this.identifier_authority = new byte[SID_TYPE_DELETED];
        System.arraycopy(src, si, this.identifier_authority, SID_TYPE_USE_NONE, SID_TYPE_DELETED);
        si += SID_TYPE_DELETED;
        if (this.sub_authority_count > (byte) 100) {
            throw new RuntimeException("Invalid SID sub_authority_count");
        }
        this.sub_authority = new int[this.sub_authority_count];
        for (byte i = (byte) 0; i < this.sub_authority_count; i += SID_TYPE_USER) {
            this.sub_authority[i] = ServerMessageBlock.readInt4(src, si);
            si += SID_TYPE_ALIAS;
        }
    }

    public SID(String textual) throws SmbException {
        StringTokenizer st = new StringTokenizer(textual, "-");
        if (st.countTokens() < SID_TYPE_DOMAIN || !st.nextToken().equals("S")) {
            throw new SmbException(new StringBuffer().append("Bad textual SID format: ").append(textual).toString());
        }
        long id;
        this.revision = Byte.parseByte(st.nextToken());
        String tmp = st.nextToken();
        if (tmp.startsWith("0x")) {
            id = Long.parseLong(tmp.substring(SID_TYPE_DOM_GRP), 16);
        } else {
            id = Long.parseLong(tmp);
        }
        this.identifier_authority = new byte[SID_TYPE_DELETED];
        int i = SID_TYPE_WKN_GRP;
        while (id > 0) {
            this.identifier_authority[i] = (byte) ((int) (id % 256));
            id >>= SID_TYPE_UNKNOWN;
            i--;
        }
        this.sub_authority_count = (byte) st.countTokens();
        if (this.sub_authority_count > (byte) 0) {
            this.sub_authority = new int[this.sub_authority_count];
            for (byte i2 = (byte) 0; i2 < this.sub_authority_count; i2 += SID_TYPE_USER) {
                this.sub_authority[i2] = (int) (Long.parseLong(st.nextToken()) & 4294967295L);
            }
        }
    }

    public SID(SID domsid, int rid) {
        this.revision = domsid.revision;
        this.identifier_authority = domsid.identifier_authority;
        this.sub_authority_count = (byte) (domsid.sub_authority_count + SID_TYPE_USER);
        this.sub_authority = new int[this.sub_authority_count];
        byte i = (byte) 0;
        while (i < domsid.sub_authority_count) {
            this.sub_authority[i] = domsid.sub_authority[i];
            i += SID_TYPE_USER;
        }
        this.sub_authority[i] = rid;
    }

    SID(sid_t sid, int type, String domainName, String acctName, boolean decrementAuthority) {
        this.revision = sid.revision;
        this.sub_authority_count = sid.sub_authority_count;
        this.identifier_authority = sid.identifier_authority;
        this.sub_authority = sid.sub_authority;
        this.type = type;
        this.domainName = domainName;
        this.acctName = acctName;
        if (decrementAuthority) {
            this.sub_authority_count = (byte) (this.sub_authority_count - 1);
            this.sub_authority = new int[this.sub_authority_count];
            for (byte i = (byte) 0; i < this.sub_authority_count; i += SID_TYPE_USER) {
                this.sub_authority[i] = sid.sub_authority[i];
            }
        }
    }

    public SID getDomainSid() {
        return new SID(this, SID_TYPE_DOMAIN, this.domainName, null, getType() != SID_TYPE_DOMAIN);
    }

    public int getRid() {
        if (getType() != SID_TYPE_DOMAIN) {
            return this.sub_authority[this.sub_authority_count - 1];
        }
        throw new IllegalArgumentException("This SID is a domain sid");
    }

    public int getType() {
        if (this.origin_server != null) {
            resolveWeak();
        }
        return this.type;
    }

    public String getTypeText() {
        if (this.origin_server != null) {
            resolveWeak();
        }
        return SID_TYPE_NAMES[this.type];
    }

    public String getDomainName() {
        if (this.origin_server != null) {
            resolveWeak();
        }
        if (this.type != SID_TYPE_UNKNOWN) {
            return this.domainName;
        }
        String full = toString();
        return full.substring(SID_TYPE_USE_NONE, (full.length() - getAccountName().length()) - 1);
    }

    public String getAccountName() {
        if (this.origin_server != null) {
            resolveWeak();
        }
        if (this.type == SID_TYPE_UNKNOWN) {
            return new StringBuffer().append(BuildConfig.VERSION_NAME).append(this.sub_authority[this.sub_authority_count - 1]).toString();
        }
        if (this.type == SID_TYPE_DOMAIN) {
            return BuildConfig.VERSION_NAME;
        }
        return this.acctName;
    }

    public int hashCode() {
        int hcode = this.identifier_authority[SID_TYPE_WKN_GRP];
        for (byte i = (byte) 0; i < this.sub_authority_count; i += SID_TYPE_USER) {
            hcode += 65599 * this.sub_authority[i];
        }
        return hcode;
    }

    public boolean equals(Object obj) {
        boolean z = true;
        if (!(obj instanceof SID)) {
            return false;
        }
        SID sid = (SID) obj;
        if (sid == this) {
            return true;
        }
        if (sid.sub_authority_count != this.sub_authority_count) {
            return false;
        }
        int i = this.sub_authority_count;
        while (true) {
            int i2 = i - 1;
            if (i <= 0) {
                break;
            } else if (sid.sub_authority[i2] != this.sub_authority[i2]) {
                return false;
            } else {
                i = i2;
            }
        }
        for (i2 = SID_TYPE_USE_NONE; i2 < SID_TYPE_DELETED; i2 += SID_TYPE_USER) {
            if (sid.identifier_authority[i2] != this.identifier_authority[i2]) {
                return false;
            }
        }
        if (sid.revision != this.revision) {
            z = false;
        }
        return z;
    }

    public String toString() {
        String ret = new StringBuffer().append("S-").append(this.revision & Type.ANY).append("-").toString();
        if (this.identifier_authority[SID_TYPE_USE_NONE] == (byte) 0 && this.identifier_authority[SID_TYPE_USER] == (byte) 0) {
            long shift = 0;
            long id = 0;
            for (int i = SID_TYPE_WKN_GRP; i > SID_TYPE_USER; i--) {
                id += (((long) this.identifier_authority[i]) & 255) << ((int) shift);
                shift += 8;
            }
            ret = new StringBuffer().append(ret).append(id).toString();
        } else {
            ret = new StringBuffer().append(new StringBuffer().append(ret).append("0x").toString()).append(Hexdump.toHexString(this.identifier_authority, SID_TYPE_USE_NONE, SID_TYPE_DELETED)).toString();
        }
        for (byte i2 = (byte) 0; i2 < this.sub_authority_count; i2 += SID_TYPE_USER) {
            ret = new StringBuffer().append(ret).append("-").append(((long) this.sub_authority[i2]) & 4294967295L).toString();
        }
        return ret;
    }

    public String toDisplayString() {
        if (this.origin_server != null) {
            resolveWeak();
        }
        if (this.domainName == null) {
            return toString();
        }
        if (this.type == SID_TYPE_DOMAIN) {
            return this.domainName;
        }
        if (this.type != SID_TYPE_WKN_GRP && !this.domainName.equals("BUILTIN")) {
            return new StringBuffer().append(this.domainName).append("\\").append(this.acctName).toString();
        }
        if (this.type == SID_TYPE_UNKNOWN) {
            return toString();
        }
        return this.acctName;
    }

    public void resolve(String authorityServerName, NtlmPasswordAuthentication auth) throws IOException {
        SID[] sids = new SID[SID_TYPE_USER];
        sids[SID_TYPE_USE_NONE] = this;
        resolveSids(authorityServerName, auth, sids);
    }

    void resolveWeak() {
        if (this.origin_server != null) {
            try {
                resolve(this.origin_server, this.origin_auth);
            } catch (IOException e) {
            } finally {
                this.origin_server = null;
                this.origin_auth = null;
            }
        }
    }

    static SID[] getGroupMemberSids0(DcerpcHandle handle, SamrDomainHandle domainHandle, SID domsid, int rid, int flags) throws IOException {
        Throwable th;
        SamrAliasHandle aliasHandle = null;
        LsarSidArray sidarray = new LsarSidArray();
        try {
            SamrAliasHandle aliasHandle2 = new SamrAliasHandle(handle, domainHandle, 131084, rid);
            try {
                MsrpcGetMembersInAlias rpc = new MsrpcGetMembersInAlias(aliasHandle2, sidarray);
                try {
                    handle.sendrecv(rpc);
                    if (rpc.retval != 0) {
                        throw new SmbException(rpc.retval, false);
                    }
                    SID[] sids = new SID[rpc.sids.num_sids];
                    String origin_server = handle.getServer();
                    NtlmPasswordAuthentication origin_auth = (NtlmPasswordAuthentication) handle.getPrincipal();
                    for (int i = SID_TYPE_USE_NONE; i < sids.length; i += SID_TYPE_USER) {
                        sids[i] = new SID(rpc.sids.sids[i].sid, SID_TYPE_USE_NONE, null, null, false);
                        sids[i].origin_server = origin_server;
                        sids[i].origin_auth = origin_auth;
                    }
                    if (sids.length > 0 && (flags & SID_TYPE_USER) != 0) {
                        resolveSids(origin_server, origin_auth, sids);
                    }
                    if (aliasHandle2 != null) {
                        aliasHandle2.close();
                    }
                    return sids;
                } catch (Throwable th2) {
                    th = th2;
                    MsrpcGetMembersInAlias msrpcGetMembersInAlias = rpc;
                    aliasHandle = aliasHandle2;
                    if (aliasHandle != null) {
                        aliasHandle.close();
                    }
                    throw th;
                }
            } catch (Throwable th3) {
                th = th3;
                aliasHandle = aliasHandle2;
                if (aliasHandle != null) {
                    aliasHandle.close();
                }
                throw th;
            }
        } catch (Throwable th4) {
            th = th4;
            if (aliasHandle != null) {
                aliasHandle.close();
            }
            throw th;
        }
    }

    public SID[] getGroupMemberSids(String authorityServerName, NtlmPasswordAuthentication auth, int flags) throws IOException {
        SamrDomainHandle domainHandle;
        Throwable th;
        if (this.type != SID_TYPE_DOM_GRP && this.type != SID_TYPE_ALIAS) {
            return new SID[SID_TYPE_USE_NONE];
        }
        DcerpcHandle handle = null;
        SamrPolicyHandle policyHandle = null;
        SamrDomainHandle domainHandle2 = null;
        SID domsid = getDomainSid();
        try {
            handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(authorityServerName).append("[\\PIPE\\samr]").toString(), auth);
            SamrPolicyHandle policyHandle2 = new SamrPolicyHandle(handle, authorityServerName, 48);
            try {
                domainHandle = new SamrDomainHandle(handle, policyHandle2, KEYRecord.OWNER_HOST, domsid);
            } catch (Throwable th2) {
                th = th2;
                policyHandle = policyHandle2;
                if (handle != null) {
                    if (policyHandle != null) {
                        if (domainHandle2 != null) {
                            domainHandle2.close();
                        }
                        policyHandle.close();
                    }
                    handle.close();
                }
                throw th;
            }
            try {
                SID[] groupMemberSids0 = getGroupMemberSids0(handle, domainHandle, domsid, getRid(), flags);
                if (handle == null) {
                    return groupMemberSids0;
                }
                if (policyHandle2 != null) {
                    if (domainHandle != null) {
                        domainHandle.close();
                    }
                    policyHandle2.close();
                }
                handle.close();
                return groupMemberSids0;
            } catch (Throwable th3) {
                th = th3;
                domainHandle2 = domainHandle;
                policyHandle = policyHandle2;
                if (handle != null) {
                    if (policyHandle != null) {
                        if (domainHandle2 != null) {
                            domainHandle2.close();
                        }
                        policyHandle.close();
                    }
                    handle.close();
                }
                throw th;
            }
        } catch (Throwable th4) {
            th = th4;
            if (handle != null) {
                if (policyHandle != null) {
                    if (domainHandle2 != null) {
                        domainHandle2.close();
                    }
                    policyHandle.close();
                }
                handle.close();
            }
            throw th;
        }
    }

    static Map getLocalGroupsMap(String authorityServerName, NtlmPasswordAuthentication auth, int flags) throws IOException {
        Throwable th;
        SID domsid = getServerSid(authorityServerName, auth);
        DcerpcHandle handle = null;
        SamrPolicyHandle policyHandle = null;
        SamrDomainHandle domainHandle = null;
        SamrSamArray sam = new SamrSamArray();
        try {
            SamrDomainHandle domainHandle2;
            handle = DcerpcHandle.getHandle(new StringBuffer().append("ncacn_np:").append(authorityServerName).append("[\\PIPE\\samr]").toString(), auth);
            SamrPolicyHandle policyHandle2 = new SamrPolicyHandle(handle, authorityServerName, 33554432);
            try {
                domainHandle2 = new SamrDomainHandle(handle, policyHandle2, 33554432, domsid);
            } catch (Throwable th2) {
                th = th2;
                policyHandle = policyHandle2;
                if (handle != null) {
                    if (policyHandle != null) {
                        if (domainHandle != null) {
                            domainHandle.close();
                        }
                        policyHandle.close();
                    }
                    handle.close();
                }
                throw th;
            }
            try {
                MsrpcEnumerateAliasesInDomain rpc = new MsrpcEnumerateAliasesInDomain(domainHandle2, Message.MAXLENGTH, sam);
                handle.sendrecv(rpc);
                if (rpc.retval != 0) {
                    throw new SmbException(rpc.retval, false);
                }
                Map map = new HashMap();
                for (int ei = SID_TYPE_USE_NONE; ei < rpc.sam.count; ei += SID_TYPE_USER) {
                    SamrSamEntry entry = rpc.sam.entries[ei];
                    SID[] mems = getGroupMemberSids0(handle, domainHandle2, domsid, entry.idx, flags);
                    SID groupSid = new SID(domsid, entry.idx);
                    groupSid.type = SID_TYPE_ALIAS;
                    groupSid.domainName = domsid.getDomainName();
                    groupSid.acctName = new UnicodeString(entry.name, false).toString();
                    for (int mi = SID_TYPE_USE_NONE; mi < mems.length; mi += SID_TYPE_USER) {
                        ArrayList groups = (ArrayList) map.get(mems[mi]);
                        if (groups == null) {
                            groups = new ArrayList();
                            map.put(mems[mi], groups);
                        }
                        if (!groups.contains(groupSid)) {
                            groups.add(groupSid);
                        }
                    }
                }
                if (handle != null) {
                    if (policyHandle2 != null) {
                        if (domainHandle2 != null) {
                            domainHandle2.close();
                        }
                        policyHandle2.close();
                    }
                    handle.close();
                }
                return map;
            } catch (Throwable th3) {
                th = th3;
                domainHandle = domainHandle2;
                policyHandle = policyHandle2;
                if (handle != null) {
                    if (policyHandle != null) {
                        if (domainHandle != null) {
                            domainHandle.close();
                        }
                        policyHandle.close();
                    }
                    handle.close();
                }
                throw th;
            }
        } catch (Throwable th4) {
            th = th4;
            if (handle != null) {
                if (policyHandle != null) {
                    if (domainHandle != null) {
                        domainHandle.close();
                    }
                    policyHandle.close();
                }
                handle.close();
            }
            throw th;
        }
    }
}
