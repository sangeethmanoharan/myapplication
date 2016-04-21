package jcifs.netbios;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import jcifs.Config;
import jcifs.util.Hexdump;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;

public final class NbtAddress {
    private static final HashMap ADDRESS_CACHE = new HashMap();
    static final String ANY_HOSTS_NAME = "*\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000";
    public static final int B_NODE = 0;
    private static final int CACHE_POLICY = Config.getInt("jcifs.netbios.cachePolicy", DEFAULT_CACHE_POLICY);
    private static final NameServiceClient CLIENT = new NameServiceClient();
    private static final int DEFAULT_CACHE_POLICY = 30;
    private static final int FOREVER = -1;
    public static final int H_NODE = 3;
    private static final HashMap LOOKUP_TABLE = new HashMap();
    public static final String MASTER_BROWSER_NAME = "\u0001\u0002__MSBROWSE__\u0002";
    public static final int M_NODE = 2;
    static final InetAddress[] NBNS = Config.getInetAddressArray("jcifs.netbios.wins", ",", new InetAddress[CACHE_POLICY]);
    public static final int P_NODE = 1;
    public static final String SMBSERVER_NAME = "*SMBSERVER     ";
    static final NbtAddress UNKNOWN_ADDRESS = new NbtAddress(UNKNOWN_NAME, CACHE_POLICY, false, CACHE_POLICY);
    static final byte[] UNKNOWN_MAC_ADDRESS = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0};
    static final Name UNKNOWN_NAME = new Name("0.0.0.0", CACHE_POLICY, null);
    static NbtAddress localhost;
    private static int nbnsIndex = CACHE_POLICY;
    int address;
    String calledName;
    boolean groupName;
    Name hostName;
    boolean isActive;
    boolean isBeingDeleted;
    boolean isDataFromNodeStatus;
    boolean isInConflict;
    boolean isPermanent;
    byte[] macAddress;
    int nodeType;

    static final class CacheEntry {
        NbtAddress address;
        long expiration;
        Name hostName;

        CacheEntry(Name hostName, NbtAddress address, long expiration) {
            this.hostName = hostName;
            this.address = address;
            this.expiration = expiration;
        }
    }

    static {
        ADDRESS_CACHE.put(UNKNOWN_NAME, new CacheEntry(UNKNOWN_NAME, UNKNOWN_ADDRESS, -1));
        InetAddress localInetAddress = CLIENT.laddr;
        if (localInetAddress == null) {
            try {
                localInetAddress = InetAddress.getLocalHost();
            } catch (UnknownHostException e) {
                try {
                    localInetAddress = InetAddress.getByName("127.0.0.1");
                } catch (UnknownHostException e2) {
                }
            }
        }
        String localHostname = Config.getProperty("jcifs.netbios.hostname", null);
        if (localHostname == null || localHostname.length() == 0) {
            byte[] addr = localInetAddress.getAddress();
            localHostname = new StringBuffer().append("JCIFS").append(addr[M_NODE] & Type.ANY).append("_").append(addr[H_NODE] & Type.ANY).append("_").append(Hexdump.toHexString((int) (Math.random() * 255.0d), (int) M_NODE)).toString();
        }
        Name localName = new Name(localHostname, CACHE_POLICY, Config.getProperty("jcifs.netbios.scope", null));
        localhost = new NbtAddress(localName, localInetAddress.hashCode(), false, CACHE_POLICY, false, false, true, false, UNKNOWN_MAC_ADDRESS);
        cacheAddress(localName, localhost, -1);
    }

    static void cacheAddress(Name hostName, NbtAddress addr) {
        if (CACHE_POLICY != 0) {
            long expiration = -1;
            if (CACHE_POLICY != FOREVER) {
                expiration = System.currentTimeMillis() + ((long) (CACHE_POLICY * 1000));
            }
            cacheAddress(hostName, addr, expiration);
        }
    }

    static void cacheAddress(Name hostName, NbtAddress addr, long expiration) {
        if (CACHE_POLICY != 0) {
            synchronized (ADDRESS_CACHE) {
                CacheEntry entry = (CacheEntry) ADDRESS_CACHE.get(hostName);
                if (entry == null) {
                    ADDRESS_CACHE.put(hostName, new CacheEntry(hostName, addr, expiration));
                } else {
                    entry.address = addr;
                    entry.expiration = expiration;
                }
            }
        }
    }

    static void cacheAddressArray(NbtAddress[] addrs) {
        if (CACHE_POLICY != 0) {
            long expiration = -1;
            if (CACHE_POLICY != FOREVER) {
                expiration = System.currentTimeMillis() + ((long) (CACHE_POLICY * 1000));
            }
            synchronized (ADDRESS_CACHE) {
                for (int i = CACHE_POLICY; i < addrs.length; i += P_NODE) {
                    CacheEntry entry = (CacheEntry) ADDRESS_CACHE.get(addrs[i].hostName);
                    if (entry == null) {
                        ADDRESS_CACHE.put(addrs[i].hostName, new CacheEntry(addrs[i].hostName, addrs[i], expiration));
                    } else {
                        entry.address = addrs[i];
                        entry.expiration = expiration;
                    }
                }
            }
        }
    }

    static NbtAddress getCachedAddress(Name hostName) {
        NbtAddress nbtAddress = null;
        if (CACHE_POLICY != 0) {
            synchronized (ADDRESS_CACHE) {
                CacheEntry entry = (CacheEntry) ADDRESS_CACHE.get(hostName);
                if (entry != null && entry.expiration < System.currentTimeMillis() && entry.expiration >= 0) {
                    entry = null;
                }
                if (entry != null) {
                    nbtAddress = entry.address;
                }
            }
        }
        return nbtAddress;
    }

    static NbtAddress doNameQuery(Name name, InetAddress svr) throws UnknownHostException {
        if (name.hexCode == 29 && svr == null) {
            svr = CLIENT.baddr;
        }
        name.srcHashCode = svr != null ? svr.hashCode() : CACHE_POLICY;
        NbtAddress addr = getCachedAddress(name);
        if (addr == null) {
            addr = (NbtAddress) checkLookupTable(name);
            if (addr == null) {
                try {
                    addr = CLIENT.getByName(name, svr);
                } catch (UnknownHostException e) {
                    addr = UNKNOWN_ADDRESS;
                } finally {
                    cacheAddress(name, addr);
                    updateLookupTable(name);
                }
            }
        }
        if (addr != UNKNOWN_ADDRESS) {
            return addr;
        }
        throw new UnknownHostException(name.toString());
    }

    private static Object checkLookupTable(Name name) {
        Object obj;
        synchronized (LOOKUP_TABLE) {
            if (LOOKUP_TABLE.containsKey(name)) {
                while (LOOKUP_TABLE.containsKey(name)) {
                    try {
                        LOOKUP_TABLE.wait();
                    } catch (InterruptedException e) {
                    }
                }
                obj = getCachedAddress(name);
                if (obj == null) {
                    synchronized (LOOKUP_TABLE) {
                        LOOKUP_TABLE.put(name, name);
                    }
                }
            } else {
                LOOKUP_TABLE.put(name, name);
                obj = null;
            }
        }
        return obj;
    }

    private static void updateLookupTable(Name name) {
        synchronized (LOOKUP_TABLE) {
            LOOKUP_TABLE.remove(name);
            LOOKUP_TABLE.notifyAll();
        }
    }

    public static NbtAddress getLocalHost() throws UnknownHostException {
        return localhost;
    }

    public static Name getLocalName() {
        return localhost.hostName;
    }

    public static NbtAddress getByName(String host) throws UnknownHostException {
        return getByName(host, CACHE_POLICY, null);
    }

    public static NbtAddress getByName(String host, int type, String scope) throws UnknownHostException {
        return getByName(host, type, scope, null);
    }

    public static NbtAddress getByName(String host, int type, String scope, InetAddress svr) throws UnknownHostException {
        if (host == null || host.length() == 0) {
            return getLocalHost();
        }
        if (!Character.isDigit(host.charAt(CACHE_POLICY))) {
            return doNameQuery(new Name(host, type, scope), svr);
        }
        int IP = CACHE_POLICY;
        int hitDots = CACHE_POLICY;
        char[] data = host.toCharArray();
        int i = CACHE_POLICY;
        while (i < data.length) {
            char c = data[i];
            if (c < '0' || c > '9') {
                return doNameQuery(new Name(host, type, scope), svr);
            }
            int b = CACHE_POLICY;
            while (c != '.') {
                if (c < '0' || c > '9') {
                    return doNameQuery(new Name(host, type, scope), svr);
                }
                b = ((b * 10) + c) - 48;
                i += P_NODE;
                if (i >= data.length) {
                    break;
                }
                c = data[i];
            }
            if (b > Type.ANY) {
                return doNameQuery(new Name(host, type, scope), svr);
            }
            IP = (IP << 8) + b;
            hitDots += P_NODE;
            i += P_NODE;
        }
        if (hitDots != 4 || host.endsWith(".")) {
            return doNameQuery(new Name(host, type, scope), svr);
        }
        return new NbtAddress(UNKNOWN_NAME, IP, false, CACHE_POLICY);
    }

    public static NbtAddress[] getAllByName(String host, int type, String scope, InetAddress svr) throws UnknownHostException {
        return CLIENT.getAllByName(new Name(host, type, scope), svr);
    }

    public static NbtAddress[] getAllByAddress(String host) throws UnknownHostException {
        return getAllByAddress(getByName(host, CACHE_POLICY, null));
    }

    public static NbtAddress[] getAllByAddress(String host, int type, String scope) throws UnknownHostException {
        return getAllByAddress(getByName(host, type, scope));
    }

    public static NbtAddress[] getAllByAddress(NbtAddress addr) throws UnknownHostException {
        try {
            NbtAddress[] addrs = CLIENT.getNodeStatus(addr);
            cacheAddressArray(addrs);
            return addrs;
        } catch (UnknownHostException e) {
            StringBuffer append = new StringBuffer().append("no name with type 0x").append(Hexdump.toHexString(addr.hostName.hexCode, (int) M_NODE));
            String stringBuffer = (addr.hostName.scope == null || addr.hostName.scope.length() == 0) ? " with no scope" : new StringBuffer().append(" with scope ").append(addr.hostName.scope).toString();
            throw new UnknownHostException(append.append(stringBuffer).append(" for host ").append(addr.getHostAddress()).toString());
        }
    }

    public static InetAddress getWINSAddress() {
        return NBNS.length == 0 ? null : NBNS[nbnsIndex];
    }

    public static boolean isWINS(InetAddress svr) {
        int i = CACHE_POLICY;
        while (svr != null && i < NBNS.length) {
            if (svr.hashCode() == NBNS[i].hashCode()) {
                return true;
            }
            i += P_NODE;
        }
        return false;
    }

    static InetAddress switchWINS() {
        nbnsIndex = nbnsIndex + P_NODE < NBNS.length ? nbnsIndex + P_NODE : CACHE_POLICY;
        return NBNS.length == 0 ? null : NBNS[nbnsIndex];
    }

    NbtAddress(Name hostName, int address, boolean groupName, int nodeType) {
        this.hostName = hostName;
        this.address = address;
        this.groupName = groupName;
        this.nodeType = nodeType;
    }

    NbtAddress(Name hostName, int address, boolean groupName, int nodeType, boolean isBeingDeleted, boolean isInConflict, boolean isActive, boolean isPermanent, byte[] macAddress) {
        this.hostName = hostName;
        this.address = address;
        this.groupName = groupName;
        this.nodeType = nodeType;
        this.isBeingDeleted = isBeingDeleted;
        this.isInConflict = isInConflict;
        this.isActive = isActive;
        this.isPermanent = isPermanent;
        this.macAddress = macAddress;
        this.isDataFromNodeStatus = true;
    }

    public String firstCalledName() {
        this.calledName = this.hostName.name;
        if (!Character.isDigit(this.calledName.charAt(CACHE_POLICY))) {
            switch (this.hostName.hexCode) {
                case Service.NSW_FE /*27*/:
                case Protocol.IRTP /*28*/:
                case Service.MSG_ICP /*29*/:
                    this.calledName = SMBSERVER_NAME;
                    break;
                default:
                    break;
            }
        }
        int dots = CACHE_POLICY;
        int i = CACHE_POLICY;
        int len = this.calledName.length();
        char[] data = this.calledName.toCharArray();
        int i2 = i;
        while (i2 < len) {
            i = i2 + P_NODE;
            if (Character.isDigit(data[i2])) {
                if (i == len && dots == H_NODE) {
                    this.calledName = SMBSERVER_NAME;
                    break;
                } else if (i >= len || data[i] != '.') {
                    i2 = i;
                } else {
                    dots += P_NODE;
                    i2 = i + P_NODE;
                }
            } else {
                break;
            }
        }
        i = i2;
        return this.calledName;
    }

    public String nextCalledName() {
        if (this.calledName == this.hostName.name) {
            this.calledName = SMBSERVER_NAME;
        } else if (this.calledName == SMBSERVER_NAME) {
            try {
                NbtAddress[] addrs = CLIENT.getNodeStatus(this);
                if (this.hostName.hexCode == 29) {
                    for (int i = CACHE_POLICY; i < addrs.length; i += P_NODE) {
                        if (addrs[i].hostName.hexCode == 32) {
                            return addrs[i].hostName.name;
                        }
                    }
                    return null;
                } else if (this.isDataFromNodeStatus) {
                    this.calledName = null;
                    return this.hostName.name;
                }
            } catch (UnknownHostException e) {
                this.calledName = null;
            }
        } else {
            this.calledName = null;
        }
        return this.calledName;
    }

    void checkData() throws UnknownHostException {
        if (this.hostName == UNKNOWN_NAME) {
            getAllByAddress(this);
        }
    }

    void checkNodeStatusData() throws UnknownHostException {
        if (!this.isDataFromNodeStatus) {
            getAllByAddress(this);
        }
    }

    public boolean isGroupAddress() throws UnknownHostException {
        checkData();
        return this.groupName;
    }

    public int getNodeType() throws UnknownHostException {
        checkData();
        return this.nodeType;
    }

    public boolean isBeingDeleted() throws UnknownHostException {
        checkNodeStatusData();
        return this.isBeingDeleted;
    }

    public boolean isInConflict() throws UnknownHostException {
        checkNodeStatusData();
        return this.isInConflict;
    }

    public boolean isActive() throws UnknownHostException {
        checkNodeStatusData();
        return this.isActive;
    }

    public boolean isPermanent() throws UnknownHostException {
        checkNodeStatusData();
        return this.isPermanent;
    }

    public byte[] getMacAddress() throws UnknownHostException {
        checkNodeStatusData();
        return this.macAddress;
    }

    public String getHostName() {
        try {
            checkData();
            return this.hostName.name;
        } catch (UnknownHostException e) {
            return getHostAddress();
        }
    }

    public byte[] getAddress() {
        return new byte[]{(byte) ((this.address >>> 24) & Type.ANY), (byte) ((this.address >>> 16) & Type.ANY), (byte) ((this.address >>> 8) & Type.ANY), (byte) (this.address & Type.ANY)};
    }

    public InetAddress getInetAddress() throws UnknownHostException {
        return InetAddress.getByName(getHostAddress());
    }

    public String getHostAddress() {
        return new StringBuffer().append((this.address >>> 24) & Type.ANY).append(".").append((this.address >>> 16) & Type.ANY).append(".").append((this.address >>> 8) & Type.ANY).append(".").append((this.address >>> CACHE_POLICY) & Type.ANY).toString();
    }

    public int getNameType() {
        return this.hostName.hexCode;
    }

    public int hashCode() {
        return this.address;
    }

    public boolean equals(Object obj) {
        return obj != null && (obj instanceof NbtAddress) && ((NbtAddress) obj).address == this.address;
    }

    public String toString() {
        return new StringBuffer().append(this.hostName.toString()).append("/").append(getHostAddress()).toString();
    }
}
