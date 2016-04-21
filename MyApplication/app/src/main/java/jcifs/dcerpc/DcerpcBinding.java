package jcifs.dcerpc;

import java.util.HashMap;
import jcifs.dcerpc.msrpc.lsarpc;
import jcifs.dcerpc.msrpc.netdfs;
import jcifs.dcerpc.msrpc.samr;
import jcifs.dcerpc.msrpc.srvsvc;

class DcerpcBinding {
    private static HashMap INTERFACES = new HashMap();
    String endpoint = null;
    int major;
    int minor;
    HashMap options = null;
    String proto;
    String server;
    UUID uuid = null;

    static {
        INTERFACES.put("srvsvc", srvsvc.getSyntax());
        INTERFACES.put("lsarpc", lsarpc.getSyntax());
        INTERFACES.put("samr", samr.getSyntax());
        INTERFACES.put("netdfs", netdfs.getSyntax());
    }

    DcerpcBinding(String proto, String server) {
        this.proto = proto;
        this.server = server;
    }

    void setOption(String key, Object val) throws DcerpcException {
        if (key.equals("endpoint")) {
            this.endpoint = val.toString().toLowerCase();
            if (this.endpoint.startsWith("\\pipe\\")) {
                String iface = (String) INTERFACES.get(this.endpoint.substring(6));
                if (iface != null) {
                    int c = iface.indexOf(58);
                    int p = iface.indexOf(46, c + 1);
                    this.uuid = new UUID(iface.substring(0, c));
                    this.major = Integer.parseInt(iface.substring(c + 1, p));
                    this.minor = Integer.parseInt(iface.substring(p + 1));
                    return;
                }
            }
            throw new DcerpcException(new StringBuffer().append("Bad endpoint: ").append(this.endpoint).toString());
        }
        if (this.options == null) {
            this.options = new HashMap();
        }
        this.options.put(key, val);
    }

    Object getOption(String key) {
        if (key.equals("endpoint")) {
            return this.endpoint;
        }
        return this.options.get(key);
    }

    public String toString() {
        String ret = new StringBuffer().append(this.proto).append(":").append(this.server).append("[").append(this.endpoint).toString();
        if (this.options != null) {
            for (Object key : this.options.keySet()) {
                ret = new StringBuffer().append(ret).append(",").append(key).append("=").append(this.options.get(key)).toString();
            }
        }
        return new StringBuffer().append(ret).append("]").toString();
    }
}
