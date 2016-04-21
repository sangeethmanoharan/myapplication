package org.xbill.DNS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class ARecord extends Record {
    private static final long serialVersionUID = -2172609200849142323L;
    private int addr;

    ARecord() {
    }

    Record getObject() {
        return new ARecord();
    }

    private static final int fromArray(byte[] array) {
        return ((((array[0] & Type.ANY) << 24) | ((array[1] & Type.ANY) << 16)) | ((array[2] & Type.ANY) << 8)) | (array[3] & Type.ANY);
    }

    private static final byte[] toArray(int addr) {
        return new byte[]{(byte) ((addr >>> 24) & Type.ANY), (byte) ((addr >>> 16) & Type.ANY), (byte) ((addr >>> 8) & Type.ANY), (byte) (addr & Type.ANY)};
    }

    public ARecord(Name name, int dclass, long ttl, InetAddress address) {
        super(name, 1, dclass, ttl);
        if (Address.familyOf(address) != 1) {
            throw new IllegalArgumentException("invalid IPv4 address");
        }
        this.addr = fromArray(address.getAddress());
    }

    void rrFromWire(DNSInput in) throws IOException {
        this.addr = fromArray(in.readByteArray(4));
    }

    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        this.addr = fromArray(st.getAddress(1).getAddress());
    }

    String rrToString() {
        return Address.toDottedQuad(toArray(this.addr));
    }

    public InetAddress getAddress() {
        try {
            if (this.name == null) {
                return InetAddress.getByAddress(toArray(this.addr));
            }
            return InetAddress.getByAddress(this.name.toString(), toArray(this.addr));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
        out.writeU32(((long) this.addr) & 4294967295L);
    }
}
