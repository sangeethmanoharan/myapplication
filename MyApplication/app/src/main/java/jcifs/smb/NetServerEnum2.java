package jcifs.smb;

import java.io.UnsupportedEncodingException;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.Type;

class NetServerEnum2 extends SmbComTransaction {
    static final String[] DESCR = new String[]{"WrLehDz\u0000B16BBDz\u0000", "WrLehDzz\u0000B16BBDz\u0000"};
    static final int SV_TYPE_ALL = -1;
    static final int SV_TYPE_DOMAIN_ENUM = Integer.MIN_VALUE;
    String domain;
    String lastName = null;
    int serverTypes;

    NetServerEnum2(String domain, int serverTypes) {
        this.domain = domain;
        this.serverTypes = serverTypes;
        this.command = (byte) 37;
        this.subCommand = (byte) 104;
        this.name = "\\PIPE\\LANMAN";
        this.maxParameterCount = 8;
        this.maxDataCount = KEYRecord.FLAG_NOCONF;
        this.maxSetupCount = (byte) 0;
        this.setupCount = 0;
        this.timeout = 5000;
    }

    void reset(int key, String lastName) {
        super.reset();
        this.lastName = lastName;
    }

    int writeSetupWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeParametersWireFormat(byte[] dst, int dstIndex) {
        int which;
        int start = dstIndex;
        if (this.subCommand == (byte) 104) {
            which = 0;
        } else {
            which = 1;
        }
        try {
            byte[] descr = DESCR[which].getBytes("ASCII");
            ServerMessageBlock.writeInt2((long) (this.subCommand & Type.ANY), dst, dstIndex);
            dstIndex += 2;
            System.arraycopy(descr, 0, dst, dstIndex, descr.length);
            dstIndex += descr.length;
            ServerMessageBlock.writeInt2(1, dst, dstIndex);
            dstIndex += 2;
            ServerMessageBlock.writeInt2((long) this.maxDataCount, dst, dstIndex);
            dstIndex += 2;
            ServerMessageBlock.writeInt4((long) this.serverTypes, dst, dstIndex);
            dstIndex += 4;
            dstIndex += writeString(this.domain.toUpperCase(), dst, dstIndex, false);
            if (which == 1) {
                dstIndex += writeString(this.lastName.toUpperCase(), dst, dstIndex, false);
            }
            return dstIndex - start;
        } catch (UnsupportedEncodingException e) {
            return 0;
        }
    }

    int writeDataWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    public String toString() {
        return new String(new StringBuffer().append("NetServerEnum2[").append(super.toString()).append(",name=").append(this.name).append(",serverTypes=").append(this.serverTypes == SV_TYPE_ALL ? "SV_TYPE_ALL" : "SV_TYPE_DOMAIN_ENUM").append("]").toString());
    }
}
