package jcifs.smb;

import jcifs.util.Hexdump;
import org.xbill.DNS.KEYRecord;

class NtTransQuerySecurityDesc extends SmbComNtTransaction {
    int fid;
    int securityInformation;

    NtTransQuerySecurityDesc(int fid, int securityInformation) {
        this.fid = fid;
        this.securityInformation = securityInformation;
        this.command = (byte) -96;
        this.function = 6;
        this.setupCount = 0;
        this.totalDataCount = 0;
        this.maxParameterCount = 4;
        this.maxDataCount = KEYRecord.FLAG_NOAUTH;
        this.maxSetupCount = (byte) 0;
    }

    int writeSetupWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeParametersWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;
        ServerMessageBlock.writeInt2((long) this.fid, dst, dstIndex);
        dstIndex += 2;
        int dstIndex2 = dstIndex + 1;
        dst[dstIndex] = (byte) 0;
        dstIndex = dstIndex2 + 1;
        dst[dstIndex2] = (byte) 0;
        ServerMessageBlock.writeInt4((long) this.securityInformation, dst, dstIndex);
        return (dstIndex + 4) - start;
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
        return new String(new StringBuffer().append("NtTransQuerySecurityDesc[").append(super.toString()).append(",fid=0x").append(Hexdump.toHexString(this.fid, 4)).append(",securityInformation=0x").append(Hexdump.toHexString(this.securityInformation, 8)).append("]").toString());
    }
}
