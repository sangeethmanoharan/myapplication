package jcifs.smb;

import org.xbill.DNS.KEYRecord.Flags;

class Trans2GetDfsReferral extends SmbComTransaction {
    private int maxReferralLevel = 3;

    Trans2GetDfsReferral(String filename) {
        this.path = filename;
        this.command = (byte) 50;
        this.subCommand = (byte) 16;
        this.totalDataCount = 0;
        this.maxParameterCount = 0;
        this.maxDataCount = Flags.EXTEND;
        this.maxSetupCount = (byte) 0;
    }

    int writeSetupWireFormat(byte[] dst, int dstIndex) {
        int i = dstIndex + 1;
        dst[dstIndex] = this.subCommand;
        dstIndex = i + 1;
        dst[i] = (byte) 0;
        return 2;
    }

    int writeParametersWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;
        ServerMessageBlock.writeInt2((long) this.maxReferralLevel, dst, dstIndex);
        dstIndex += 2;
        return (dstIndex + writeString(this.path, dst, dstIndex)) - start;
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
        return new String(new StringBuffer().append("Trans2GetDfsReferral[").append(super.toString()).append(",maxReferralLevel=0x").append(this.maxReferralLevel).append(",filename=").append(this.path).append("]").toString());
    }
}
