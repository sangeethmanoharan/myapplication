package jcifs.smb;

import org.xbill.DNS.KEYRecord;

class Trans2GetDfsReferralResponse extends SmbComTransactionResponse {
    int flags;
    int numReferrals;
    int pathConsumed;
    Referral[] referrals;

    class Referral {
        private String altPath;
        private int altPathOffset;
        private int flags;
        String node = null;
        private int nodeOffset;
        String path = null;
        private int pathOffset;
        private int proximity;
        private int serverType;
        private int size;
        private final Trans2GetDfsReferralResponse this$0;
        int ttl;
        private int version;

        Referral(Trans2GetDfsReferralResponse this$0) {
            this.this$0 = this$0;
        }

        int readWireFormat(byte[] buffer, int bufferIndex, int len) {
            boolean z = true;
            int start = bufferIndex;
            this.version = ServerMessageBlock.readInt2(buffer, bufferIndex);
            if (this.version == 3 || this.version == 1) {
                bufferIndex += 2;
                this.size = ServerMessageBlock.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                this.serverType = ServerMessageBlock.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                this.flags = ServerMessageBlock.readInt2(buffer, bufferIndex);
                bufferIndex += 2;
                Trans2GetDfsReferralResponse trans2GetDfsReferralResponse;
                if (this.version == 3) {
                    this.proximity = ServerMessageBlock.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    this.ttl = ServerMessageBlock.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    this.pathOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    this.altPathOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    this.nodeOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
                    bufferIndex += 2;
                    this.path = this.this$0.readString(buffer, start + this.pathOffset, len, (this.this$0.flags2 & KEYRecord.FLAG_NOAUTH) != 0);
                    if (this.nodeOffset > 0) {
                        trans2GetDfsReferralResponse = this.this$0;
                        int i = this.nodeOffset + start;
                        if ((this.this$0.flags2 & KEYRecord.FLAG_NOAUTH) == 0) {
                            z = false;
                        }
                        this.node = trans2GetDfsReferralResponse.readString(buffer, i, len, z);
                    }
                } else if (this.version == 1) {
                    trans2GetDfsReferralResponse = this.this$0;
                    if ((this.this$0.flags2 & KEYRecord.FLAG_NOAUTH) == 0) {
                        z = false;
                    }
                    this.node = trans2GetDfsReferralResponse.readString(buffer, bufferIndex, len, z);
                }
                return this.size;
            }
            throw new RuntimeException(new StringBuffer().append("Version ").append(this.version).append(" referral not supported. Please report this to jcifs at samba dot org.").toString());
        }

        public String toString() {
            return new String(new StringBuffer().append("Referral[version=").append(this.version).append(",size=").append(this.size).append(",serverType=").append(this.serverType).append(",flags=").append(this.flags).append(",proximity=").append(this.proximity).append(",ttl=").append(this.ttl).append(",pathOffset=").append(this.pathOffset).append(",altPathOffset=").append(this.altPathOffset).append(",nodeOffset=").append(this.nodeOffset).append(",path=").append(this.path).append(",altPath=").append(this.altPath).append(",node=").append(this.node).append("]").toString());
        }
    }

    Trans2GetDfsReferralResponse() {
        this.subCommand = (byte) 16;
    }

    int writeSetupWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeParametersWireFormat(byte[] dst, int dstIndex) {
        return 0;
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
        int start = bufferIndex;
        this.pathConsumed = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        if ((this.flags2 & KEYRecord.FLAG_NOAUTH) != 0) {
            this.pathConsumed /= 2;
        }
        this.numReferrals = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.flags = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 4;
        this.referrals = new Referral[this.numReferrals];
        for (int ri = 0; ri < this.numReferrals; ri++) {
            this.referrals[ri] = new Referral(this);
            bufferIndex += this.referrals[ri].readWireFormat(buffer, bufferIndex, len);
        }
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("Trans2GetDfsReferralResponse[").append(super.toString()).append(",pathConsumed=").append(this.pathConsumed).append(",numReferrals=").append(this.numReferrals).append(",flags=").append(this.flags).append("]").toString());
    }
}
