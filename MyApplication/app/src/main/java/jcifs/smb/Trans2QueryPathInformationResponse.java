package jcifs.smb;

import java.util.Date;
import jcifs.util.Hexdump;
import org.xbill.DNS.Type;

class Trans2QueryPathInformationResponse extends SmbComTransactionResponse {
    static final int SMB_QUERY_FILE_BASIC_INFO = 257;
    static final int SMB_QUERY_FILE_STANDARD_INFO = 258;
    Info info;
    private int informationLevel;

    class SmbQueryFileBasicInfo implements Info {
        int attributes;
        long changeTime;
        long createTime;
        long lastAccessTime;
        long lastWriteTime;
        private final Trans2QueryPathInformationResponse this$0;

        SmbQueryFileBasicInfo(Trans2QueryPathInformationResponse this$0) {
            this.this$0 = this$0;
        }

        public int getAttributes() {
            return this.attributes;
        }

        public long getCreateTime() {
            return this.createTime;
        }

        public long getLastWriteTime() {
            return this.lastWriteTime;
        }

        public long getSize() {
            return 0;
        }

        public String toString() {
            return new String(new StringBuffer().append("SmbQueryFileBasicInfo[createTime=").append(new Date(this.createTime)).append(",lastAccessTime=").append(new Date(this.lastAccessTime)).append(",lastWriteTime=").append(new Date(this.lastWriteTime)).append(",changeTime=").append(new Date(this.changeTime)).append(",attributes=0x").append(Hexdump.toHexString(this.attributes, 4)).append("]").toString());
        }
    }

    class SmbQueryFileStandardInfo implements Info {
        long allocationSize;
        boolean deletePending;
        boolean directory;
        long endOfFile;
        int numberOfLinks;
        private final Trans2QueryPathInformationResponse this$0;

        SmbQueryFileStandardInfo(Trans2QueryPathInformationResponse this$0) {
            this.this$0 = this$0;
        }

        public int getAttributes() {
            return 0;
        }

        public long getCreateTime() {
            return 0;
        }

        public long getLastWriteTime() {
            return 0;
        }

        public long getSize() {
            return this.endOfFile;
        }

        public String toString() {
            return new String(new StringBuffer().append("SmbQueryInfoStandard[allocationSize=").append(this.allocationSize).append(",endOfFile=").append(this.endOfFile).append(",numberOfLinks=").append(this.numberOfLinks).append(",deletePending=").append(this.deletePending).append(",directory=").append(this.directory).append("]").toString());
        }
    }

    Trans2QueryPathInformationResponse(int informationLevel) {
        this.informationLevel = informationLevel;
        this.subCommand = (byte) 5;
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
        return 2;
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
        switch (this.informationLevel) {
            case SMB_QUERY_FILE_BASIC_INFO /*257*/:
                return readSmbQueryFileBasicInfoWireFormat(buffer, bufferIndex);
            case SMB_QUERY_FILE_STANDARD_INFO /*258*/:
                return readSmbQueryFileStandardInfoWireFormat(buffer, bufferIndex);
            default:
                return 0;
        }
    }

    int readSmbQueryFileStandardInfoWireFormat(byte[] buffer, int bufferIndex) {
        boolean z;
        boolean z2 = true;
        int start = bufferIndex;
        SmbQueryFileStandardInfo info = new SmbQueryFileStandardInfo(this);
        info.allocationSize = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.endOfFile = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.numberOfLinks = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        int bufferIndex2 = bufferIndex + 1;
        if ((buffer[bufferIndex] & Type.ANY) > 0) {
            z = true;
        } else {
            z = false;
        }
        info.deletePending = z;
        bufferIndex = bufferIndex2 + 1;
        if ((buffer[bufferIndex2] & Type.ANY) <= 0) {
            z2 = false;
        }
        info.directory = z2;
        this.info = info;
        return bufferIndex - start;
    }

    int readSmbQueryFileBasicInfoWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        SmbQueryFileBasicInfo info = new SmbQueryFileBasicInfo(this);
        info.createTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.lastAccessTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.lastWriteTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.changeTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        info.attributes = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.info = info;
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("Trans2QueryPathInformationResponse[").append(super.toString()).append("]").toString());
    }
}
