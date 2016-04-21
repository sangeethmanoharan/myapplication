package jcifs.smb;

class Trans2QueryFSInformationResponse extends SmbComTransactionResponse {
    static final int SMB_FS_FULL_SIZE_INFORMATION = 1007;
    static final int SMB_INFO_ALLOCATION = 1;
    static final int SMB_QUERY_FS_SIZE_INFO = 259;
    AllocInfo info;
    private int informationLevel;

    class SmbInfoAllocation implements AllocInfo {
        long alloc;
        int bytesPerSect;
        long free;
        int sectPerAlloc;
        private final Trans2QueryFSInformationResponse this$0;

        SmbInfoAllocation(Trans2QueryFSInformationResponse this$0) {
            this.this$0 = this$0;
        }

        public long getCapacity() {
            return (this.alloc * ((long) this.sectPerAlloc)) * ((long) this.bytesPerSect);
        }

        public long getFree() {
            return (this.free * ((long) this.sectPerAlloc)) * ((long) this.bytesPerSect);
        }

        public String toString() {
            return new String(new StringBuffer().append("SmbInfoAllocation[alloc=").append(this.alloc).append(",free=").append(this.free).append(",sectPerAlloc=").append(this.sectPerAlloc).append(",bytesPerSect=").append(this.bytesPerSect).append("]").toString());
        }
    }

    Trans2QueryFSInformationResponse(int informationLevel) {
        this.informationLevel = informationLevel;
        this.command = (byte) 50;
        this.subCommand = (byte) 3;
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
        switch (this.informationLevel) {
            case SMB_INFO_ALLOCATION /*1*/:
                return readSmbInfoAllocationWireFormat(buffer, bufferIndex);
            case SMB_QUERY_FS_SIZE_INFO /*259*/:
                return readSmbQueryFSSizeInfoWireFormat(buffer, bufferIndex);
            case SMB_FS_FULL_SIZE_INFORMATION /*1007*/:
                return readFsFullSizeInformationWireFormat(buffer, bufferIndex);
            default:
                return 0;
        }
    }

    int readSmbInfoAllocationWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        SmbInfoAllocation info = new SmbInfoAllocation(this);
        bufferIndex += 4;
        info.sectPerAlloc = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        info.alloc = (long) ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        info.free = (long) ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        info.bytesPerSect = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 4;
        this.info = info;
        return bufferIndex - start;
    }

    int readSmbQueryFSSizeInfoWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        SmbInfoAllocation info = new SmbInfoAllocation(this);
        info.alloc = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.free = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.sectPerAlloc = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        info.bytesPerSect = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.info = info;
        return bufferIndex - start;
    }

    int readFsFullSizeInformationWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        SmbInfoAllocation info = new SmbInfoAllocation(this);
        info.alloc = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        info.free = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex = (bufferIndex + 8) + 8;
        info.sectPerAlloc = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        info.bytesPerSect = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.info = info;
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("Trans2QueryFSInformationResponse[").append(super.toString()).append("]").toString());
    }
}
