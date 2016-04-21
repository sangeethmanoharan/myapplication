package jcifs.smb;

import jcifs.util.LogStream;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Message;

class NetShareEnumResponse extends SmbComTransactionResponse {
    private int converter;
    private int totalAvailableEntries;

    NetShareEnumResponse() {
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
        int start = bufferIndex;
        this.status = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.converter = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.numEntries = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.totalAvailableEntries = ServerMessageBlock.readInt2(buffer, bufferIndex);
        return (bufferIndex + 2) - start;
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
        int start = bufferIndex;
        this.useUnicode = false;
        this.results = new SmbShareInfo[this.numEntries];
        for (int i = 0; i < this.numEntries; i++) {
            FileEntry[] fileEntryArr = this.results;
            SmbShareInfo e = new SmbShareInfo();
            fileEntryArr[i] = e;
            e.netName = readString(buffer, bufferIndex, 13, false);
            bufferIndex += 14;
            e.type = ServerMessageBlock.readInt2(buffer, bufferIndex);
            bufferIndex += 2;
            int off = ServerMessageBlock.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            e.remark = readString(buffer, ((Message.MAXLENGTH & off) - this.converter) + start, Flags.FLAG8, false);
            LogStream logStream = log;
            if (LogStream.level >= 4) {
                log.println(e);
            }
        }
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("NetShareEnumResponse[").append(super.toString()).append(",status=").append(this.status).append(",converter=").append(this.converter).append(",entriesReturned=").append(this.numEntries).append(",totalAvailableEntries=").append(this.totalAvailableEntries).append("]").toString());
    }
}
