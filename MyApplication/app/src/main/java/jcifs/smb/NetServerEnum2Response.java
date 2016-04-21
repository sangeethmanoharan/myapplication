package jcifs.smb;

import jcifs.util.Hexdump;
import jcifs.util.LogStream;
import org.xbill.DNS.Message;
import org.xbill.DNS.Type;

class NetServerEnum2Response extends SmbComTransactionResponse {
    private int converter;
    String lastName;
    private int totalAvailableEntries;

    class ServerInfo1 implements FileEntry {
        String commentOrMasterBrowser;
        String name;
        private final NetServerEnum2Response this$0;
        int type;
        int versionMajor;
        int versionMinor;

        ServerInfo1(NetServerEnum2Response this$0) {
            this.this$0 = this$0;
        }

        public String getName() {
            return this.name;
        }

        public int getType() {
            return (this.type & SmbConstants.GENERIC_READ) != 0 ? 2 : 4;
        }

        public int getAttributes() {
            return 17;
        }

        public long createTime() {
            return 0;
        }

        public long lastModified() {
            return 0;
        }

        public long length() {
            return 0;
        }

        public String toString() {
            return new String(new StringBuffer().append("ServerInfo1[name=").append(this.name).append(",versionMajor=").append(this.versionMajor).append(",versionMinor=").append(this.versionMinor).append(",type=0x").append(Hexdump.toHexString(this.type, 8)).append(",commentOrMasterBrowser=").append(this.commentOrMasterBrowser).append("]").toString());
        }
    }

    NetServerEnum2Response() {
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
        ServerInfo1 e = null;
        this.results = new ServerInfo1[this.numEntries];
        for (int i = 0; i < this.numEntries; i++) {
            FileEntry[] fileEntryArr = this.results;
            e = new ServerInfo1(this);
            fileEntryArr[i] = e;
            e.name = readString(buffer, bufferIndex, 16, false);
            bufferIndex += 16;
            int bufferIndex2 = bufferIndex + 1;
            e.versionMajor = buffer[bufferIndex] & Type.ANY;
            bufferIndex = bufferIndex2 + 1;
            e.versionMinor = buffer[bufferIndex2] & Type.ANY;
            e.type = ServerMessageBlock.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            int off = ServerMessageBlock.readInt4(buffer, bufferIndex);
            bufferIndex += 4;
            e.commentOrMasterBrowser = readString(buffer, ((Message.MAXLENGTH & off) - this.converter) + start, 48, false);
            LogStream logStream = log;
            if (LogStream.level >= 4) {
                log.println(e);
            }
        }
        this.lastName = this.numEntries == 0 ? null : e.name;
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("NetServerEnum2Response[").append(super.toString()).append(",status=").append(this.status).append(",converter=").append(this.converter).append(",entriesReturned=").append(this.numEntries).append(",totalAvailableEntries=").append(this.totalAvailableEntries).append(",lastName=").append(this.lastName).append("]").toString());
    }
}
