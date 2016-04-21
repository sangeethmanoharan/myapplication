package jcifs.smb;

import java.util.Date;
import jcifs.util.Hexdump;

class SmbComQueryInformationResponse extends ServerMessageBlock implements Info {
    private int fileAttributes = 0;
    private int fileSize = 0;
    private long lastWriteTime = 0;
    private long serverTimeZoneOffset;

    SmbComQueryInformationResponse(long serverTimeZoneOffset) {
        this.serverTimeZoneOffset = serverTimeZoneOffset;
        this.command = (byte) 8;
    }

    public int getAttributes() {
        return this.fileAttributes;
    }

    public long getCreateTime() {
        return this.lastWriteTime + this.serverTimeZoneOffset;
    }

    public long getLastWriteTime() {
        return this.lastWriteTime + this.serverTimeZoneOffset;
    }

    public long getSize() {
        return (long) this.fileSize;
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        if (this.wordCount == 0) {
            return 0;
        }
        this.fileAttributes = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.lastWriteTime = ServerMessageBlock.readUTime(buffer, bufferIndex);
        this.fileSize = ServerMessageBlock.readInt4(buffer, bufferIndex + 4);
        return 20;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComQueryInformationResponse[").append(super.toString()).append(",fileAttributes=0x").append(Hexdump.toHexString(this.fileAttributes, 4)).append(",lastWriteTime=").append(new Date(this.lastWriteTime)).append(",fileSize=").append(this.fileSize).append("]").toString());
    }
}
