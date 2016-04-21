package jcifs.smb;

import java.util.Date;
import jcifs.util.Hexdump;
import org.xbill.DNS.Type;

class SmbComNTCreateAndXResponse extends AndXServerMessageBlock {
    static final int BATCH_OPLOCK_GRANTED = 2;
    static final int EXCLUSIVE_OPLOCK_GRANTED = 1;
    static final int LEVEL_II_OPLOCK_GRANTED = 3;
    long allocationSize;
    long changeTime;
    int createAction;
    long creationTime;
    int deviceState;
    boolean directory;
    long endOfFile;
    int extFileAttributes;
    int fid;
    int fileType;
    boolean isExtended;
    long lastAccessTime;
    long lastWriteTime;
    byte oplockLevel;

    SmbComNTCreateAndXResponse() {
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        int bufferIndex2 = bufferIndex + EXCLUSIVE_OPLOCK_GRANTED;
        this.oplockLevel = buffer[bufferIndex];
        this.fid = ServerMessageBlock.readInt2(buffer, bufferIndex2);
        bufferIndex = bufferIndex2 + BATCH_OPLOCK_GRANTED;
        this.createAction = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.creationTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastAccessTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.lastWriteTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.changeTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.extFileAttributes = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.allocationSize = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.endOfFile = ServerMessageBlock.readInt8(buffer, bufferIndex);
        bufferIndex += 8;
        this.fileType = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += BATCH_OPLOCK_GRANTED;
        this.deviceState = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += BATCH_OPLOCK_GRANTED;
        bufferIndex2 = bufferIndex + EXCLUSIVE_OPLOCK_GRANTED;
        this.directory = (buffer[bufferIndex] & Type.ANY) > 0;
        return bufferIndex2 - start;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComNTCreateAndXResponse[").append(super.toString()).append(",oplockLevel=").append(this.oplockLevel).append(",fid=").append(this.fid).append(",createAction=0x").append(Hexdump.toHexString(this.createAction, 4)).append(",creationTime=").append(new Date(this.creationTime)).append(",lastAccessTime=").append(new Date(this.lastAccessTime)).append(",lastWriteTime=").append(new Date(this.lastWriteTime)).append(",changeTime=").append(new Date(this.changeTime)).append(",extFileAttributes=0x").append(Hexdump.toHexString(this.extFileAttributes, 4)).append(",allocationSize=").append(this.allocationSize).append(",endOfFile=").append(this.endOfFile).append(",fileType=").append(this.fileType).append(",deviceState=").append(this.deviceState).append(",directory=").append(this.directory).append("]").toString());
    }
}
