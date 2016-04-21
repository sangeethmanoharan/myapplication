package jcifs.smb;

import java.util.Enumeration;
import jcifs.util.LogStream;
import org.xbill.DNS.Type;

abstract class SmbComTransactionResponse extends ServerMessageBlock implements Enumeration {
    private static final int DISCONNECT_TID = 1;
    private static final int ONE_WAY_TRANSACTION = 2;
    private static final int SETUP_OFFSET = 61;
    protected int bufDataStart;
    protected int bufParameterStart;
    int dataCount;
    protected int dataDisplacement;
    private boolean dataDone;
    protected int dataOffset;
    boolean hasMore = true;
    boolean isPrimary = true;
    int numEntries;
    private int pad;
    private int pad1;
    protected int parameterCount;
    protected int parameterDisplacement;
    protected int parameterOffset;
    private boolean parametersDone;
    FileEntry[] results;
    protected int setupCount;
    int status;
    byte subCommand;
    protected int totalDataCount;
    protected int totalParameterCount;
    byte[] txn_buf = null;

    abstract int readDataWireFormat(byte[] bArr, int i, int i2);

    abstract int readParametersWireFormat(byte[] bArr, int i, int i2);

    abstract int readSetupWireFormat(byte[] bArr, int i, int i2);

    abstract int writeDataWireFormat(byte[] bArr, int i);

    abstract int writeParametersWireFormat(byte[] bArr, int i);

    abstract int writeSetupWireFormat(byte[] bArr, int i);

    SmbComTransactionResponse() {
    }

    void reset() {
        super.reset();
        this.bufDataStart = 0;
        this.hasMore = true;
        this.isPrimary = true;
        this.dataDone = false;
        this.parametersDone = false;
    }

    public boolean hasMoreElements() {
        return this.errorCode == 0 && this.hasMore;
    }

    public Object nextElement() {
        if (this.isPrimary) {
            this.isPrimary = false;
        }
        return this;
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        this.totalParameterCount = ServerMessageBlock.readInt2(buffer, bufferIndex);
        if (this.bufDataStart == 0) {
            this.bufDataStart = this.totalParameterCount;
        }
        bufferIndex += ONE_WAY_TRANSACTION;
        this.totalDataCount = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 4;
        this.parameterCount = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += ONE_WAY_TRANSACTION;
        this.parameterOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += ONE_WAY_TRANSACTION;
        this.parameterDisplacement = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += ONE_WAY_TRANSACTION;
        this.dataCount = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += ONE_WAY_TRANSACTION;
        this.dataOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += ONE_WAY_TRANSACTION;
        this.dataDisplacement = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += ONE_WAY_TRANSACTION;
        this.setupCount = buffer[bufferIndex] & Type.ANY;
        bufferIndex += ONE_WAY_TRANSACTION;
        if (this.setupCount != 0) {
            LogStream logStream = log;
            if (LogStream.level > ONE_WAY_TRANSACTION) {
                log.println(new StringBuffer().append("setupCount is not zero: ").append(this.setupCount).toString());
            }
        }
        return bufferIndex - start;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        this.pad1 = 0;
        this.pad = 0;
        if (this.parameterCount > 0) {
            int i = this.parameterOffset - (bufferIndex - this.headerStart);
            this.pad = i;
            bufferIndex += i;
            System.arraycopy(buffer, bufferIndex, this.txn_buf, this.bufParameterStart + this.parameterDisplacement, this.parameterCount);
            bufferIndex += this.parameterCount;
        }
        if (this.dataCount > 0) {
            i = this.dataOffset - (bufferIndex - this.headerStart);
            this.pad1 = i;
            bufferIndex += i;
            System.arraycopy(buffer, bufferIndex, this.txn_buf, this.bufDataStart + this.dataDisplacement, this.dataCount);
            bufferIndex += this.dataCount;
        }
        if (!this.parametersDone && this.parameterDisplacement + this.parameterCount == this.totalParameterCount) {
            this.parametersDone = true;
        }
        if (!this.dataDone && this.dataDisplacement + this.dataCount == this.totalDataCount) {
            this.dataDone = true;
        }
        if (this.parametersDone && this.dataDone) {
            this.hasMore = false;
            readParametersWireFormat(this.txn_buf, this.bufParameterStart, this.totalParameterCount);
            readDataWireFormat(this.txn_buf, this.bufDataStart, this.totalDataCount);
        }
        return ((this.pad + this.parameterCount) + this.pad1) + this.dataCount;
    }

    public String toString() {
        return new String(new StringBuffer().append(super.toString()).append(",totalParameterCount=").append(this.totalParameterCount).append(",totalDataCount=").append(this.totalDataCount).append(",parameterCount=").append(this.parameterCount).append(",parameterOffset=").append(this.parameterOffset).append(",parameterDisplacement=").append(this.parameterDisplacement).append(",dataCount=").append(this.dataCount).append(",dataOffset=").append(this.dataOffset).append(",dataDisplacement=").append(this.dataDisplacement).append(",setupCount=").append(this.setupCount).append(",pad=").append(this.pad).append(",pad1=").append(this.pad1).toString());
    }
}
