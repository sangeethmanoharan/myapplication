package jcifs.smb;

class TransPeekNamedPipeResponse extends SmbComTransactionResponse {
    static final int STATUS_CONNECTION_OK = 3;
    static final int STATUS_DISCONNECTED = 1;
    static final int STATUS_LISTENING = 2;
    static final int STATUS_SERVER_END_CLOSED = 4;
    int available;
    private int head;
    private SmbNamedPipe pipe;
    int status;

    TransPeekNamedPipeResponse(SmbNamedPipe pipe) {
        this.pipe = pipe;
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
        this.available = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += STATUS_LISTENING;
        this.head = ServerMessageBlock.readInt2(buffer, bufferIndex);
        this.status = ServerMessageBlock.readInt2(buffer, bufferIndex + STATUS_LISTENING);
        return 6;
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    public String toString() {
        return new String(new StringBuffer().append("TransPeekNamedPipeResponse[").append(super.toString()).append("]").toString());
    }
}
