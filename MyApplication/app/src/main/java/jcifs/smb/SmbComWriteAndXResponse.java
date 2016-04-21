package jcifs.smb;

class SmbComWriteAndXResponse extends AndXServerMessageBlock {
    long count;

    SmbComWriteAndXResponse() {
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        this.count = ((long) ServerMessageBlock.readInt2(buffer, bufferIndex)) & 65535;
        return 8;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComWriteAndXResponse[").append(super.toString()).append(",count=").append(this.count).append("]").toString());
    }
}
