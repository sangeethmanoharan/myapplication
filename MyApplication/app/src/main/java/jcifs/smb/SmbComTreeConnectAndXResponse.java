package jcifs.smb;

import java.io.UnsupportedEncodingException;
import lksystems.wifiintruder.BuildConfig;

class SmbComTreeConnectAndXResponse extends AndXServerMessageBlock {
    private static final int SMB_SHARE_IS_IN_DFS = 2;
    private static final int SMB_SUPPORT_SEARCH_BITS = 1;
    String nativeFileSystem = BuildConfig.VERSION_NAME;
    String service;
    boolean shareIsInDfs;
    boolean supportSearchBits;

    SmbComTreeConnectAndXResponse(ServerMessageBlock andx) {
        super(andx);
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        boolean z;
        boolean z2 = true;
        if ((buffer[bufferIndex] & SMB_SUPPORT_SEARCH_BITS) == SMB_SUPPORT_SEARCH_BITS) {
            z = true;
        } else {
            z = false;
        }
        this.supportSearchBits = z;
        if ((buffer[bufferIndex] & SMB_SHARE_IS_IN_DFS) != SMB_SHARE_IS_IN_DFS) {
            z2 = false;
        }
        this.shareIsInDfs = z2;
        return SMB_SHARE_IS_IN_DFS;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        int len = readStringLength(buffer, bufferIndex, 32);
        try {
            this.service = new String(buffer, bufferIndex, len, "ASCII");
            return (bufferIndex + (len + SMB_SUPPORT_SEARCH_BITS)) - start;
        } catch (UnsupportedEncodingException e) {
            return 0;
        }
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComTreeConnectAndXResponse[").append(super.toString()).append(",supportSearchBits=").append(this.supportSearchBits).append(",shareIsInDfs=").append(this.shareIsInDfs).append(",service=").append(this.service).append(",nativeFileSystem=").append(this.nativeFileSystem).append("]").toString());
    }
}
