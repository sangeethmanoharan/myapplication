package jcifs.smb;

import java.io.UnsupportedEncodingException;
import jcifs.util.LogStream;
import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.KEYRecord;

class SmbComSessionSetupAndXResponse extends AndXServerMessageBlock {
    boolean isLoggedInAsGuest;
    private String nativeLanMan = BuildConfig.VERSION_NAME;
    private String nativeOs = BuildConfig.VERSION_NAME;
    private String primaryDomain = BuildConfig.VERSION_NAME;

    SmbComSessionSetupAndXResponse(ServerMessageBlock andx) {
        super(andx);
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        boolean z = true;
        if ((buffer[bufferIndex] & 1) != 1) {
            z = false;
        }
        this.isLoggedInAsGuest = z;
        return 2;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        this.nativeOs = readString(buffer, bufferIndex);
        bufferIndex += stringWireLength(this.nativeOs, bufferIndex);
        this.nativeLanMan = readString(buffer, bufferIndex);
        bufferIndex += stringWireLength(this.nativeLanMan, bufferIndex);
        if (this.useUnicode) {
            if ((bufferIndex - this.headerStart) % 2 != 0) {
                bufferIndex++;
            }
            int len = 0;
            while (buffer[bufferIndex + len] != (byte) 0) {
                len += 2;
                if (len > KEYRecord.OWNER_ZONE) {
                    throw new RuntimeException("zero termination not found");
                }
            }
            try {
                this.primaryDomain = new String(buffer, bufferIndex, len, "UnicodeLittle");
            } catch (UnsupportedEncodingException uee) {
                LogStream logStream = log;
                if (LogStream.level > 1) {
                    uee.printStackTrace(log);
                }
            }
            bufferIndex += len;
        } else {
            this.primaryDomain = readString(buffer, bufferIndex);
            bufferIndex += stringWireLength(this.primaryDomain, bufferIndex);
        }
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComSessionSetupAndXResponse[").append(super.toString()).append(",isLoggedInAsGuest=").append(this.isLoggedInAsGuest).append(",nativeOs=").append(this.nativeOs).append(",nativeLanMan=").append(this.nativeLanMan).append(",primaryDomain=").append(this.primaryDomain).append("]").toString());
    }
}
