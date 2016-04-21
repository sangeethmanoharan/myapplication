package jcifs.smb;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import jcifs.util.Hexdump;
import jcifs.util.LogStream;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.Type;

class SmbComNegotiateResponse extends ServerMessageBlock {
    int dialectIndex;
    ServerData server;

    SmbComNegotiateResponse(ServerData server) {
        this.server = server;
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        boolean z = true;
        int start = bufferIndex;
        this.dialectIndex = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        if (this.dialectIndex > 10) {
            return bufferIndex - start;
        }
        boolean z2;
        int bufferIndex2 = bufferIndex + 1;
        this.server.securityMode = buffer[bufferIndex] & Type.ANY;
        this.server.security = this.server.securityMode & 1;
        ServerData serverData = this.server;
        if ((this.server.securityMode & 2) == 2) {
            z2 = true;
        } else {
            z2 = false;
        }
        serverData.encryptedPasswords = z2;
        serverData = this.server;
        if ((this.server.securityMode & 4) == 4) {
            z2 = true;
        } else {
            z2 = false;
        }
        serverData.signaturesEnabled = z2;
        ServerData serverData2 = this.server;
        if ((this.server.securityMode & 8) != 8) {
            z = false;
        }
        serverData2.signaturesRequired = z;
        this.server.maxMpxCount = ServerMessageBlock.readInt2(buffer, bufferIndex2);
        bufferIndex = bufferIndex2 + 2;
        this.server.maxNumberVcs = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        this.server.maxBufferSize = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.maxRawSize = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.sessionKey = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.capabilities = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        this.server.serverTime = ServerMessageBlock.readTime(buffer, bufferIndex);
        bufferIndex += 8;
        this.server.serverTimeZone = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        bufferIndex2 = bufferIndex + 1;
        this.server.encryptionKeyLength = buffer[bufferIndex] & Type.ANY;
        bufferIndex = bufferIndex2;
        return bufferIndex2 - start;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        int start = bufferIndex;
        this.server.encryptionKey = new byte[this.server.encryptionKeyLength];
        System.arraycopy(buffer, bufferIndex, this.server.encryptionKey, 0, this.server.encryptionKeyLength);
        bufferIndex += this.server.encryptionKeyLength;
        if (this.byteCount > this.server.encryptionKeyLength) {
            int len = 0;
            try {
                if ((this.flags2 & KEYRecord.FLAG_NOAUTH) == KEYRecord.FLAG_NOAUTH) {
                    do {
                        if (buffer[bufferIndex + len] == (byte) 0 && buffer[(bufferIndex + len) + 1] == (byte) 0) {
                            this.server.oemDomainName = new String(buffer, bufferIndex, len, "UnicodeLittleUnmarked");
                        } else {
                            len += 2;
                        }
                    } while (len <= KEYRecord.OWNER_ZONE);
                    throw new RuntimeException("zero termination not found");
                }
                while (buffer[bufferIndex + len] != (byte) 0) {
                    len++;
                    if (len > KEYRecord.OWNER_ZONE) {
                        throw new RuntimeException("zero termination not found");
                    }
                }
                this.server.oemDomainName = new String(buffer, bufferIndex, len, SmbConstants.OEM_ENCODING);
            } catch (UnsupportedEncodingException uee) {
                LogStream logStream = log;
                if (LogStream.level > 1) {
                    uee.printStackTrace(log);
                }
            }
            bufferIndex += len;
        } else {
            this.server.oemDomainName = new String();
        }
        return bufferIndex - start;
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComNegotiateResponse[").append(super.toString()).append(",wordCount=").append(this.wordCount).append(",dialectIndex=").append(this.dialectIndex).append(",securityMode=0x").append(Hexdump.toHexString(this.server.securityMode, 1)).append(",security=").append(this.server.security == 0 ? "share" : "user").append(",encryptedPasswords=").append(this.server.encryptedPasswords).append(",maxMpxCount=").append(this.server.maxMpxCount).append(",maxNumberVcs=").append(this.server.maxNumberVcs).append(",maxBufferSize=").append(this.server.maxBufferSize).append(",maxRawSize=").append(this.server.maxRawSize).append(",sessionKey=0x").append(Hexdump.toHexString(this.server.sessionKey, 8)).append(",capabilities=0x").append(Hexdump.toHexString(this.server.capabilities, 8)).append(",serverTime=").append(new Date(this.server.serverTime)).append(",serverTimeZone=").append(this.server.serverTimeZone).append(",encryptionKeyLength=").append(this.server.encryptionKeyLength).append(",byteCount=").append(this.byteCount).append(",encryptionKey=0x").append(Hexdump.toHexString(this.server.encryptionKey, 0, this.server.encryptionKeyLength * 2)).append(",oemDomainName=").append(this.server.oemDomainName).append("]").toString());
    }
}
