package jcifs.smb;

import java.io.IOException;
import org.xbill.DNS.KEYRecord.Flags;

public class SecurityDescriptor {
    public ACE[] aces;
    public int type;

    public SecurityDescriptor(byte[] buffer, int bufferIndex, int len) throws IOException {
        decode(buffer, bufferIndex, len);
    }

    public int decode(byte[] buffer, int bufferIndex, int len) throws IOException {
        int start = bufferIndex;
        bufferIndex = (bufferIndex + 1) + 1;
        this.type = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        ServerMessageBlock.readInt4(buffer, bufferIndex);
        int daclOffset = ServerMessageBlock.readInt4(buffer, bufferIndex + 4);
        bufferIndex = ((start + daclOffset) + 1) + 1;
        int size = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        int numAces = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        if (numAces > Flags.EXTEND) {
            throw new IOException("Invalid SecurityDescriptor");
        }
        if (daclOffset != 0) {
            this.aces = new ACE[numAces];
            for (int i = 0; i < numAces; i++) {
                this.aces[i] = new ACE();
                bufferIndex += this.aces[i].decode(buffer, bufferIndex);
            }
        } else {
            this.aces = null;
        }
        return bufferIndex - start;
    }

    public String toString() {
        String ret = "SecurityDescriptor:\n";
        if (this.aces == null) {
            return new StringBuffer().append(ret).append("NULL").toString();
        }
        for (ACE ace : this.aces) {
            ret = new StringBuffer().append(ret).append(ace.toString()).append("\n").toString();
        }
        return ret;
    }
}
