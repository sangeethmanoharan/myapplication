package jcifs.netbios;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.xbill.DNS.Message;
import org.xbill.DNS.Type;

class SocketOutputStream extends FilterOutputStream {
    SocketOutputStream(OutputStream out) {
        super(out);
    }

    public synchronized void write(byte[] b, int off, int len) throws IOException {
        if (len > Message.MAXLENGTH) {
            throw new IOException(new StringBuffer().append("write too large: ").append(len).toString());
        } else if (off < 4) {
            throw new IOException("NetBIOS socket output buffer requires 4 bytes available before off");
        } else {
            off -= 4;
            b[off + 0] = (byte) 0;
            b[off + 1] = (byte) 0;
            b[off + 2] = (byte) ((len >> 8) & Type.ANY);
            b[off + 3] = (byte) (len & Type.ANY);
            this.out.write(b, off, len + 4);
        }
    }
}
