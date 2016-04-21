package jcifs.dcerpc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFileInputStream;
import jcifs.smb.SmbFileOutputStream;
import jcifs.smb.SmbNamedPipe;
import jcifs.util.Encdec;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Type;

public class DcerpcPipeHandle extends DcerpcHandle {
    SmbFileInputStream in = null;
    boolean isStart = true;
    SmbFileOutputStream out = null;
    SmbNamedPipe pipe;

    public DcerpcPipeHandle(String url, NtlmPasswordAuthentication auth) throws UnknownHostException, MalformedURLException, DcerpcException {
        this.binding = DcerpcHandle.parseBinding(url);
        this.pipe = new SmbNamedPipe(new StringBuffer().append("smb://").append(this.binding.server).append("/IPC$/").append(this.binding.endpoint.substring(6)).toString(), 27198979, auth);
    }

    protected void doSendFragment(byte[] buf, int off, int length, boolean isDirect) throws IOException {
        if (this.in == null) {
            this.in = (SmbFileInputStream) this.pipe.getNamedPipeInputStream();
        }
        if (this.out == null) {
            this.out = (SmbFileOutputStream) this.pipe.getNamedPipeOutputStream();
        }
        if (isDirect) {
            this.out.writeDirect(buf, off, length, 1);
        } else {
            this.out.write(buf, off, length);
        }
    }

    protected void doReceiveFragment(byte[] buf, boolean isDirect) throws IOException {
        boolean z = true;
        if (buf.length < this.max_recv) {
            throw new IllegalArgumentException("buffer too small");
        }
        int off;
        if (!this.isStart || isDirect) {
            off = this.in.readDirect(buf, 0, buf.length);
        } else {
            off = this.in.read(buf, 0, Flags.FLAG5);
        }
        if (buf[0] == (byte) 5 || buf[1] == (byte) 0) {
            if (((buf[3] & Type.ANY) & 2) != 2) {
                z = false;
            }
            this.isStart = z;
            int length = Encdec.dec_uint16le(buf, 8);
            if (length > this.max_recv) {
                throw new IOException(new StringBuffer().append("Unexpected fragment length: ").append(length).toString());
            }
            while (off < length) {
                off += this.in.readDirect(buf, off, length - off);
            }
            return;
        }
        throw new IOException("Unexpected DCERPC PDU header");
    }

    public void close() throws IOException {
        if (this.out != null) {
            this.out.close();
        }
    }
}
