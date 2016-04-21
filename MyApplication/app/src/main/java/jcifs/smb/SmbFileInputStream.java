package jcifs.smb;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import jcifs.util.LogStream;
import jcifs.util.transport.TransportException;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Type;

public class SmbFileInputStream extends InputStream {
    private int access;
    SmbFile file;
    private long fp;
    private int openFlags;
    private int readSize;
    private byte[] tmp;

    public SmbFileInputStream(String url) throws SmbException, MalformedURLException, UnknownHostException {
        this(new SmbFile(url));
    }

    public SmbFileInputStream(SmbFile file) throws SmbException, MalformedURLException, UnknownHostException {
        this(file, 1);
    }

    SmbFileInputStream(SmbFile file, int openFlags) throws SmbException, MalformedURLException, UnknownHostException {
        this.tmp = new byte[1];
        this.file = file;
        this.openFlags = openFlags & Message.MAXLENGTH;
        this.access = (openFlags >>> 16) & Message.MAXLENGTH;
        if (file.type != 16) {
            file.open(openFlags, this.access, Flags.FLAG8, 0);
            this.openFlags &= -81;
        } else {
            file.connect0();
        }
        this.readSize = Math.min(file.tree.session.transport.rcv_buf_size - 70, file.tree.session.transport.server.maxBufferSize - 70);
    }

    protected IOException seToIoe(SmbException se) {
        IOException ioe = se;
        Throwable root = se.getRootCause();
        if (root instanceof TransportException) {
            ioe = (TransportException) root;
            root = ((TransportException) ioe).getRootCause();
        }
        if (!(root instanceof InterruptedException)) {
            return ioe;
        }
        ioe = new InterruptedIOException(root.getMessage());
        ioe.initCause(root);
        return ioe;
    }

    public void close() throws IOException {
        try {
            this.file.close();
            this.tmp = null;
        } catch (SmbException se) {
            throw seToIoe(se);
        }
    }

    public int read() throws IOException {
        if (read(this.tmp, 0, 1) == -1) {
            return -1;
        }
        return this.tmp[0] & Type.ANY;
    }

    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    public int read(byte[] b, int off, int len) throws IOException {
        return readDirect(b, off, len);
    }

    public int readDirect(byte[] b, int off, int len) throws IOException {
        if (len <= 0) {
            return 0;
        }
        long start = this.fp;
        if (this.tmp == null) {
            throw new IOException("Bad file descriptor");
        }
        this.file.open(this.openFlags, this.access, Flags.FLAG8, 0);
        SmbFile smbFile = this.file;
        LogStream logStream = SmbFile.log;
        if (LogStream.level >= 4) {
            smbFile = this.file;
            SmbFile.log.println(new StringBuffer().append("read: fid=").append(this.file.fid).append(",off=").append(off).append(",len=").append(len).toString());
        }
        SmbComReadAndXResponse response = new SmbComReadAndXResponse(b, off);
        if (this.file.type == 16) {
            response.responseTimeout = 0;
        }
        int n;
        int r;
        do {
            if (len > this.readSize) {
                r = this.readSize;
            } else {
                r = len;
            }
            smbFile = this.file;
            logStream = SmbFile.log;
            if (LogStream.level >= 4) {
                smbFile = this.file;
                SmbFile.log.println(new StringBuffer().append("read: len=").append(len).append(",r=").append(r).append(",fp=").append(this.fp).toString());
            }
            try {
                SmbComReadAndX request = new SmbComReadAndX(this.file.fid, this.fp, r, null);
                if (this.file.type == 16) {
                    request.remaining = Flags.FLAG5;
                    request.maxCount = Flags.FLAG5;
                    request.minCount = Flags.FLAG5;
                }
                this.file.send(request, response);
                n = response.dataLength;
                if (n > 0) {
                    this.fp += (long) n;
                    len -= n;
                    response.off += n;
                    if (len <= 0) {
                        break;
                    }
                } else {
                    return (int) (this.fp - start > 0 ? this.fp - start : -1);
                }
            } catch (SmbException se) {
                if (this.file.type == 16 && se.getNtStatus() == NtStatus.NT_STATUS_PIPE_BROKEN) {
                    return -1;
                }
                throw seToIoe(se);
            }
        } while (n == r);
        return (int) (this.fp - start);
    }

    public int available() throws IOException {
        int i = 0;
        if (this.file.type == 16) {
            try {
                SmbNamedPipe pipe = this.file;
                this.file.open(32, pipe.pipeType & 16711680, Flags.FLAG8, 0);
                TransPeekNamedPipe req = new TransPeekNamedPipe(this.file.unc, this.file.fid);
                TransPeekNamedPipeResponse resp = new TransPeekNamedPipeResponse(pipe);
                pipe.send(req, resp);
                if (resp.status == 1 || resp.status == 4) {
                    this.file.opened = false;
                } else {
                    i = resp.available;
                }
            } catch (SmbException se) {
                throw seToIoe(se);
            }
        }
        return i;
    }

    public long skip(long n) throws IOException {
        if (n <= 0) {
            return 0;
        }
        this.fp += n;
        return n;
    }
}
