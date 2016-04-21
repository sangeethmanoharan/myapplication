package jcifs.dcerpc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.security.Principal;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.smb.BufferCache;
import jcifs.smb.NtlmPasswordAuthentication;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

public abstract class DcerpcHandle implements DcerpcConstants {
    private static int call_id = 1;
    protected DcerpcBinding binding;
    protected int max_recv = this.max_xmit;
    protected int max_xmit = 4280;
    protected int state = 0;

    public abstract void close() throws IOException;

    protected abstract void doReceiveFragment(byte[] bArr, boolean z) throws IOException;

    protected abstract void doSendFragment(byte[] bArr, int i, int i2, boolean z) throws IOException;

    protected static DcerpcBinding parseBinding(String str) throws DcerpcException {
        char[] arr = str.toCharArray();
        String proto = null;
        String key = null;
        DcerpcBinding binding = null;
        int si = 0;
        int mark = 0;
        int state = 0;
        do {
            char ch = arr[si];
            switch (state) {
                case Tokenizer.EOF /*0*/:
                    if (ch == ':') {
                        proto = str.substring(mark, si);
                        mark = si + 1;
                        state = 1;
                        break;
                    }
                    break;
                case Zone.PRIMARY /*1*/:
                    if (ch == '\\') {
                        mark = si + 1;
                        break;
                    }
                    state = 2;
                case Zone.SECONDARY /*2*/:
                    if (ch == '[') {
                        if (str.substring(mark, si).trim().length() == 0) {
                            String server = "127.0.0.1";
                        }
                        binding = new DcerpcBinding(proto, str.substring(mark, si));
                        mark = si + 1;
                        state = 5;
                        break;
                    }
                    break;
                case Service.RJE /*5*/:
                    if (ch != '=') {
                        if (ch == ',' || ch == ']') {
                            String val = str.substring(mark, si).trim();
                            if (key == null) {
                                key = "endpoint";
                            }
                            binding.setOption(key, val);
                            key = null;
                            break;
                        }
                    }
                    key = str.substring(mark, si).trim();
                    mark = si + 1;
                    break;
                default:
                    si = arr.length;
                    break;
            }
            si++;
        } while (si < arr.length);
        if (binding != null && binding.endpoint != null) {
            return binding;
        }
        throw new DcerpcException(new StringBuffer().append("Invalid binding URL: ").append(str).toString());
    }

    public static DcerpcHandle getHandle(String url, NtlmPasswordAuthentication auth) throws UnknownHostException, MalformedURLException, DcerpcException {
        if (url.startsWith("ncacn_np:")) {
            return new DcerpcPipeHandle(url, auth);
        }
        throw new DcerpcException(new StringBuffer().append("DCERPC transport not supported: ").append(url).toString());
    }

    public void sendrecv(DcerpcMessage msg) throws DcerpcException, IOException {
        if (this.state == 0) {
            this.state = 1;
            sendrecv(new DcerpcBind(this.binding, this));
        }
        boolean isDirect = msg instanceof DcerpcBind;
        try {
            byte[] stub = BufferCache.getBuffer();
            try {
                NdrBuffer buf = new NdrBuffer(stub, 0);
                msg.flags = 3;
                msg.call_id = call_id;
                msg.encode(buf);
                int tot = buf.getLength();
                int off = 0;
                while (off < tot) {
                    int i = call_id;
                    call_id = i + 1;
                    msg.call_id = i;
                    if (tot - off > this.max_xmit) {
                        throw new DcerpcException("Fragmented request PDUs currently not supported");
                    }
                    int n = tot - off;
                    doSendFragment(stub, off, n, isDirect);
                    off += n;
                }
                doReceiveFragment(stub, isDirect);
                buf.reset();
                msg.decode_header(buf);
                off = 24;
                if (msg.ptype == 2 && !msg.isFlagSet(2)) {
                    off = msg.length;
                }
                byte[] frag = null;
                NdrBuffer fbuf = null;
                while (!msg.isFlagSet(2)) {
                    if (frag == null) {
                        frag = new byte[this.max_recv];
                        fbuf = new NdrBuffer(frag, 0);
                    }
                    doReceiveFragment(frag, isDirect);
                    fbuf.reset();
                    msg.decode_header(fbuf);
                    int stub_frag_len = msg.length - 24;
                    if (off + stub_frag_len > stub.length) {
                        byte[] tmp = new byte[(off + stub_frag_len)];
                        System.arraycopy(stub, 0, tmp, 0, off);
                        stub = tmp;
                    }
                    System.arraycopy(frag, 24, stub, off, stub_frag_len);
                    off += stub_frag_len;
                }
                msg.decode(new NdrBuffer(stub, 0));
                DcerpcException de = msg.getResult();
                if (de != null) {
                    throw de;
                }
            } finally {
                BufferCache.releaseBuffer(stub);
            }
        } catch (InterruptedException ie) {
            throw new IOException(ie.getMessage());
        }
    }

    public String getServer() {
        if (this instanceof DcerpcPipeHandle) {
            return ((DcerpcPipeHandle) this).pipe.getServer();
        }
        return null;
    }

    public Principal getPrincipal() {
        if (this instanceof DcerpcPipeHandle) {
            return ((DcerpcPipeHandle) this).pipe.getPrincipal();
        }
        return null;
    }

    public String toString() {
        return this.binding.toString();
    }
}
