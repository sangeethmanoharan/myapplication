package jcifs.smb;

import jcifs.Config;
import org.xbill.DNS.Message;

public class BufferCache {
    private static final int MAX_BUFFERS = Config.getInt("jcifs.smb.maxBuffers", 16);
    static Object[] cache = new Object[MAX_BUFFERS];
    private static int freeBuffers = 0;
    private static int numBuffers = 0;

    private static byte[] getBuffer0() {
        byte[] buf;
        if (freeBuffers > 0) {
            for (int i = 0; i < MAX_BUFFERS; i++) {
                if (cache[i] != null) {
                    buf = cache[i];
                    cache[i] = null;
                    freeBuffers--;
                    return buf;
                }
            }
        }
        buf = new byte[Message.MAXLENGTH];
        numBuffers++;
        return buf;
    }

    static void getBuffers(SmbComTransaction req, SmbComTransactionResponse rsp) throws InterruptedException {
        synchronized (cache) {
            while (freeBuffers + (MAX_BUFFERS - numBuffers) < 2) {
                cache.wait();
            }
            req.txn_buf = getBuffer0();
            rsp.txn_buf = getBuffer0();
        }
    }

    public static byte[] getBuffer() throws InterruptedException {
        byte[] buffer0;
        synchronized (cache) {
            while (freeBuffers + (MAX_BUFFERS - numBuffers) < 1) {
                cache.wait();
            }
            buffer0 = getBuffer0();
        }
        return buffer0;
    }

    public static void releaseBuffer(byte[] buf) {
        synchronized (cache) {
            for (int i = 0; i < MAX_BUFFERS; i++) {
                if (cache[i] == null) {
                    cache[i] = buf;
                    freeBuffers++;
                    cache.notify();
                    return;
                }
            }
        }
    }
}
