package jcifs.smb;

import java.security.MessageDigest;
import jcifs.util.Hexdump;
import jcifs.util.LogStream;
import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

public class SigningDigest implements SmbConstants {
    static LogStream log = LogStream.getInstance();
    private MessageDigest digest;
    private byte[] macSigningKey;
    private int signSequence;
    private int updates;

    public SigningDigest(SmbTransport transport, NtlmPasswordAuthentication auth) throws SmbException {
        LogStream logStream;
        try {
            this.digest = MessageDigest.getInstance("MD5");
            try {
                switch (SmbConstants.LM_COMPATIBILITY) {
                    case Tokenizer.EOF /*0*/:
                    case Zone.PRIMARY /*1*/:
                    case Zone.SECONDARY /*2*/:
                        this.macSigningKey = new byte[40];
                        auth.getUserSessionKey(transport.server.encryptionKey, this.macSigningKey, 0);
                        System.arraycopy(auth.getUnicodeHash(transport.server.encryptionKey), 0, this.macSigningKey, 16, 24);
                        break;
                    case Protocol.GGP /*3*/:
                    case Type.MF /*4*/:
                    case Service.RJE /*5*/:
                        this.macSigningKey = new byte[16];
                        auth.getUserSessionKey(transport.server.encryptionKey, this.macSigningKey, 0);
                        break;
                    default:
                        this.macSigningKey = new byte[40];
                        auth.getUserSessionKey(transport.server.encryptionKey, this.macSigningKey, 0);
                        System.arraycopy(auth.getUnicodeHash(transport.server.encryptionKey), 0, this.macSigningKey, 16, 24);
                        break;
                }
                logStream = log;
                if (LogStream.level >= 5) {
                    log.println(new StringBuffer().append("LM_COMPATIBILITY=").append(SmbConstants.LM_COMPATIBILITY).toString());
                    Hexdump.hexdump(log, this.macSigningKey, 0, this.macSigningKey.length);
                }
            } catch (Throwable ex) {
                throw new SmbException(BuildConfig.VERSION_NAME, ex);
            }
        } catch (Throwable ex2) {
            logStream = log;
            if (LogStream.level > 0) {
                ex2.printStackTrace(log);
            }
            throw new SmbException("MD5", ex2);
        }
    }

    public void update(byte[] input, int offset, int len) {
        LogStream logStream = log;
        if (LogStream.level >= 5) {
            log.println(new StringBuffer().append("update: ").append(this.updates).append(" ").append(offset).append(":").append(len).toString());
            Hexdump.hexdump(log, input, offset, Math.min(len, KEYRecord.OWNER_ZONE));
            log.flush();
        }
        if (len != 0) {
            this.digest.update(input, offset, len);
            this.updates++;
        }
    }

    public byte[] digest() {
        byte[] b = this.digest.digest();
        LogStream logStream = log;
        if (LogStream.level >= 5) {
            log.println("digest: ");
            Hexdump.hexdump(log, b, 0, b.length);
            log.flush();
        }
        this.updates = 0;
        return b;
    }

    void sign(byte[] data, int offset, int length, ServerMessageBlock request, ServerMessageBlock response) {
        request.signSeq = this.signSequence;
        if (response != null) {
            response.signSeq = this.signSequence + 1;
            response.verifyFailed = false;
        }
        try {
            update(this.macSigningKey, 0, this.macSigningKey.length);
            int index = offset + 14;
            for (int i = 0; i < 8; i++) {
                data[index + i] = (byte) 0;
            }
            ServerMessageBlock.writeInt4((long) this.signSequence, data, index);
            update(data, offset, length);
            System.arraycopy(digest(), 0, data, index, 8);
            this.signSequence += 2;
        } catch (Exception ex) {
            LogStream logStream = log;
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
            this.signSequence += 2;
        } catch (Throwable th) {
            this.signSequence += 2;
        }
    }

    boolean verify(byte[] data, int offset, ServerMessageBlock response) {
        update(this.macSigningKey, 0, this.macSigningKey.length);
        int index = offset;
        update(data, index, 14);
        index += 14;
        byte[] sequence = new byte[8];
        ServerMessageBlock.writeInt4((long) response.signSeq, sequence, 0);
        update(sequence, 0, sequence.length);
        index += 8;
        if (response.command == (byte) 46) {
            SmbComReadAndXResponse raxr = (SmbComReadAndXResponse) response;
            update(data, index, ((response.length - raxr.dataLength) - 14) - 8);
            update(raxr.b, raxr.off, raxr.dataLength);
        } else {
            update(data, index, (response.length - 14) - 8);
        }
        byte[] signature = digest();
        for (int i = 0; i < 8; i++) {
            if (signature[i] != data[(offset + 14) + i]) {
                LogStream logStream = log;
                if (LogStream.level >= 2) {
                    log.println("signature verification failure");
                    Hexdump.hexdump(log, signature, 0, 8);
                    Hexdump.hexdump(log, data, offset + 14, 8);
                }
                response.verifyFailed = true;
                return true;
            }
        }
        response.verifyFailed = false;
        return false;
    }

    public String toString() {
        return new StringBuffer().append("LM_COMPATIBILITY=").append(SmbConstants.LM_COMPATIBILITY).append(" MacSigningKey=").append(Hexdump.toHexString(this.macSigningKey, 0, this.macSigningKey.length)).toString();
    }
}
