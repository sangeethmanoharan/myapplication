package jcifs.smb;

import java.io.UnsupportedEncodingException;
import jcifs.Config;
import jcifs.util.Hexdump;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

class SmbComTreeConnectAndX extends AndXServerMessageBlock {
    private static final boolean DISABLE_PLAIN_TEXT_PASSWORDS = Config.getBoolean("jcifs.smb.client.disablePlainTextPasswords", true);
    private static byte[] batchLimits = new byte[]{(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 0};
    private boolean disconnectTid = false;
    private byte[] password;
    private int passwordLength;
    private String path;
    private String service;
    private SmbSession session;

    static {
        String s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.CheckDirectory");
        if (s != null) {
            batchLimits[0] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.CreateDirectory");
        if (s != null) {
            batchLimits[2] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.Delete");
        if (s != null) {
            batchLimits[3] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.DeleteDirectory");
        if (s != null) {
            batchLimits[4] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.OpenAndX");
        if (s != null) {
            batchLimits[5] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.Rename");
        if (s != null) {
            batchLimits[6] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.Transaction");
        if (s != null) {
            batchLimits[7] = Byte.parseByte(s);
        }
        s = Config.getProperty("jcifs.smb.client.TreeConnectAndX.QueryInformation");
        if (s != null) {
            batchLimits[8] = Byte.parseByte(s);
        }
    }

    SmbComTreeConnectAndX(SmbSession session, String path, String service, ServerMessageBlock andx) {
        super(andx);
        this.session = session;
        this.path = path;
        this.service = service;
        this.command = (byte) 117;
    }

    int getBatchLimit(byte command) {
        switch (command & Type.ANY) {
            case Tokenizer.EOF /*0*/:
                return batchLimits[2];
            case Zone.PRIMARY /*1*/:
                return batchLimits[4];
            case Protocol.TCP /*6*/:
                return batchLimits[3];
            case Service.ECHO /*7*/:
                return batchLimits[6];
            case Protocol.EGP /*8*/:
                return batchLimits[8];
            case Protocol.CHAOS /*16*/:
                return batchLimits[0];
            case Service.TIME /*37*/:
                return batchLimits[7];
            case Service.MPM /*45*/:
                return batchLimits[5];
            default:
                return 0;
        }
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        byte b = (byte) 1;
        if (this.session.transport.server.security != 0 || (!this.session.auth.hashesExternal && this.session.auth.password.length() <= 0)) {
            this.passwordLength = 1;
        } else if (this.session.transport.server.encryptedPasswords) {
            this.password = this.session.auth.getAnsiHash(this.session.transport.server.encryptionKey);
            this.passwordLength = this.password.length;
        } else if (DISABLE_PLAIN_TEXT_PASSWORDS) {
            throw new RuntimeException("Plain text passwords are disabled");
        } else {
            this.password = new byte[((this.session.auth.password.length() + 1) * 2)];
            this.passwordLength = writeString(this.session.auth.password, this.password, 0);
        }
        int dstIndex2 = dstIndex + 1;
        if (!this.disconnectTid) {
            b = (byte) 0;
        }
        dst[dstIndex] = b;
        dstIndex = dstIndex2 + 1;
        dst[dstIndex2] = (byte) 0;
        ServerMessageBlock.writeInt2((long) this.passwordLength, dst, dstIndex);
        return 4;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;
        if (this.session.transport.server.security != 0 || (!this.session.auth.hashesExternal && this.session.auth.password.length() <= 0)) {
            int dstIndex2 = dstIndex + 1;
            dst[dstIndex] = (byte) 0;
            dstIndex = dstIndex2;
        } else {
            System.arraycopy(this.password, 0, dst, dstIndex, this.passwordLength);
            dstIndex += this.passwordLength;
        }
        dstIndex += writeString(this.path, dst, dstIndex);
        try {
            System.arraycopy(this.service.getBytes("ASCII"), 0, dst, dstIndex, this.service.length());
            dstIndex += this.service.length();
            dstIndex2 = dstIndex + 1;
            dst[dstIndex] = (byte) 0;
            dstIndex = dstIndex2;
            return dstIndex2 - start;
        } catch (UnsupportedEncodingException e) {
            return 0;
        }
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbComTreeConnectAndX[").append(super.toString()).append(",disconnectTid=").append(this.disconnectTid).append(",passwordLength=").append(this.passwordLength).append(",password=").append(Hexdump.toHexString(this.password, this.passwordLength, 0)).append(",path=").append(this.path).append(",service=").append(this.service).append("]").toString());
    }
}
