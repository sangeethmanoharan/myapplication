package jcifs.smb;

import java.util.Arrays;
import jcifs.Config;

class SmbComSessionSetupAndX extends AndXServerMessageBlock {
    private static final int BATCH_LIMIT = Config.getInt("jcifs.smb.client.SessionSetupAndX.TreeConnectAndX", 1);
    private static final boolean DISABLE_PLAIN_TEXT_PASSWORDS = Config.getBoolean("jcifs.smb.client.disablePlainTextPasswords", true);
    private String accountName;
    private byte[] accountPassword;
    NtlmPasswordAuthentication auth;
    private int passwordLength;
    private String primaryDomain;
    SmbSession session;
    private int sessionKey;
    private byte[] unicodePassword;
    private int unicodePasswordLength;

    SmbComSessionSetupAndX(SmbSession session, ServerMessageBlock andx) throws SmbException {
        super(andx);
        this.command = (byte) 115;
        this.session = session;
        this.auth = session.auth;
        if (this.auth.hashesExternal && !Arrays.equals(this.auth.challenge, session.transport.server.encryptionKey)) {
            throw new SmbAuthException(NtStatus.NT_STATUS_ACCESS_VIOLATION);
        }
    }

    int getBatchLimit(byte command) {
        return command == (byte) 117 ? BATCH_LIMIT : 0;
    }

    int writeParameterWordsWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;
        if (this.session.transport.server.security != 1 || (!this.auth.hashesExternal && this.auth.password.length() <= 0)) {
            this.unicodePasswordLength = 0;
            this.passwordLength = 0;
        } else if (this.session.transport.server.encryptedPasswords) {
            this.accountPassword = this.auth.getAnsiHash(this.session.transport.server.encryptionKey);
            this.passwordLength = this.accountPassword.length;
            this.unicodePassword = this.auth.getUnicodeHash(this.session.transport.server.encryptionKey);
            this.unicodePasswordLength = this.unicodePassword.length;
            if (this.unicodePasswordLength == 0 && this.passwordLength == 0) {
                throw new RuntimeException("Null setup prohibited.");
            }
        } else if (DISABLE_PLAIN_TEXT_PASSWORDS) {
            throw new RuntimeException("Plain text passwords are disabled");
        } else if (this.useUnicode) {
            password = this.auth.getPassword();
            this.accountPassword = new byte[0];
            this.passwordLength = 0;
            this.unicodePassword = new byte[((password.length() + 1) * 2)];
            this.unicodePasswordLength = writeString(password, this.unicodePassword, 0);
        } else {
            password = this.auth.getPassword();
            this.accountPassword = new byte[((password.length() + 1) * 2)];
            this.passwordLength = writeString(password, this.accountPassword, 0);
            this.unicodePassword = new byte[0];
            this.unicodePasswordLength = 0;
        }
        this.sessionKey = this.session.transport.sessionKey;
        ServerMessageBlock.writeInt2((long) this.session.transport.snd_buf_size, dst, dstIndex);
        dstIndex += 2;
        ServerMessageBlock.writeInt2((long) this.session.transport.maxMpxCount, dst, dstIndex);
        dstIndex += 2;
        SmbTransport smbTransport = this.session.transport;
        ServerMessageBlock.writeInt2(1, dst, dstIndex);
        dstIndex += 2;
        ServerMessageBlock.writeInt4((long) this.sessionKey, dst, dstIndex);
        dstIndex += 4;
        ServerMessageBlock.writeInt2((long) this.passwordLength, dst, dstIndex);
        dstIndex += 2;
        ServerMessageBlock.writeInt2((long) this.unicodePasswordLength, dst, dstIndex);
        dstIndex += 2;
        int dstIndex2 = dstIndex + 1;
        dst[dstIndex] = (byte) 0;
        dstIndex = dstIndex2 + 1;
        dst[dstIndex2] = (byte) 0;
        dstIndex2 = dstIndex + 1;
        dst[dstIndex] = (byte) 0;
        dstIndex = dstIndex2 + 1;
        dst[dstIndex2] = (byte) 0;
        ServerMessageBlock.writeInt4((long) this.session.transport.capabilities, dst, dstIndex);
        return (dstIndex + 4) - start;
    }

    int writeBytesWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;
        this.accountName = this.useUnicode ? this.auth.username : this.auth.username.toUpperCase();
        this.primaryDomain = this.auth.domain.toUpperCase();
        if (this.session.transport.server.security == 1 && (this.auth.hashesExternal || this.auth.password.length() > 0)) {
            System.arraycopy(this.accountPassword, 0, dst, dstIndex, this.passwordLength);
            dstIndex += this.passwordLength;
            if (!(this.session.transport.server.encryptedPasswords || !this.useUnicode || (dstIndex - this.headerStart) % 2 == 0)) {
                int dstIndex2 = dstIndex + 1;
                dst[dstIndex] = (byte) 0;
                dstIndex = dstIndex2;
            }
            System.arraycopy(this.unicodePassword, 0, dst, dstIndex, this.unicodePasswordLength);
            dstIndex += this.unicodePasswordLength;
        }
        dstIndex += writeString(this.accountName, dst, dstIndex);
        dstIndex += writeString(this.primaryDomain, dst, dstIndex);
        SmbTransport smbTransport = this.session.transport;
        dstIndex += writeString(SmbConstants.NATIVE_OS, dst, dstIndex);
        smbTransport = this.session.transport;
        return (dstIndex + writeString(SmbConstants.NATIVE_LANMAN, dst, dstIndex)) - start;
    }

    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }

    public String toString() {
        StringBuffer append = new StringBuffer().append("SmbComSessionSetupAndX[").append(super.toString()).append(",snd_buf_size=").append(this.session.transport.snd_buf_size).append(",maxMpxCount=").append(this.session.transport.maxMpxCount).append(",VC_NUMBER=");
        SmbTransport smbTransport = this.session.transport;
        append = append.append(1).append(",sessionKey=").append(this.sessionKey).append(",passwordLength=").append(this.passwordLength).append(",unicodePasswordLength=").append(this.unicodePasswordLength).append(",capabilities=").append(this.session.transport.capabilities).append(",accountName=").append(this.accountName).append(",primaryDomain=").append(this.primaryDomain).append(",NATIVE_OS=");
        smbTransport = this.session.transport;
        append = append.append(SmbConstants.NATIVE_OS).append(",NATIVE_LANMAN=");
        smbTransport = this.session.transport;
        return new String(append.append(SmbConstants.NATIVE_LANMAN).append("]").toString());
    }
}
