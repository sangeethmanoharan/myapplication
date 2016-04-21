package jcifs.ntlmssp;

import jcifs.Config;
import org.xbill.DNS.Type;

public abstract class NtlmMessage implements NtlmFlags {
    protected static final byte[] NTLMSSP_SIGNATURE = new byte[]{(byte) 78, (byte) 84, (byte) 76, (byte) 77, (byte) 83, (byte) 83, (byte) 80, (byte) 0};
    private static final String OEM_ENCODING = Config.getProperty("jcifs.encoding", "Cp850");
    private int flags;

    public abstract byte[] toByteArray();

    public int getFlags() {
        return this.flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public boolean getFlag(int flag) {
        return (getFlags() & flag) != 0;
    }

    public void setFlag(int flag, boolean value) {
        setFlags(value ? getFlags() | flag : getFlags() & (flag ^ -1));
    }

    static int readULong(byte[] src, int index) {
        return (((src[index] & Type.ANY) | ((src[index + 1] & Type.ANY) << 8)) | ((src[index + 2] & Type.ANY) << 16)) | ((src[index + 3] & Type.ANY) << 24);
    }

    static int readUShort(byte[] src, int index) {
        return (src[index] & Type.ANY) | ((src[index + 1] & Type.ANY) << 8);
    }

    static byte[] readSecurityBuffer(byte[] src, int index) {
        int length = readUShort(src, index);
        byte[] buffer = new byte[length];
        System.arraycopy(src, readULong(src, index + 4), buffer, 0, length);
        return buffer;
    }

    static void writeULong(byte[] dest, int offset, int ulong) {
        dest[offset] = (byte) (ulong & Type.ANY);
        dest[offset + 1] = (byte) ((ulong >> 8) & Type.ANY);
        dest[offset + 2] = (byte) ((ulong >> 16) & Type.ANY);
        dest[offset + 3] = (byte) ((ulong >> 24) & Type.ANY);
    }

    static void writeUShort(byte[] dest, int offset, int ushort) {
        dest[offset] = (byte) (ushort & Type.ANY);
        dest[offset + 1] = (byte) ((ushort >> 8) & Type.ANY);
    }

    static void writeSecurityBuffer(byte[] dest, int offset, int bodyOffset, byte[] src) {
        int length;
        if (src != null) {
            length = src.length;
        } else {
            length = 0;
        }
        if (length != 0) {
            writeUShort(dest, offset, length);
            writeUShort(dest, offset + 2, length);
            writeULong(dest, offset + 4, bodyOffset);
            System.arraycopy(src, 0, dest, bodyOffset, length);
        }
    }

    static String getOEMEncoding() {
        return OEM_ENCODING;
    }
}
