package jcifs.smb;

import jcifs.util.Hexdump;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;

public class ACE {
    public static final int DELETE = 65536;
    public static final int FILE_APPEND_DATA = 4;
    public static final int FILE_DELETE = 64;
    public static final int FILE_EXECUTE = 32;
    public static final int FILE_READ_ATTRIBUTES = 128;
    public static final int FILE_READ_DATA = 1;
    public static final int FILE_READ_EA = 8;
    public static final int FILE_WRITE_ATTRIBUTES = 256;
    public static final int FILE_WRITE_DATA = 2;
    public static final int FILE_WRITE_EA = 16;
    public static final int FLAGS_CONTAINER_INHERIT = 2;
    public static final int FLAGS_INHERITED = 16;
    public static final int FLAGS_INHERIT_ONLY = 8;
    public static final int FLAGS_NO_PROPAGATE = 4;
    public static final int FLAGS_OBJECT_INHERIT = 1;
    public static final int GENERIC_ALL = 268435456;
    public static final int GENERIC_EXECUTE = 536870912;
    public static final int GENERIC_READ = Integer.MIN_VALUE;
    public static final int GENERIC_WRITE = 1073741824;
    public static final int READ_CONTROL = 131072;
    public static final int SYNCHRONIZE = 1048576;
    public static final int WRITE_DAC = 262144;
    public static final int WRITE_OWNER = 524288;
    int access;
    boolean allow;
    int flags;
    SID sid;

    public boolean isAllow() {
        return this.allow;
    }

    public boolean isInherited() {
        return (this.flags & FLAGS_INHERITED) != 0;
    }

    public int getFlags() {
        return this.flags;
    }

    public String getApplyToText() {
        switch (this.flags & 11) {
            case Tokenizer.EOF /*0*/:
                return "This folder only";
            case FLAGS_OBJECT_INHERIT /*1*/:
                return "This folder and files";
            case FLAGS_CONTAINER_INHERIT /*2*/:
                return "This folder and subfolders";
            case Protocol.GGP /*3*/:
                return "This folder, subfolders and files";
            case Service.DISCARD /*9*/:
                return "Files only";
            case Protocol.BBN_RCC_MON /*10*/:
                return "Subfolders only";
            case Service.USERS /*11*/:
                return "Subfolders and files only";
            default:
                return "Invalid";
        }
    }

    public int getAccessMask() {
        return this.access;
    }

    public SID getSID() {
        return this.sid;
    }

    int decode(byte[] buf, int bi) {
        int bi2 = bi + FLAGS_OBJECT_INHERIT;
        this.allow = buf[bi] == (byte) 0;
        bi = bi2 + FLAGS_OBJECT_INHERIT;
        this.flags = buf[bi2] & Type.ANY;
        int size = ServerMessageBlock.readInt2(buf, bi);
        bi += FLAGS_CONTAINER_INHERIT;
        this.access = ServerMessageBlock.readInt4(buf, bi);
        this.sid = new SID(buf, bi + FLAGS_NO_PROPAGATE);
        return size;
    }

    void appendCol(StringBuffer sb, String str, int width) {
        sb.append(str);
        int count = width - str.length();
        for (int i = 0; i < count; i += FLAGS_OBJECT_INHERIT) {
            sb.append(' ');
        }
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(isAllow() ? "Allow " : "Deny  ");
        appendCol(sb, this.sid.toDisplayString(), 25);
        sb.append(" 0x").append(Hexdump.toHexString(this.access, (int) FLAGS_INHERIT_ONLY)).append(' ');
        sb.append(isInherited() ? "Inherited " : "Direct    ");
        appendCol(sb, getApplyToText(), 34);
        return sb.toString();
    }
}
