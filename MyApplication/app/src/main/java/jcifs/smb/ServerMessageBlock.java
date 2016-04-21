package jcifs.smb;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import jcifs.util.Encdec;
import jcifs.util.Hexdump;
import jcifs.util.LogStream;
import jcifs.util.transport.Request;
import jcifs.util.transport.Response;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

abstract class ServerMessageBlock extends Response implements SmbConstants, Request {
    static final byte SMB_COM_CHECK_DIRECTORY = (byte) 16;
    static final byte SMB_COM_CLOSE = (byte) 4;
    static final byte SMB_COM_CREATE_DIRECTORY = (byte) 0;
    static final byte SMB_COM_DELETE = (byte) 6;
    static final byte SMB_COM_DELETE_DIRECTORY = (byte) 1;
    static final byte SMB_COM_ECHO = (byte) 43;
    static final byte SMB_COM_FIND_CLOSE2 = (byte) 52;
    static final byte SMB_COM_LOGOFF_ANDX = (byte) 116;
    static final byte SMB_COM_MOVE = (byte) 42;
    static final byte SMB_COM_NEGOTIATE = (byte) 114;
    static final byte SMB_COM_NT_CREATE_ANDX = (byte) -94;
    static final byte SMB_COM_NT_TRANSACT = (byte) -96;
    static final byte SMB_COM_NT_TRANSACT_SECONDARY = (byte) -95;
    static final byte SMB_COM_OPEN_ANDX = (byte) 45;
    static final byte SMB_COM_QUERY_INFORMATION = (byte) 8;
    static final byte SMB_COM_READ_ANDX = (byte) 46;
    static final byte SMB_COM_RENAME = (byte) 7;
    static final byte SMB_COM_SESSION_SETUP_ANDX = (byte) 115;
    static final byte SMB_COM_TRANSACTION = (byte) 37;
    static final byte SMB_COM_TRANSACTION2 = (byte) 50;
    static final byte SMB_COM_TRANSACTION_SECONDARY = (byte) 38;
    static final byte SMB_COM_TREE_CONNECT_ANDX = (byte) 117;
    static final byte SMB_COM_TREE_DISCONNECT = (byte) 113;
    static final byte SMB_COM_WRITE = (byte) 11;
    static final byte SMB_COM_WRITE_ANDX = (byte) 47;
    static final byte[] header = new byte[]{(byte) -1, (byte) 83, (byte) 77, (byte) 66, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY, SMB_COM_CREATE_DIRECTORY};
    static LogStream log = LogStream.getInstance();
    NtlmPasswordAuthentication auth = null;
    int batchLevel = 0;
    int byteCount;
    byte command;
    SigningDigest digest = null;
    int errorCode;
    byte flags = (byte) 24;
    int flags2;
    int headerStart;
    int length;
    int mid;
    String path;
    int pid = SmbConstants.PID;
    boolean received;
    ServerMessageBlock response;
    long responseTimeout = 1;
    int signSeq;
    int tid;
    int uid;
    boolean useUnicode;
    boolean verifyFailed;
    int wordCount;

    abstract int readBytesWireFormat(byte[] bArr, int i);

    abstract int readParameterWordsWireFormat(byte[] bArr, int i);

    abstract int writeBytesWireFormat(byte[] bArr, int i);

    abstract int writeParameterWordsWireFormat(byte[] bArr, int i);

    static void writeInt2(long val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) ((int) val);
        dst[dstIndex + 1] = (byte) ((int) (val >> 8));
    }

    static void writeInt4(long val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dst[dstIndex + 1] = (byte) ((int) (val >> 8));
    }

    static int readInt2(byte[] src, int srcIndex) {
        return (src[srcIndex] & Type.ANY) + ((src[srcIndex + 1] & Type.ANY) << 8);
    }

    static int readInt4(byte[] src, int srcIndex) {
        return (((src[srcIndex] & Type.ANY) + ((src[srcIndex + 1] & Type.ANY) << 8)) + ((src[srcIndex + 2] & Type.ANY) << 16)) + ((src[srcIndex + 3] & Type.ANY) << 24);
    }

    static long readInt8(byte[] src, int srcIndex) {
        return (((long) readInt4(src, srcIndex)) & 4294967295L) + (((long) readInt4(src, srcIndex + 4)) << 32);
    }

    static void writeInt8(long val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dstIndex++;
        val >>= 8;
        dst[dstIndex] = (byte) ((int) val);
        dst[dstIndex + 1] = (byte) ((int) (val >> 8));
    }

    static long readTime(byte[] src, int srcIndex) {
        return (((((long) readInt4(src, srcIndex + 4)) << 32) | (((long) readInt4(src, srcIndex)) & 4294967295L)) / 10000) - Encdec.MILLISECONDS_BETWEEN_1970_AND_1601;
    }

    static void writeTime(long t, byte[] dst, int dstIndex) {
        if (t != 0) {
            t = (Encdec.MILLISECONDS_BETWEEN_1970_AND_1601 + t) * 10000;
        }
        writeInt8(t, dst, dstIndex);
    }

    static long readUTime(byte[] buffer, int bufferIndex) {
        return ((long) readInt4(buffer, bufferIndex)) * 1000;
    }

    static void writeUTime(long t, byte[] dst, int dstIndex) {
        if (t == 0 || t == -1) {
            writeInt4(-1, dst, dstIndex);
            return;
        }
        synchronized (SmbConstants.TZ) {
            if (SmbConstants.TZ.inDaylightTime(new Date())) {
                if (!SmbConstants.TZ.inDaylightTime(new Date(t))) {
                    t -= 3600000;
                }
            } else if (SmbConstants.TZ.inDaylightTime(new Date(t))) {
                t += 3600000;
            }
        }
        writeInt4((long) ((int) (t / 1000)), dst, dstIndex);
    }

    ServerMessageBlock() {
    }

    void reset() {
        this.flags = (byte) 24;
        this.flags2 = 0;
        this.errorCode = 0;
        this.received = false;
        this.digest = null;
    }

    int writeString(String str, byte[] dst, int dstIndex) {
        return writeString(str, dst, dstIndex, this.useUnicode);
    }

    int writeString(String str, byte[] dst, int dstIndex, boolean useUnicode) {
        UnsupportedEncodingException uee;
        int start = dstIndex;
        int dstIndex2;
        if (useUnicode) {
            try {
                if ((dstIndex - this.headerStart) % 2 != 0) {
                    dstIndex2 = dstIndex + 1;
                    try {
                        dst[dstIndex] = SMB_COM_CREATE_DIRECTORY;
                        dstIndex = dstIndex2;
                    } catch (UnsupportedEncodingException e) {
                        uee = e;
                        dstIndex = dstIndex2;
                        LogStream logStream = log;
                        if (LogStream.level > 1) {
                            uee.printStackTrace(log);
                        }
                        return dstIndex - start;
                    }
                }
                System.arraycopy(str.getBytes("UnicodeLittleUnmarked"), 0, dst, dstIndex, str.length() * 2);
                dstIndex += str.length() * 2;
                dstIndex2 = dstIndex + 1;
                dst[dstIndex] = SMB_COM_CREATE_DIRECTORY;
                dstIndex = dstIndex2 + 1;
                dst[dstIndex2] = SMB_COM_CREATE_DIRECTORY;
            } catch (UnsupportedEncodingException e2) {
                uee = e2;
                LogStream logStream2 = log;
                if (LogStream.level > 1) {
                    uee.printStackTrace(log);
                }
                return dstIndex - start;
            }
        }
        byte[] b = str.getBytes(SmbConstants.OEM_ENCODING);
        System.arraycopy(b, 0, dst, dstIndex, b.length);
        dstIndex += b.length;
        dstIndex2 = dstIndex + 1;
        dst[dstIndex] = SMB_COM_CREATE_DIRECTORY;
        dstIndex = dstIndex2;
        return dstIndex - start;
    }

    String readString(byte[] src, int srcIndex) {
        return readString(src, srcIndex, KEYRecord.OWNER_ZONE, this.useUnicode);
    }

    String readString(byte[] src, int srcIndex, int maxLen, boolean useUnicode) {
        int i = Flags.FLAG8;
        int len = 0;
        if (useUnicode) {
            try {
                if ((srcIndex - this.headerStart) % 2 != 0) {
                    srcIndex++;
                }
                do {
                    if (src[srcIndex + len] == (byte) 0 && src[(srcIndex + len) + 1] == (byte) 0) {
                        return new String(src, srcIndex, len, "UnicodeLittleUnmarked");
                    }
                    len += 2;
                } while (len <= maxLen);
                LogStream logStream = log;
                if (LogStream.level > 0) {
                    PrintStream printStream = System.err;
                    if (maxLen < Flags.FLAG8) {
                        i = maxLen + 8;
                    }
                    Hexdump.hexdump(printStream, src, srcIndex, i);
                }
                throw new RuntimeException("zero termination not found");
            } catch (UnsupportedEncodingException uee) {
                LogStream logStream2 = log;
                if (LogStream.level <= 1) {
                    return null;
                }
                uee.printStackTrace(log);
                return null;
            }
        }
        while (src[srcIndex + len] != (byte) 0) {
            len++;
            if (len > maxLen) {
                logStream = log;
                if (LogStream.level > 0) {
                    printStream = System.err;
                    if (maxLen < Flags.FLAG8) {
                        i = maxLen + 8;
                    }
                    Hexdump.hexdump(printStream, src, srcIndex, i);
                }
                throw new RuntimeException("zero termination not found");
            }
        }
        return new String(src, srcIndex, len, SmbConstants.OEM_ENCODING);
    }

    int stringWireLength(String str, int offset) {
        int len = str.length() + 1;
        if (!this.useUnicode) {
            return len;
        }
        len = (str.length() * 2) + 2;
        if (offset % 2 != 0) {
            return len + 1;
        }
        return len;
    }

    int readStringLength(byte[] src, int srcIndex, int max) {
        int len = 0;
        while (src[srcIndex + len] != (byte) 0) {
            int len2 = len + 1;
            if (len > max) {
                throw new RuntimeException(new StringBuffer().append("zero termination not found: ").append(this).toString());
            }
            len = len2;
        }
        return len;
    }

    int encode(byte[] dst, int dstIndex) {
        this.headerStart = dstIndex;
        int start = dstIndex;
        dstIndex += writeHeaderWireFormat(dst, dstIndex);
        this.wordCount = writeParameterWordsWireFormat(dst, dstIndex + 1);
        int dstIndex2 = dstIndex + 1;
        dst[dstIndex] = (byte) ((this.wordCount / 2) & Type.ANY);
        dstIndex = dstIndex2 + this.wordCount;
        this.wordCount /= 2;
        this.byteCount = writeBytesWireFormat(dst, dstIndex + 2);
        dstIndex2 = dstIndex + 1;
        dst[dstIndex] = (byte) (this.byteCount & Type.ANY);
        dstIndex = dstIndex2 + 1;
        dst[dstIndex2] = (byte) ((this.byteCount >> 8) & Type.ANY);
        this.length = (dstIndex + this.byteCount) - start;
        if (this.digest != null) {
            this.digest.sign(dst, this.headerStart, this.length, this, this.response);
        }
        return this.length;
    }

    int decode(byte[] buffer, int bufferIndex) {
        int n;
        this.headerStart = bufferIndex;
        int start = bufferIndex;
        bufferIndex += readHeaderWireFormat(buffer, bufferIndex);
        int bufferIndex2 = bufferIndex + 1;
        this.wordCount = buffer[bufferIndex];
        if (this.wordCount != 0) {
            n = readParameterWordsWireFormat(buffer, bufferIndex2);
            if (n != this.wordCount * 2) {
                LogStream logStream = log;
                if (LogStream.level >= 5) {
                    log.println(new StringBuffer().append("wordCount * 2=").append(this.wordCount * 2).append(" but readParameterWordsWireFormat returned ").append(n).toString());
                }
            }
            bufferIndex = bufferIndex2 + (this.wordCount * 2);
        } else {
            bufferIndex = bufferIndex2;
        }
        this.byteCount = readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        if (this.byteCount != 0) {
            n = readBytesWireFormat(buffer, bufferIndex);
            if (n != this.byteCount) {
                logStream = log;
                if (LogStream.level >= 5) {
                    log.println(new StringBuffer().append("byteCount=").append(this.byteCount).append(" but readBytesWireFormat returned ").append(n).toString());
                }
            }
            bufferIndex += this.byteCount;
        }
        this.length = bufferIndex - start;
        return this.length;
    }

    int writeHeaderWireFormat(byte[] dst, int dstIndex) {
        System.arraycopy(header, 0, dst, dstIndex, header.length);
        dst[dstIndex + 4] = this.command;
        dst[dstIndex + 9] = this.flags;
        writeInt2((long) this.flags2, dst, (dstIndex + 9) + 1);
        dstIndex += 24;
        writeInt2((long) this.tid, dst, dstIndex);
        writeInt2((long) this.pid, dst, dstIndex + 2);
        writeInt2((long) this.uid, dst, dstIndex + 4);
        writeInt2((long) this.mid, dst, dstIndex + 6);
        return 32;
    }

    int readHeaderWireFormat(byte[] buffer, int bufferIndex) {
        this.command = buffer[bufferIndex + 4];
        this.errorCode = readInt4(buffer, bufferIndex + 5);
        this.flags = buffer[bufferIndex + 9];
        this.flags2 = readInt2(buffer, (bufferIndex + 9) + 1);
        this.tid = readInt2(buffer, bufferIndex + 24);
        this.pid = readInt2(buffer, (bufferIndex + 24) + 2);
        this.uid = readInt2(buffer, (bufferIndex + 24) + 4);
        this.mid = readInt2(buffer, (bufferIndex + 24) + 6);
        return 32;
    }

    boolean isResponse() {
        return (this.flags & Flags.FLAG8) == Flags.FLAG8;
    }

    public int hashCode() {
        return this.mid;
    }

    public boolean equals(Object obj) {
        return (obj instanceof ServerMessageBlock) && ((ServerMessageBlock) obj).mid == this.mid;
    }

    public String toString() {
        String c;
        String str;
        switch (this.command) {
            case (byte) -96:
                c = "SMB_COM_NT_TRANSACT";
                break;
            case (byte) -95:
                c = "SMB_COM_NT_TRANSACT_SECONDARY";
                break;
            case (byte) -94:
                c = "SMB_COM_NT_CREATE_ANDX";
                break;
            case Tokenizer.EOF /*0*/:
                c = "SMB_COM_CREATE_DIRECTORY";
                break;
            case Zone.PRIMARY /*1*/:
                c = "SMB_COM_DELETE_DIRECTORY";
                break;
            case Type.MF /*4*/:
                c = "SMB_COM_CLOSE";
                break;
            case Protocol.TCP /*6*/:
                c = "SMB_COM_DELETE";
                break;
            case Service.ECHO /*7*/:
                c = "SMB_COM_RENAME";
                break;
            case Protocol.EGP /*8*/:
                c = "SMB_COM_QUERY_INFORMATION";
                break;
            case Protocol.CHAOS /*16*/:
                c = "SMB_COM_CHECK_DIRECTORY";
                break;
            case Service.TIME /*37*/:
                c = "SMB_COM_TRANSACTION";
                break;
            case Type.A6 /*38*/:
                c = "SMB_COM_TRANSACTION_SECONDARY";
                break;
            case Service.NAMESERVER /*42*/:
                c = "SMB_COM_MOVE";
                break;
            case Service.NICNAME /*43*/:
                c = "SMB_COM_ECHO";
                break;
            case Service.MPM /*45*/:
                c = "SMB_COM_OPEN_ANDX";
                break;
            case Service.MPM_SND /*46*/:
                c = "SMB_COM_READ_ANDX";
                break;
            case Service.NI_FTP /*47*/:
                c = "SMB_COM_WRITE_ANDX";
                break;
            case Type.NSEC3 /*50*/:
                c = "SMB_COM_TRANSACTION2";
                break;
            case Type.TLSA /*52*/:
                c = "SMB_COM_FIND_CLOSE2";
                break;
            case Service.AUTH /*113*/:
                c = "SMB_COM_TREE_DISCONNECT";
                break;
            case (byte) 114:
                c = "SMB_COM_NEGOTIATE";
                break;
            case Service.SFTP /*115*/:
                c = "SMB_COM_SESSION_SETUP_ANDX";
                break;
            case (byte) 116:
                c = "SMB_COM_LOGOFF_ANDX";
                break;
            case Service.UUCP_PATH /*117*/:
                c = "SMB_COM_TREE_CONNECT_ANDX";
                break;
            default:
                c = "UNKNOWN";
                break;
        }
        if (this.errorCode == 0) {
            str = "0";
        } else {
            str = SmbException.getMessageByCode(this.errorCode);
        }
        return new String(new StringBuffer().append("command=").append(c).append(",received=").append(this.received).append(",errorCode=").append(str).append(",flags=0x").append(Hexdump.toHexString(this.flags & Type.ANY, 4)).append(",flags2=0x").append(Hexdump.toHexString(this.flags2, 4)).append(",signSeq=").append(this.signSeq).append(",tid=").append(this.tid).append(",pid=").append(this.pid).append(",uid=").append(this.uid).append(",mid=").append(this.mid).append(",wordCount=").append(this.wordCount).append(",byteCount=").append(this.byteCount).toString());
    }
}
