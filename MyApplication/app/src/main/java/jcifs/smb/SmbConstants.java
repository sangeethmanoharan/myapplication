package jcifs.smb;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.TimeZone;
import jcifs.Config;

interface SmbConstants {
    public static final int ATTR_ARCHIVE = 32;
    public static final int ATTR_COMPRESSED = 2048;
    public static final int ATTR_DIRECTORY = 16;
    public static final int ATTR_HIDDEN = 2;
    public static final int ATTR_NORMAL = 128;
    public static final int ATTR_READONLY = 1;
    public static final int ATTR_SYSTEM = 4;
    public static final int ATTR_TEMPORARY = 256;
    public static final int ATTR_VOLUME = 8;
    public static final int CAPABILITIES = Config.getInt("jcifs.smb.client.capabilities", DEFAULT_CAPABILITIES);
    public static final int CAP_DFS = 4096;
    public static final int CAP_LARGE_FILES = 8;
    public static final int CAP_LEVEL_II_OPLOCKS = 128;
    public static final int CAP_LOCK_AND_READ = 256;
    public static final int CAP_MPX_MODE = 2;
    public static final int CAP_NONE = 0;
    public static final int CAP_NT_FIND = 512;
    public static final int CAP_NT_SMBS = 16;
    public static final int CAP_RAW_MODE = 1;
    public static final int CAP_RPC_REMOTE_APIS = 32;
    public static final int CAP_STATUS32 = 64;
    public static final int CAP_UNICODE = 4;
    public static final int CMD_OFFSET = 4;
    public static final LinkedList CONNECTIONS = new LinkedList();
    public static final int DEFAULT_CAPABILITIES;
    public static final int DEFAULT_FLAGS2 = ((USE_UNICODE ? FLAGS2_UNICODE : SSN_LIMIT) | ((((USE_EXTSEC ? FLAGS2_EXTENDED_SECURITY_NEGOTIATION : SSN_LIMIT) | 3) | (SIGNPREF ? FLAGS_COPY_TARGET_MODE_ASCII : SSN_LIMIT)) | (USE_NTSTATUS ? FLAGS2_STATUS32 : SSN_LIMIT)));
    public static final int DEFAULT_MAX_MPX_COUNT = 10;
    public static final int DEFAULT_PORT = 445;
    public static final int DEFAULT_RCV_BUF_SIZE = 60416;
    public static final int DEFAULT_RESPONSE_TIMEOUT = 30000;
    public static final int DEFAULT_SND_BUF_SIZE = 16644;
    public static final int DEFAULT_SO_TIMEOUT = 35000;
    public static final int DEFAULT_SSN_LIMIT = 250;
    public static final int DELETE = 65536;
    public static final int ERROR_CODE_OFFSET = 5;
    public static final int FILE_APPEND_DATA = 4;
    public static final int FILE_DELETE = 64;
    public static final int FILE_EXECUTE = 32;
    public static final int FILE_READ_ATTRIBUTES = 128;
    public static final int FILE_READ_DATA = 1;
    public static final int FILE_READ_EA = 8;
    public static final int FILE_WRITE_ATTRIBUTES = 256;
    public static final int FILE_WRITE_DATA = 2;
    public static final int FILE_WRITE_EA = 16;
    public static final int FLAGS2 = Config.getInt("jcifs.smb.client.flags2", DEFAULT_FLAGS2);
    public static final int FLAGS2_EXTENDED_ATTRIBUTES = 2;
    public static final int FLAGS2_EXTENDED_SECURITY_NEGOTIATION = 2048;
    public static final int FLAGS2_LONG_FILENAMES = 1;
    public static final int FLAGS2_NONE = 0;
    public static final int FLAGS2_PERMIT_READ_IF_EXECUTE_PERM = 8192;
    public static final int FLAGS2_RESOLVE_PATHS_IN_DFS = 4096;
    public static final int FLAGS2_SECURITY_SIGNATURES = 4;
    public static final int FLAGS2_STATUS32 = 16384;
    public static final int FLAGS2_UNICODE = 32768;
    public static final int FLAGS_COPY_SOURCE_MODE_ASCII = 8;
    public static final int FLAGS_COPY_TARGET_MODE_ASCII = 4;
    public static final int FLAGS_LOCK_AND_READ_WRITE_AND_UNLOCK = 1;
    public static final int FLAGS_NONE = 0;
    public static final int FLAGS_NOTIFY_OF_MODIFY_ACTION = 64;
    public static final int FLAGS_OFFSET = 9;
    public static final int FLAGS_OPLOCK_REQUESTED_OR_GRANTED = 32;
    public static final int FLAGS_PATH_NAMES_CANONICALIZED = 16;
    public static final int FLAGS_PATH_NAMES_CASELESS = 8;
    public static final int FLAGS_RECEIVE_BUFFER_POSTED = 2;
    public static final int FLAGS_RESPONSE = 128;
    public static final int FLAGS_TARGET_MUST_BE_DIRECTORY = 2;
    public static final int FLAGS_TARGET_MUST_BE_FILE = 1;
    public static final int FLAGS_TREE_COPY = 32;
    public static final int FLAGS_VERIFY_ALL_WRITES = 16;
    public static final boolean FORCE_UNICODE = Config.getBoolean("jcifs.smb.client.useUnicode", USE_UNICODE);
    public static final int GENERIC_ALL = 268435456;
    public static final int GENERIC_EXECUTE = 536870912;
    public static final int GENERIC_READ = Integer.MIN_VALUE;
    public static final int GENERIC_WRITE = 1073741824;
    public static final int HEADER_LENGTH = 32;
    public static final InetAddress LADDR = Config.getLocalHost();
    public static final int LM_COMPATIBILITY = Config.getInt("jcifs.smb.lmCompatibility", SSN_LIMIT);
    public static final int LPORT = Config.getInt("jcifs.smb.client.lport", SSN_LIMIT);
    public static final int MAX_MPX_COUNT = Config.getInt("jcifs.smb.client.maxMpxCount", DEFAULT_MAX_MPX_COUNT);
    public static final long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;
    public static final String NATIVE_LANMAN = Config.getProperty("jcifs.smb.client.nativeLanMan", "jCIFS");
    public static final String NATIVE_OS = Config.getProperty("jcifs.smb.client.nativeOs", System.getProperty("os.name"));
    public static final String NETBIOS_HOSTNAME = Config.getProperty("jcifs.netbios.hostname", null);
    public static final SmbTransport NULL_TRANSPORT = new SmbTransport(null, SSN_LIMIT, null, SSN_LIMIT);
    public static final String OEM_ENCODING = Config.getProperty("jcifs.encoding", Config.DEFAULT_OEM_ENCODING);
    public static final int OPEN_FUNCTION_FAIL_IF_EXISTS = 0;
    public static final int OPEN_FUNCTION_OVERWRITE_IF_EXISTS = 32;
    public static final int PID = ((int) (Math.random() * 65536.0d));
    public static final int RCV_BUF_SIZE = Config.getInt("jcifs.smb.client.rcv_buf_size", DEFAULT_RCV_BUF_SIZE);
    public static final int READ_CONTROL = 131072;
    public static final int RESPONSE_TIMEOUT = Config.getInt("jcifs.smb.client.responseTimeout", DEFAULT_RESPONSE_TIMEOUT);
    public static final int SECURITY_SHARE = 0;
    public static final int SECURITY_USER = 1;
    public static final int SIGNATURE_OFFSET = 14;
    public static final boolean SIGNPREF = Config.getBoolean("jcifs.smb.client.signingPreferred", USE_UNICODE);
    public static final int SND_BUF_SIZE = Config.getInt("jcifs.smb.client.snd_buf_size", DEFAULT_SND_BUF_SIZE);
    public static final int SO_TIMEOUT = Config.getInt("jcifs.smb.client.soTimeout", DEFAULT_SO_TIMEOUT);
    public static final int SSN_LIMIT = Config.getInt("jcifs.smb.client.ssnLimit", DEFAULT_SSN_LIMIT);
    public static final int SYNCHRONIZE = 1048576;
    public static final boolean TCP_NODELAY = Config.getBoolean("jcifs.smb.client.tcpNoDelay", USE_UNICODE);
    public static final int TID_OFFSET = 24;
    public static final TimeZone TZ = TimeZone.getDefault();
    public static final boolean USE_BATCHING = Config.getBoolean("jcifs.smb.client.useBatching", true);
    public static final boolean USE_EXTSEC = Config.getBoolean("jcifs.smb.client.useExtendedSecurity", USE_UNICODE);
    public static final boolean USE_NTSMBS = Config.getBoolean("jcifs.smb.client.useNTSmbs", true);
    public static final boolean USE_NTSTATUS = Config.getBoolean("jcifs.smb.client.useNtStatus", true);
    public static final boolean USE_UNICODE = Config.getBoolean("jcifs.smb.client.useUnicode", true);
    public static final int VC_NUMBER = 1;
    public static final int WRITE_DAC = 262144;
    public static final int WRITE_OWNER = 524288;

    static {
        int i = FLAGS_COPY_TARGET_MODE_ASCII;
        int i2 = (USE_NTSMBS ? FLAGS_VERIFY_ALL_WRITES : SSN_LIMIT) | (USE_NTSTATUS ? FLAGS_NOTIFY_OF_MODIFY_ACTION : SSN_LIMIT);
        if (!USE_UNICODE) {
            i = SSN_LIMIT;
        }
        DEFAULT_CAPABILITIES = (i2 | i) | FLAGS2_RESOLVE_PATHS_IN_DFS;
    }
}
