package jcifs.smb;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Random;
import jcifs.Config;
import jcifs.util.DES;
import jcifs.util.HMACT64;
import jcifs.util.LogStream;
import jcifs.util.MD4;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

public final class NtlmPasswordAuthentication implements Serializable, Principal {
    static final String BLANK = "";
    static final NtlmPasswordAuthentication DEFAULT = new NtlmPasswordAuthentication(null);
    static String DEFAULT_DOMAIN;
    static String DEFAULT_PASSWORD;
    static String DEFAULT_USERNAME;
    static final NtlmPasswordAuthentication GUEST = new NtlmPasswordAuthentication("?", "GUEST", BLANK);
    private static final int LM_COMPATIBILITY = Config.getInt("jcifs.smb.lmCompatibility", 0);
    static final NtlmPasswordAuthentication NULL = new NtlmPasswordAuthentication(BLANK, BLANK, BLANK);
    private static final Random RANDOM = new Random();
    private static final byte[] S8 = new byte[]{(byte) 75, (byte) 71, (byte) 83, (byte) 33, (byte) 64, (byte) 35, (byte) 36, (byte) 37};
    private static LogStream log = LogStream.getInstance();
    byte[] ansiHash;
    byte[] challenge;
    byte[] clientChallenge;
    String domain;
    boolean hashesExternal;
    String password;
    byte[] unicodeHash;
    String username;

    private static void E(byte[] key, byte[] data, byte[] e) {
        byte[] key7 = new byte[7];
        byte[] e8 = new byte[8];
        for (int i = 0; i < key.length / 7; i++) {
            System.arraycopy(key, i * 7, key7, 0, 7);
            new DES(key7).encrypt(data, e8);
            System.arraycopy(e8, 0, e, i * 8, 8);
        }
    }

    static void initDefaults() {
        if (DEFAULT_DOMAIN == null) {
            DEFAULT_DOMAIN = Config.getProperty("jcifs.smb.client.domain", "?");
            DEFAULT_USERNAME = Config.getProperty("jcifs.smb.client.username", "GUEST");
            DEFAULT_PASSWORD = Config.getProperty("jcifs.smb.client.password", BLANK);
        }
    }

    public static byte[] getPreNTLMResponse(String password, byte[] challenge) {
        byte[] p14 = new byte[14];
        byte[] p21 = new byte[21];
        byte[] p24 = new byte[24];
        try {
            byte[] passwordBytes = password.toUpperCase().getBytes(SmbConstants.OEM_ENCODING);
            int passwordLength = passwordBytes.length;
            if (passwordLength > 14) {
                passwordLength = 14;
            }
            System.arraycopy(passwordBytes, 0, p14, 0, passwordLength);
            E(p14, S8, p21);
            E(p21, challenge, p24);
            return p24;
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("Try setting jcifs.encoding=US-ASCII", uee);
        }
    }

    public static byte[] getNTLMResponse(String password, byte[] challenge) {
        byte[] uni = null;
        byte[] p21 = new byte[21];
        byte[] p24 = new byte[24];
        try {
            uni = password.getBytes("UnicodeLittleUnmarked");
        } catch (UnsupportedEncodingException uee) {
            LogStream logStream = log;
            if (LogStream.level > 0) {
                uee.printStackTrace(log);
            }
        }
        MD4 md4 = new MD4();
        md4.update(uni);
        try {
            md4.digest(p21, 0, 16);
        } catch (Exception ex) {
            logStream = log;
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
        }
        E(p21, challenge, p24);
        return p24;
    }

    public static byte[] getLMv2Response(String domain, String user, String password, byte[] challenge, byte[] clientChallenge) {
        try {
            byte[] hash = new byte[16];
            byte[] response = new byte[24];
            MD4 md4 = new MD4();
            md4.update(password.getBytes("UnicodeLittleUnmarked"));
            HMACT64 hmac = new HMACT64(md4.digest());
            hmac.update(user.toUpperCase().getBytes("UnicodeLittleUnmarked"));
            hmac.update(domain.toUpperCase().getBytes("UnicodeLittleUnmarked"));
            HMACT64 hmac2 = new HMACT64(hmac.digest());
            hmac2.update(challenge);
            hmac2.update(clientChallenge);
            hmac2.digest(response, 0, 16);
            System.arraycopy(clientChallenge, 0, response, 16, 8);
            return response;
        } catch (Exception ex) {
            LogStream logStream = log;
            if (LogStream.level > 0) {
                ex.printStackTrace(log);
            }
            return null;
        }
    }

    public NtlmPasswordAuthentication(String userInfo) {
        this.hashesExternal = false;
        this.clientChallenge = null;
        this.challenge = null;
        this.password = null;
        this.username = null;
        this.domain = null;
        if (userInfo != null) {
            try {
                userInfo = unescape(userInfo);
            } catch (UnsupportedEncodingException e) {
            }
            int end = userInfo.length();
            int i = 0;
            int u = 0;
            while (i < end) {
                char c = userInfo.charAt(i);
                if (c == ';') {
                    this.domain = userInfo.substring(0, i);
                    u = i + 1;
                } else if (c == ':') {
                    this.password = userInfo.substring(i + 1);
                    break;
                }
                i++;
            }
            this.username = userInfo.substring(u, i);
        }
        initDefaults();
        if (this.domain == null) {
            this.domain = DEFAULT_DOMAIN;
        }
        if (this.username == null) {
            this.username = DEFAULT_USERNAME;
        }
        if (this.password == null) {
            this.password = DEFAULT_PASSWORD;
        }
    }

    public NtlmPasswordAuthentication(String domain, String username, String password) {
        this.hashesExternal = false;
        this.clientChallenge = null;
        this.challenge = null;
        this.domain = domain;
        this.username = username;
        this.password = password;
        initDefaults();
        if (domain == null) {
            this.domain = DEFAULT_DOMAIN;
        }
        if (username == null) {
            this.username = DEFAULT_USERNAME;
        }
        if (password == null) {
            this.password = DEFAULT_PASSWORD;
        }
    }

    public NtlmPasswordAuthentication(String domain, String username, byte[] challenge, byte[] ansiHash, byte[] unicodeHash) {
        this.hashesExternal = false;
        this.clientChallenge = null;
        this.challenge = null;
        if (domain == null || username == null || ansiHash == null || unicodeHash == null) {
            throw new IllegalArgumentException("External credentials cannot be null");
        }
        this.domain = domain;
        this.username = username;
        this.password = null;
        this.challenge = challenge;
        this.ansiHash = ansiHash;
        this.unicodeHash = unicodeHash;
        this.hashesExternal = true;
    }

    public String getDomain() {
        return this.domain;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public String getName() {
        boolean d = this.domain.length() > 0 && !this.domain.equals("?");
        return d ? new StringBuffer().append(this.domain).append("\\").append(this.username).toString() : this.username;
    }

    public byte[] getAnsiHash(byte[] challenge) {
        if (this.hashesExternal) {
            return this.ansiHash;
        }
        switch (LM_COMPATIBILITY) {
            case Tokenizer.EOF /*0*/:
            case Zone.PRIMARY /*1*/:
                return getPreNTLMResponse(this.password, challenge);
            case Zone.SECONDARY /*2*/:
                return getNTLMResponse(this.password, challenge);
            case Protocol.GGP /*3*/:
            case Type.MF /*4*/:
            case Service.RJE /*5*/:
                if (this.clientChallenge == null) {
                    this.clientChallenge = new byte[8];
                    RANDOM.nextBytes(this.clientChallenge);
                }
                return getLMv2Response(this.domain, this.username, this.password, challenge, this.clientChallenge);
            default:
                return getPreNTLMResponse(this.password, challenge);
        }
    }

    public byte[] getUnicodeHash(byte[] challenge) {
        if (this.hashesExternal) {
            return this.unicodeHash;
        }
        switch (LM_COMPATIBILITY) {
            case Tokenizer.EOF /*0*/:
            case Zone.PRIMARY /*1*/:
            case Zone.SECONDARY /*2*/:
                return getNTLMResponse(this.password, challenge);
            case Protocol.GGP /*3*/:
            case Type.MF /*4*/:
            case Service.RJE /*5*/:
                return new byte[0];
            default:
                return getNTLMResponse(this.password, challenge);
        }
    }

    public byte[] getUserSessionKey(byte[] challenge) {
        if (this.hashesExternal) {
            return null;
        }
        byte[] key = new byte[16];
        try {
            getUserSessionKey(challenge, key, 0);
            return key;
        } catch (Exception ex) {
            LogStream logStream = log;
            if (LogStream.level <= 0) {
                return key;
            }
            ex.printStackTrace(log);
            return key;
        }
    }

    void getUserSessionKey(byte[] challenge, byte[] dest, int offset) throws Exception {
        if (!this.hashesExternal) {
            MD4 md4 = new MD4();
            md4.update(this.password.getBytes("UnicodeLittleUnmarked"));
            switch (LM_COMPATIBILITY) {
                case Tokenizer.EOF /*0*/:
                case Zone.PRIMARY /*1*/:
                case Zone.SECONDARY /*2*/:
                    md4.update(md4.digest());
                    md4.digest(dest, offset, 16);
                    return;
                case Protocol.GGP /*3*/:
                case Type.MF /*4*/:
                case Service.RJE /*5*/:
                    if (this.clientChallenge == null) {
                        this.clientChallenge = new byte[8];
                        RANDOM.nextBytes(this.clientChallenge);
                    }
                    HMACT64 hmac = new HMACT64(md4.digest());
                    hmac.update(this.username.toUpperCase().getBytes("UnicodeLittleUnmarked"));
                    hmac.update(this.domain.toUpperCase().getBytes("UnicodeLittleUnmarked"));
                    byte[] ntlmv2Hash = hmac.digest();
                    hmac = new HMACT64(ntlmv2Hash);
                    hmac.update(challenge);
                    hmac.update(this.clientChallenge);
                    HMACT64 userKey = new HMACT64(ntlmv2Hash);
                    userKey.update(hmac.digest());
                    userKey.digest(dest, offset, 16);
                    return;
                default:
                    md4.update(md4.digest());
                    md4.digest(dest, offset, 16);
                    return;
            }
        }
    }

    public boolean equals(Object obj) {
        if (obj instanceof NtlmPasswordAuthentication) {
            NtlmPasswordAuthentication ntlm = (NtlmPasswordAuthentication) obj;
            if (ntlm.domain.toUpperCase().equals(this.domain.toUpperCase()) && ntlm.username.toUpperCase().equals(this.username.toUpperCase())) {
                if (this.hashesExternal && ntlm.hashesExternal) {
                    if (Arrays.equals(this.ansiHash, ntlm.ansiHash) && Arrays.equals(this.unicodeHash, ntlm.unicodeHash)) {
                        return true;
                    }
                    return false;
                } else if (!this.hashesExternal && this.password.equals(ntlm.password)) {
                    return true;
                }
            }
        }
        return false;
    }

    public int hashCode() {
        return getName().toUpperCase().hashCode();
    }

    public String toString() {
        return getName();
    }

    static String unescape(String str) throws NumberFormatException, UnsupportedEncodingException {
        byte[] b = new byte[1];
        if (str == null) {
            return null;
        }
        int len = str.length();
        char[] out = new char[len];
        int state = 0;
        int i = 0;
        int j = 0;
        while (i < len) {
            int j2;
            switch (state) {
                case Tokenizer.EOF /*0*/:
                    char ch = str.charAt(i);
                    if (ch != '%') {
                        j2 = j + 1;
                        out[j] = ch;
                        break;
                    }
                    state = 1;
                    j2 = j;
                    break;
                case Zone.PRIMARY /*1*/:
                    b[0] = (byte) (Integer.parseInt(str.substring(i, i + 2), 16) & Type.ANY);
                    j2 = j + 1;
                    out[j] = new String(b, 0, 1, "ASCII").charAt(0);
                    i++;
                    state = 0;
                    break;
                default:
                    j2 = j;
                    break;
            }
            i++;
            j = j2;
        }
        return new String(out, 0, j);
    }
}
