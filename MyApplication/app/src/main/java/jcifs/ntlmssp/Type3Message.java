package jcifs.ntlmssp;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import jcifs.Config;
import jcifs.netbios.NbtAddress;
import jcifs.smb.NtlmPasswordAuthentication;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

public class Type3Message extends NtlmMessage {
    private static final String DEFAULT_DOMAIN = Config.getProperty("jcifs.smb.client.domain", null);
    private static final int DEFAULT_FLAGS;
    private static final String DEFAULT_PASSWORD = Config.getProperty("jcifs.smb.client.password", null);
    private static final String DEFAULT_USER = Config.getProperty("jcifs.smb.client.username", null);
    private static final String DEFAULT_WORKSTATION;
    private static final int LM_COMPATIBILITY = Config.getInt("jcifs.smb.lmCompatibility", 0);
    private static final SecureRandom RANDOM = new SecureRandom();
    private String domain;
    private byte[] lmResponse;
    private byte[] ntResponse;
    private byte[] sessionKey;
    private String user;
    private String workstation;

    static {
        int i = 1;
        if (!Config.getBoolean("jcifs.smb.client.useUnicode", true)) {
            i = 2;
        }
        DEFAULT_FLAGS = i | KEYRecord.OWNER_HOST;
        String defaultWorkstation = null;
        try {
            defaultWorkstation = NbtAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
        }
        DEFAULT_WORKSTATION = defaultWorkstation;
    }

    public Type3Message() {
        setFlags(getDefaultFlags());
        setDomain(getDefaultDomain());
        setUser(getDefaultUser());
        setWorkstation(getDefaultWorkstation());
    }

    public Type3Message(Type2Message type2) {
        setFlags(getDefaultFlags(type2));
        setWorkstation(getDefaultWorkstation());
        String domain = getDefaultDomain();
        setDomain(domain);
        String user = getDefaultUser();
        setUser(user);
        String password = getDefaultPassword();
        switch (LM_COMPATIBILITY) {
            case Tokenizer.EOF /*0*/:
            case Zone.PRIMARY /*1*/:
                setLMResponse(getLMResponse(type2, password));
                setNTResponse(getNTResponse(type2, password));
                return;
            case Zone.SECONDARY /*2*/:
                byte[] nt = getNTResponse(type2, password);
                setLMResponse(nt);
                setNTResponse(nt);
                return;
            case Protocol.GGP /*3*/:
            case Type.MF /*4*/:
            case Service.RJE /*5*/:
                byte[] clientChallenge = new byte[8];
                RANDOM.nextBytes(clientChallenge);
                setLMResponse(getLMv2Response(type2, domain, user, password, clientChallenge));
                return;
            default:
                setLMResponse(getLMResponse(type2, password));
                setNTResponse(getNTResponse(type2, password));
                return;
        }
    }

    public Type3Message(Type2Message type2, String password, String domain, String user, String workstation) {
        setFlags(getDefaultFlags(type2));
        setDomain(domain);
        setUser(user);
        setWorkstation(workstation);
        switch (LM_COMPATIBILITY) {
            case Tokenizer.EOF /*0*/:
            case Zone.PRIMARY /*1*/:
                setLMResponse(getLMResponse(type2, password));
                setNTResponse(getNTResponse(type2, password));
                return;
            case Zone.SECONDARY /*2*/:
                byte[] nt = getNTResponse(type2, password);
                setLMResponse(nt);
                setNTResponse(nt);
                return;
            case Protocol.GGP /*3*/:
            case Type.MF /*4*/:
            case Service.RJE /*5*/:
                byte[] clientChallenge = new byte[8];
                RANDOM.nextBytes(clientChallenge);
                setLMResponse(getLMv2Response(type2, domain, user, password, clientChallenge));
                return;
            default:
                setLMResponse(getLMResponse(type2, password));
                setNTResponse(getNTResponse(type2, password));
                return;
        }
    }

    public Type3Message(int flags, byte[] lmResponse, byte[] ntResponse, String domain, String user, String workstation) {
        setFlags(flags);
        setLMResponse(lmResponse);
        setNTResponse(ntResponse);
        setDomain(domain);
        setUser(user);
        setWorkstation(workstation);
    }

    public Type3Message(byte[] material) throws IOException {
        parse(material);
    }

    public byte[] getLMResponse() {
        return this.lmResponse;
    }

    public void setLMResponse(byte[] lmResponse) {
        this.lmResponse = lmResponse;
    }

    public byte[] getNTResponse() {
        return this.ntResponse;
    }

    public void setNTResponse(byte[] ntResponse) {
        this.ntResponse = ntResponse;
    }

    public String getDomain() {
        return this.domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getUser() {
        return this.user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getWorkstation() {
        return this.workstation;
    }

    public void setWorkstation(String workstation) {
        this.workstation = workstation;
    }

    public byte[] getSessionKey() {
        return this.sessionKey;
    }

    public void setSessionKey(byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    public byte[] toByteArray() {
        try {
            int flags = getFlags();
            boolean unicode = (flags & 1) != 0;
            String oem = unicode ? null : NtlmMessage.getOEMEncoding();
            String domainName = getDomain();
            byte[] domain = null;
            if (!(domainName == null || domainName.length() == 0)) {
                domain = unicode ? domainName.toUpperCase().getBytes("UnicodeLittleUnmarked") : domainName.toUpperCase().getBytes(oem);
            }
            int domainLength = domain != null ? domain.length : 0;
            String userName = getUser();
            byte[] user = null;
            if (!(userName == null || userName.length() == 0)) {
                user = unicode ? userName.getBytes("UnicodeLittleUnmarked") : userName.toUpperCase().getBytes(oem);
            }
            int userLength = user != null ? user.length : 0;
            String workstationName = getWorkstation();
            byte[] workstation = null;
            if (!(workstationName == null || workstationName.length() == 0)) {
                workstation = unicode ? workstationName.getBytes("UnicodeLittleUnmarked") : workstationName.toUpperCase().getBytes(oem);
            }
            int workstationLength = workstation != null ? workstation.length : 0;
            byte[] lmResponse = getLMResponse();
            int lmLength = lmResponse != null ? lmResponse.length : 0;
            byte[] ntResponse = getNTResponse();
            int ntLength = ntResponse != null ? ntResponse.length : 0;
            byte[] sessionKey = getSessionKey();
            Object type3 = new byte[((((((domainLength + 64) + userLength) + workstationLength) + lmLength) + ntLength) + (sessionKey != null ? sessionKey.length : 0))];
            System.arraycopy(NTLMSSP_SIGNATURE, 0, type3, 0, 8);
            NtlmMessage.writeULong(type3, 8, 3);
            NtlmMessage.writeSecurityBuffer(type3, 12, 64, lmResponse);
            int offset = 64 + lmLength;
            NtlmMessage.writeSecurityBuffer(type3, 20, offset, ntResponse);
            offset += ntLength;
            NtlmMessage.writeSecurityBuffer(type3, 28, offset, domain);
            offset += domainLength;
            NtlmMessage.writeSecurityBuffer(type3, 36, offset, user);
            offset += userLength;
            NtlmMessage.writeSecurityBuffer(type3, 44, offset, workstation);
            NtlmMessage.writeSecurityBuffer(type3, 52, offset + workstationLength, sessionKey);
            NtlmMessage.writeULong(type3, 60, flags);
            return type3;
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    public String toString() {
        int i;
        String user = getUser();
        String domain = getDomain();
        String workstation = getWorkstation();
        byte[] lmResponse = getLMResponse();
        byte[] ntResponse = getNTResponse();
        byte[] sessionKey = getSessionKey();
        int flags = getFlags();
        StringBuffer buffer = new StringBuffer();
        if (domain != null) {
            buffer.append("domain: ").append(domain);
        }
        if (user != null) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("user: ").append(user);
        }
        if (workstation != null) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("workstation: ").append(workstation);
        }
        if (lmResponse != null) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("lmResponse: ");
            buffer.append("0x");
            for (i = 0; i < lmResponse.length; i++) {
                buffer.append(Integer.toHexString((lmResponse[i] >> 4) & 15));
                buffer.append(Integer.toHexString(lmResponse[i] & 15));
            }
        }
        if (ntResponse != null) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("ntResponse: ");
            buffer.append("0x");
            for (i = 0; i < ntResponse.length; i++) {
                buffer.append(Integer.toHexString((ntResponse[i] >> 4) & 15));
                buffer.append(Integer.toHexString(ntResponse[i] & 15));
            }
        }
        if (sessionKey != null) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("sessionKey: ");
            buffer.append("0x");
            for (i = 0; i < sessionKey.length; i++) {
                buffer.append(Integer.toHexString((sessionKey[i] >> 4) & 15));
                buffer.append(Integer.toHexString(sessionKey[i] & 15));
            }
        }
        if (flags != 0) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("flags: ");
            buffer.append("0x");
            buffer.append(Integer.toHexString((flags >> 28) & 15));
            buffer.append(Integer.toHexString((flags >> 24) & 15));
            buffer.append(Integer.toHexString((flags >> 20) & 15));
            buffer.append(Integer.toHexString((flags >> 16) & 15));
            buffer.append(Integer.toHexString((flags >> 12) & 15));
            buffer.append(Integer.toHexString((flags >> 8) & 15));
            buffer.append(Integer.toHexString((flags >> 4) & 15));
            buffer.append(Integer.toHexString(flags & 15));
        }
        return buffer.toString();
    }

    public static int getDefaultFlags() {
        return DEFAULT_FLAGS;
    }

    public static int getDefaultFlags(Type2Message type2) {
        if (type2 == null) {
            return DEFAULT_FLAGS;
        }
        return KEYRecord.OWNER_HOST | ((type2.getFlags() & 1) != 0 ? 1 : 2);
    }

    public static byte[] getLMResponse(Type2Message type2, String password) {
        if (type2 == null || password == null) {
            return null;
        }
        return NtlmPasswordAuthentication.getPreNTLMResponse(password, type2.getChallenge());
    }

    public static byte[] getLMv2Response(Type2Message type2, String domain, String user, String password, byte[] clientChallenge) {
        if (type2 == null || domain == null || user == null || password == null || clientChallenge == null) {
            return null;
        }
        return NtlmPasswordAuthentication.getLMv2Response(domain, user, password, type2.getChallenge(), clientChallenge);
    }

    public static byte[] getNTResponse(Type2Message type2, String password) {
        if (type2 == null || password == null) {
            return null;
        }
        return NtlmPasswordAuthentication.getNTLMResponse(password, type2.getChallenge());
    }

    public static String getDefaultDomain() {
        return DEFAULT_DOMAIN;
    }

    public static String getDefaultUser() {
        return DEFAULT_USER;
    }

    public static String getDefaultPassword() {
        return DEFAULT_PASSWORD;
    }

    public static String getDefaultWorkstation() {
        return DEFAULT_WORKSTATION;
    }

    private void parse(byte[] material) throws IOException {
        for (int i = 0; i < 8; i++) {
            if (material[i] != NTLMSSP_SIGNATURE[i]) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }
        if (NtlmMessage.readULong(material, 8) != 3) {
            throw new IOException("Not a Type 3 message.");
        }
        int flags;
        String charset;
        byte[] lmResponse = NtlmMessage.readSecurityBuffer(material, 12);
        int lmResponseOffset = NtlmMessage.readULong(material, 16);
        byte[] ntResponse = NtlmMessage.readSecurityBuffer(material, 20);
        int ntResponseOffset = NtlmMessage.readULong(material, 24);
        byte[] domain = NtlmMessage.readSecurityBuffer(material, 28);
        int domainOffset = NtlmMessage.readULong(material, 32);
        byte[] user = NtlmMessage.readSecurityBuffer(material, 36);
        int userOffset = NtlmMessage.readULong(material, 40);
        byte[] workstation = NtlmMessage.readSecurityBuffer(material, 44);
        int workstationOffset = NtlmMessage.readULong(material, 48);
        if (lmResponseOffset == 52 || ntResponseOffset == 52 || domainOffset == 52 || userOffset == 52 || workstationOffset == 52) {
            flags = 514;
            charset = NtlmMessage.getOEMEncoding();
        } else {
            setSessionKey(NtlmMessage.readSecurityBuffer(material, 52));
            flags = NtlmMessage.readULong(material, 60);
            charset = (flags & 1) != 0 ? "UnicodeLittleUnmarked" : NtlmMessage.getOEMEncoding();
        }
        setFlags(flags);
        setLMResponse(lmResponse);
        if (ntResponse.length == 24) {
            setNTResponse(ntResponse);
        }
        setDomain(new String(domain, charset));
        setUser(new String(user, charset));
        setWorkstation(new String(workstation, charset));
    }
}
