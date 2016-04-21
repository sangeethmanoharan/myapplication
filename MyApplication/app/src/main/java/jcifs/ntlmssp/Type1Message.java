package jcifs.ntlmssp;

import java.io.IOException;
import java.net.UnknownHostException;
import jcifs.Config;
import jcifs.netbios.NbtAddress;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.KEYRecord.Flags;

public class Type1Message extends NtlmMessage {
    private static final String DEFAULT_DOMAIN = Config.getProperty("jcifs.smb.client.domain", null);
    private static final int DEFAULT_FLAGS;
    private static final String DEFAULT_WORKSTATION;
    private String suppliedDomain;
    private String suppliedWorkstation;

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

    public Type1Message() {
        this(getDefaultFlags(), getDefaultDomain(), getDefaultWorkstation());
    }

    public Type1Message(int flags, String suppliedDomain, String suppliedWorkstation) {
        setFlags(flags);
        setSuppliedDomain(suppliedDomain);
        setSuppliedWorkstation(suppliedWorkstation);
    }

    public Type1Message(byte[] material) throws IOException {
        parse(material);
    }

    public String getSuppliedDomain() {
        return this.suppliedDomain;
    }

    public void setSuppliedDomain(String suppliedDomain) {
        this.suppliedDomain = suppliedDomain;
    }

    public String getSuppliedWorkstation() {
        return this.suppliedWorkstation;
    }

    public void setSuppliedWorkstation(String suppliedWorkstation) {
        this.suppliedWorkstation = suppliedWorkstation;
    }

    public byte[] toByteArray() {
        int i = 16;
        try {
            String suppliedDomain = getSuppliedDomain();
            String suppliedWorkstation = getSuppliedWorkstation();
            int flags = getFlags();
            boolean hostInfo = false;
            byte[] domain = new byte[0];
            if (suppliedDomain == null || suppliedDomain.length() == 0) {
                flags &= -4097;
            } else {
                hostInfo = true;
                flags |= Flags.EXTEND;
                domain = suppliedDomain.toUpperCase().getBytes(NtlmMessage.getOEMEncoding());
            }
            byte[] workstation = new byte[0];
            if (suppliedWorkstation == null || suppliedWorkstation.length() == 0) {
                flags &= -8193;
            } else {
                hostInfo = true;
                flags |= Flags.FLAG2;
                workstation = suppliedWorkstation.toUpperCase().getBytes(NtlmMessage.getOEMEncoding());
            }
            if (hostInfo) {
                i = (domain.length + 32) + workstation.length;
            }
            byte[] type1 = new byte[i];
            System.arraycopy(NTLMSSP_SIGNATURE, 0, type1, 0, 8);
            NtlmMessage.writeULong(type1, 8, 1);
            NtlmMessage.writeULong(type1, 12, flags);
            if (hostInfo) {
                NtlmMessage.writeSecurityBuffer(type1, 16, 32, domain);
                NtlmMessage.writeSecurityBuffer(type1, 24, domain.length + 32, workstation);
            }
            return type1;
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    public String toString() {
        String suppliedDomain = getSuppliedDomain();
        String suppliedWorkstation = getSuppliedWorkstation();
        int flags = getFlags();
        StringBuffer buffer = new StringBuffer();
        if (suppliedDomain != null) {
            buffer.append("suppliedDomain: ").append(suppliedDomain);
        }
        if (suppliedWorkstation != null) {
            if (buffer.length() > 0) {
                buffer.append("; ");
            }
            buffer.append("suppliedWorkstation: ").append(suppliedWorkstation);
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

    public static String getDefaultDomain() {
        return DEFAULT_DOMAIN;
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
        if (NtlmMessage.readULong(material, 8) != 1) {
            throw new IOException("Not a Type 1 message.");
        }
        int flags = NtlmMessage.readULong(material, 12);
        String suppliedDomain = null;
        if ((flags & Flags.EXTEND) != 0) {
            suppliedDomain = new String(NtlmMessage.readSecurityBuffer(material, 16), NtlmMessage.getOEMEncoding());
        }
        String suppliedWorkstation = null;
        if ((flags & Flags.FLAG2) != 0) {
            suppliedWorkstation = new String(NtlmMessage.readSecurityBuffer(material, 24), NtlmMessage.getOEMEncoding());
        }
        setFlags(flags);
        setSuppliedDomain(suppliedDomain);
        setSuppliedWorkstation(suppliedWorkstation);
    }
}
