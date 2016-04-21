package jcifs.smb;

import jcifs.util.Hexdump;
import org.xbill.DNS.Message;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.Zone;

public class SmbShareInfo implements FileEntry {
    protected String netName;
    protected String remark;
    protected int type;

    public SmbShareInfo(String netName, int type, String remark) {
        this.netName = netName;
        this.type = type;
        this.remark = remark;
    }

    public String getName() {
        return this.netName;
    }

    public int getType() {
        switch (this.type & Message.MAXLENGTH) {
            case Zone.PRIMARY /*1*/:
                return 32;
            case Protocol.GGP /*3*/:
                return 16;
            default:
                return 8;
        }
    }

    public int getAttributes() {
        return 17;
    }

    public long createTime() {
        return 0;
    }

    public long lastModified() {
        return 0;
    }

    public long length() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof SmbShareInfo)) {
            return false;
        }
        return this.netName.equals(((SmbShareInfo) obj).netName);
    }

    public int hashCode() {
        return this.netName.hashCode();
    }

    public String toString() {
        return new String(new StringBuffer().append("SmbShareInfo[netName=").append(this.netName).append(",type=0x").append(Hexdump.toHexString(this.type, 8)).append(",remark=").append(this.remark).append("]").toString());
    }
}
