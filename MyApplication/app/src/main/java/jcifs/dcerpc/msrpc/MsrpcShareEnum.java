package jcifs.dcerpc.msrpc;

import jcifs.dcerpc.msrpc.srvsvc.ShareEnumAll;
import jcifs.dcerpc.msrpc.srvsvc.ShareInfo1;
import jcifs.dcerpc.msrpc.srvsvc.ShareInfoCtr1;
import jcifs.smb.FileEntry;
import jcifs.smb.SmbShareInfo;

public class MsrpcShareEnum extends ShareEnumAll {

    class MsrpcShareInfo1 extends SmbShareInfo {
        private final MsrpcShareEnum this$0;

        MsrpcShareInfo1(MsrpcShareEnum this$0, ShareInfo1 info1) {
            this.this$0 = this$0;
            this.netName = info1.netname;
            this.type = info1.type;
            this.remark = info1.remark;
        }
    }

    public MsrpcShareEnum(String server) {
        super(new StringBuffer().append("\\\\").append(server).toString(), 1, new ShareInfoCtr1(), -1, 0, 0);
        this.ptype = 0;
        this.flags = 3;
    }

    public FileEntry[] getEntries() {
        ShareInfoCtr1 ctr = this.info;
        MsrpcShareInfo1[] entries = new MsrpcShareInfo1[ctr.count];
        for (int i = 0; i < ctr.count; i++) {
            entries[i] = new MsrpcShareInfo1(this, ctr.array[i]);
        }
        return entries;
    }
}
