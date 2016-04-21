package jcifs.dcerpc.ndr;

import org.xbill.DNS.Type;

public class NdrSmall extends NdrObject {
    public int value;

    public NdrSmall(int value) {
        this.value = value & Type.ANY;
    }

    public void encode(NdrBuffer dst) throws NdrException {
        dst.enc_ndr_small(this.value);
    }

    public void decode(NdrBuffer src) throws NdrException {
        this.value = src.dec_ndr_small();
    }
}
