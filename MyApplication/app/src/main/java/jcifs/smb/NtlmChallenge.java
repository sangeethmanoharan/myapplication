package jcifs.smb;

import java.io.Serializable;
import jcifs.UniAddress;
import jcifs.util.Hexdump;

public final class NtlmChallenge implements Serializable {
    public byte[] challenge;
    public UniAddress dc;

    NtlmChallenge(byte[] challenge, UniAddress dc) {
        this.challenge = challenge;
        this.dc = dc;
    }

    public String toString() {
        return new StringBuffer().append("NtlmChallenge[challenge=0x").append(Hexdump.toHexString(this.challenge, 0, this.challenge.length * 2)).append(",dc=").append(this.dc.toString()).append("]").toString();
    }
}
