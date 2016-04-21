package jcifs.util;

import jcifs.ntlmssp.NtlmFlags;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Service;

public class DES {
    private static int[] SP1 = new int[]{16843776, 0, SmbConstants.DELETE, 16843780, 16842756, 66564, 4, SmbConstants.DELETE, Flags.FLAG5, 16843776, 16843780, Flags.FLAG5, 16778244, 16842756, 16777216, 4, 1028, 16778240, 16778240, 66560, 66560, 16842752, 16842752, 16778244, 65540, 16777220, 16777220, 65540, 0, 1028, 66564, 16777216, SmbConstants.DELETE, 16843780, 4, 16842752, 16843776, 16777216, 16777216, Flags.FLAG5, 16842756, SmbConstants.DELETE, 66560, 16777220, Flags.FLAG5, 4, 16778244, 66564, 16843780, 65540, 16842752, 16778244, 16777220, 1028, 66564, 16843776, 1028, 16778240, 16778240, 0, 65540, 66560, 0, 16842756};
    private static int[] SP2 = new int[]{-2146402272, -2147450880, KEYRecord.FLAG_NOAUTH, 1081376, SmbConstants.SYNCHRONIZE, 32, -2146435040, -2147450848, -2147483616, -2146402272, -2146402304, SmbConstants.GENERIC_READ, -2147450880, SmbConstants.SYNCHRONIZE, 32, -2146435040, 1081344, 1048608, -2147450848, 0, SmbConstants.GENERIC_READ, KEYRecord.FLAG_NOAUTH, 1081376, -2146435072, 1048608, -2147483616, 0, 1081344, 32800, -2146402304, -2146435072, 32800, 0, 1081376, -2146435040, SmbConstants.SYNCHRONIZE, -2147450848, -2146435072, -2146402304, KEYRecord.FLAG_NOAUTH, -2146435072, -2147450880, 32, -2146402272, 1081376, 32, KEYRecord.FLAG_NOAUTH, SmbConstants.GENERIC_READ, 32800, -2146402304, SmbConstants.SYNCHRONIZE, -2147483616, 1048608, -2147450848, -2147483616, 1048608, 1081344, 0, -2147450880, 32800, SmbConstants.GENERIC_READ, -2146435040, -2146402272, 1081344};
    private static int[] SP3 = new int[]{520, 134349312, 0, 134348808, 134218240, 0, 131592, 134218240, 131080, 134217736, 134217736, SmbConstants.READ_CONTROL, 134349320, 131080, 134348800, 520, 134217728, 8, 134349312, KEYRecord.OWNER_HOST, 131584, 134348800, 134348808, 131592, 134218248, 131584, SmbConstants.READ_CONTROL, 134218248, 8, 134349320, KEYRecord.OWNER_HOST, 134217728, 134349312, 134217728, 131080, 520, SmbConstants.READ_CONTROL, 134349312, 134218240, 0, KEYRecord.OWNER_HOST, 131080, 134349320, 134218240, 134217736, KEYRecord.OWNER_HOST, 0, 134348808, 134218248, SmbConstants.READ_CONTROL, 134217728, 134349320, 8, 131592, 131584, 134217736, 134348800, 134218248, 520, 134348800, 131592, 8, 134348808, 131584};
    private static int[] SP4 = new int[]{8396801, 8321, 8321, Flags.FLAG8, 8396928, 8388737, 8388609, 8193, 0, 8396800, 8396800, 8396929, Service.PWDGEN, 0, 8388736, 8388609, 1, Flags.FLAG2, NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, 8396801, Flags.FLAG8, NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, 8193, 8320, 8388737, 1, 8320, 8388736, Flags.FLAG2, 8396928, 8396929, Service.PWDGEN, 8388736, 8388609, 8396800, 8396929, Service.PWDGEN, 0, 0, 8396800, 8320, 8388736, 8388737, 1, 8396801, 8321, 8321, Flags.FLAG8, 8396929, Service.PWDGEN, 1, Flags.FLAG2, 8388609, 8193, 8396928, 8388737, 8193, 8320, NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, 8396801, Flags.FLAG8, NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, Flags.FLAG2, 8396928};
    private static int[] SP5 = new int[]{KEYRecord.OWNER_ZONE, 34078976, 34078720, 1107296512, SmbConstants.WRITE_OWNER, KEYRecord.OWNER_ZONE, SmbConstants.GENERIC_WRITE, 34078720, 1074266368, SmbConstants.WRITE_OWNER, 33554688, 1074266368, 1107296512, 1107820544, 524544, SmbConstants.GENERIC_WRITE, 33554432, 1074266112, 1074266112, 0, 1073742080, 1107820800, 1107820800, 33554688, 1107820544, 1073742080, 0, 1107296256, 34078976, 33554432, 1107296256, 524544, SmbConstants.WRITE_OWNER, 1107296512, KEYRecord.OWNER_ZONE, 33554432, SmbConstants.GENERIC_WRITE, 34078720, 1107296512, 1074266368, 33554688, SmbConstants.GENERIC_WRITE, 1107820544, 34078976, 1074266368, KEYRecord.OWNER_ZONE, 33554432, 1107820544, 1107820800, 524544, 1107296256, 1107820800, 34078720, 0, 1074266112, 1107296256, 524544, 33554688, 1073742080, SmbConstants.WRITE_OWNER, 0, 1074266112, 34078976, 1073742080};
    private static int[] SP6 = new int[]{536870928, 541065216, KEYRecord.FLAG_NOCONF, 541081616, 541065216, 16, 541081616, NtlmFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY, 536887296, 4210704, NtlmFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY, 536870928, 4194320, 536887296, SmbConstants.GENERIC_EXECUTE, 16400, 0, 4194320, 536887312, KEYRecord.FLAG_NOCONF, 4210688, 536887312, 16, 541065232, 541065232, 0, 4210704, 541081600, 16400, 4210688, 541081600, SmbConstants.GENERIC_EXECUTE, 536887296, 16, 541065232, 4210688, 541081616, NtlmFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY, 16400, 536870928, NtlmFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY, 536887296, SmbConstants.GENERIC_EXECUTE, 16400, 536870928, 541081616, 4210688, 541065216, 4210704, 541081600, 0, 541065232, 16, KEYRecord.FLAG_NOCONF, 541065216, 4210704, KEYRecord.FLAG_NOCONF, 4194320, 536887312, 0, 541081600, SmbConstants.GENERIC_EXECUTE, 4194320, 536887312};
    private static int[] SP7 = new int[]{NtlmFlags.NTLMSSP_REQUEST_ACCEPT_RESPONSE, 69206018, 67110914, 0, Flags.FLAG4, 67110914, 2099202, 69208064, 69208066, NtlmFlags.NTLMSSP_REQUEST_ACCEPT_RESPONSE, 0, 67108866, 2, 67108864, 69206018, 2050, 67110912, 2099202, 2097154, 67110912, 67108866, 69206016, 69208064, 2097154, 69206016, Flags.FLAG4, 2050, 69208066, 2099200, 2, 67108864, 2099200, 67108864, 2099200, NtlmFlags.NTLMSSP_REQUEST_ACCEPT_RESPONSE, 67110914, 67110914, 69206018, 69206018, 2, 2097154, 67108864, 67110912, NtlmFlags.NTLMSSP_REQUEST_ACCEPT_RESPONSE, 69208064, 2050, 2099202, 69208064, 2050, 67108866, 69208066, 69206016, 2099200, 0, 2, 69208066, 0, 2099202, 69206016, Flags.FLAG4, 67108866, 67110912, Flags.FLAG4, 2097154};
    private static int[] SP8 = new int[]{268439616, Flags.EXTEND, SmbConstants.WRITE_DAC, 268701760, SmbConstants.GENERIC_ALL, 268439616, 64, SmbConstants.GENERIC_ALL, 262208, 268697600, 268701760, 266240, 268701696, 266304, Flags.EXTEND, 64, 268697600, 268435520, 268439552, 4160, 266240, 262208, 268697664, 268701696, 4160, 0, 0, 268697664, 268435520, 268439552, 266304, SmbConstants.WRITE_DAC, 266304, SmbConstants.WRITE_DAC, 268701696, Flags.EXTEND, 64, 268697664, Flags.EXTEND, 266304, 268439552, 64, 268435520, 268697600, 268697664, SmbConstants.GENERIC_ALL, SmbConstants.WRITE_DAC, 268439616, 0, 268701760, 262208, 268435520, 268697600, 268439552, 268439616, 0, 268701760, 266240, 266240, 4160, 4160, 262208, SmbConstants.GENERIC_ALL, 268701696};
    private static int[] bigbyte = new int[]{NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, NtlmFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY, NtlmFlags.NTLMSSP_REQUEST_ACCEPT_RESPONSE, SmbConstants.SYNCHRONIZE, SmbConstants.WRITE_OWNER, SmbConstants.WRITE_DAC, SmbConstants.READ_CONTROL, SmbConstants.DELETE, KEYRecord.FLAG_NOAUTH, KEYRecord.FLAG_NOCONF, Flags.FLAG2, Flags.EXTEND, Flags.FLAG4, Flags.FLAG5, KEYRecord.OWNER_HOST, KEYRecord.OWNER_ZONE, Flags.FLAG8, 64, 32, 16, 8, 4, 2, 1};
    private static byte[] bytebit = new byte[]{Byte.MIN_VALUE, (byte) 64, (byte) 32, (byte) 16, (byte) 8, (byte) 4, (byte) 2, (byte) 1};
    private static byte[] pc1 = new byte[]{(byte) 56, (byte) 48, (byte) 40, (byte) 32, (byte) 24, (byte) 16, (byte) 8, (byte) 0, (byte) 57, (byte) 49, (byte) 41, (byte) 33, (byte) 25, (byte) 17, (byte) 9, (byte) 1, (byte) 58, (byte) 50, (byte) 42, (byte) 34, (byte) 26, (byte) 18, (byte) 10, (byte) 2, (byte) 59, (byte) 51, (byte) 43, (byte) 35, (byte) 62, (byte) 54, (byte) 46, (byte) 38, (byte) 30, (byte) 22, (byte) 14, (byte) 6, (byte) 61, (byte) 53, (byte) 45, (byte) 37, (byte) 29, (byte) 21, (byte) 13, (byte) 5, (byte) 60, (byte) 52, (byte) 44, (byte) 36, (byte) 28, (byte) 20, (byte) 12, (byte) 4, (byte) 27, (byte) 19, org.xbill.DNS.Flags.CD, (byte) 3};
    private static byte[] pc2 = new byte[]{(byte) 13, (byte) 16, (byte) 10, (byte) 23, (byte) 0, (byte) 4, (byte) 2, (byte) 27, (byte) 14, (byte) 5, (byte) 20, (byte) 9, (byte) 22, (byte) 18, org.xbill.DNS.Flags.CD, (byte) 3, (byte) 25, (byte) 7, (byte) 15, (byte) 6, (byte) 26, (byte) 19, (byte) 12, (byte) 1, (byte) 40, (byte) 51, (byte) 30, (byte) 36, (byte) 46, (byte) 54, (byte) 29, (byte) 39, (byte) 50, (byte) 44, (byte) 32, (byte) 47, (byte) 43, (byte) 48, (byte) 38, (byte) 55, (byte) 33, (byte) 52, (byte) 45, (byte) 41, (byte) 49, (byte) 35, (byte) 28, (byte) 31};
    private static int[] totrot = new int[]{1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28};
    private int[] decryptKeys;
    private int[] encryptKeys;
    private int[] tempInts;

    public DES() {
        this.encryptKeys = new int[32];
        this.decryptKeys = new int[32];
        this.tempInts = new int[2];
    }

    public DES(byte[] key) {
        this.encryptKeys = new int[32];
        this.decryptKeys = new int[32];
        this.tempInts = new int[2];
        if (key.length == 7) {
            byte[] key8 = new byte[8];
            makeSMBKey(key, key8);
            setKey(key8);
            return;
        }
        setKey(key);
    }

    public static void makeSMBKey(byte[] key7, byte[] key8) {
        key8[0] = (byte) ((key7[0] >> 1) & Type.ANY);
        key8[1] = (byte) ((((key7[0] & 1) << 6) | (((key7[1] & Type.ANY) >> 2) & Type.ANY)) & Type.ANY);
        key8[2] = (byte) ((((key7[1] & 3) << 5) | (((key7[2] & Type.ANY) >> 3) & Type.ANY)) & Type.ANY);
        key8[3] = (byte) ((((key7[2] & 7) << 4) | (((key7[3] & Type.ANY) >> 4) & Type.ANY)) & Type.ANY);
        key8[4] = (byte) ((((key7[3] & 15) << 3) | (((key7[4] & Type.ANY) >> 5) & Type.ANY)) & Type.ANY);
        key8[5] = (byte) ((((key7[4] & 31) << 2) | (((key7[5] & Type.ANY) >> 6) & Type.ANY)) & Type.ANY);
        key8[6] = (byte) ((((key7[5] & 63) << 1) | (((key7[6] & Type.ANY) >> 7) & Type.ANY)) & Type.ANY);
        key8[7] = (byte) (key7[6] & Service.LOCUS_CON);
        for (int i = 0; i < 8; i++) {
            key8[i] = (byte) (key8[i] << 1);
        }
    }

    public void setKey(byte[] key) {
        deskey(key, true, this.encryptKeys);
        deskey(key, false, this.decryptKeys);
    }

    private void deskey(byte[] keyBlock, boolean encrypting, int[] KnL) {
        int j;
        int[] pc1m = new int[56];
        int[] pcr = new int[56];
        int[] kn = new int[32];
        for (j = 0; j < 56; j++) {
            int l = pc1[j];
            pc1m[j] = (keyBlock[l >>> 3] & bytebit[l & 7]) != 0 ? 1 : 0;
        }
        for (int i = 0; i < 16; i++) {
            int m;
            if (encrypting) {
                m = i << 1;
            } else {
                m = (15 - i) << 1;
            }
            int n = m + 1;
            kn[n] = 0;
            kn[m] = 0;
            for (j = 0; j < 28; j++) {
                l = j + totrot[i];
                if (l < 28) {
                    pcr[j] = pc1m[l];
                } else {
                    pcr[j] = pc1m[l - 28];
                }
            }
            for (j = 28; j < 56; j++) {
                l = j + totrot[i];
                if (l < 56) {
                    pcr[j] = pc1m[l];
                } else {
                    pcr[j] = pc1m[l - 28];
                }
            }
            for (j = 0; j < 24; j++) {
                if (pcr[pc2[j]] != 0) {
                    kn[m] = kn[m] | bigbyte[j];
                }
                if (pcr[pc2[j + 24]] != 0) {
                    kn[n] = kn[n] | bigbyte[j];
                }
            }
        }
        cookey(kn, KnL);
    }

    private void cookey(int[] raw, int[] KnL) {
        int KnLi = 0;
        int rawi = 0;
        for (int i = 0; i < 16; i++) {
            int rawi2 = rawi + 1;
            int raw0 = raw[rawi];
            rawi = rawi2 + 1;
            int raw1 = raw[rawi2];
            KnL[KnLi] = (raw0 & 16515072) << 6;
            KnL[KnLi] = KnL[KnLi] | ((raw0 & 4032) << 10);
            KnL[KnLi] = KnL[KnLi] | ((raw1 & 16515072) >>> 10);
            KnL[KnLi] = KnL[KnLi] | ((raw1 & 4032) >>> 6);
            KnLi++;
            KnL[KnLi] = (raw0 & 258048) << 12;
            KnL[KnLi] = KnL[KnLi] | ((raw0 & 63) << 16);
            KnL[KnLi] = KnL[KnLi] | ((raw1 & 258048) >>> 4);
            KnL[KnLi] = KnL[KnLi] | (raw1 & 63);
            KnLi++;
        }
    }

    private void encrypt(byte[] clearText, int clearOff, byte[] cipherText, int cipherOff) {
        squashBytesToInts(clearText, clearOff, this.tempInts, 0, 2);
        des(this.tempInts, this.tempInts, this.encryptKeys);
        spreadIntsToBytes(this.tempInts, 0, cipherText, cipherOff, 2);
    }

    private void decrypt(byte[] cipherText, int cipherOff, byte[] clearText, int clearOff) {
        squashBytesToInts(cipherText, cipherOff, this.tempInts, 0, 2);
        des(this.tempInts, this.tempInts, this.decryptKeys);
        spreadIntsToBytes(this.tempInts, 0, clearText, clearOff, 2);
    }

    private void des(int[] inInts, int[] outInts, int[] keys) {
        int leftt = inInts[0];
        int right = inInts[1];
        int work = ((leftt >>> 4) ^ right) & 252645135;
        right ^= work;
        leftt ^= work << 4;
        work = ((leftt >>> 16) ^ right) & Message.MAXLENGTH;
        right ^= work;
        leftt ^= work << 16;
        work = ((right >>> 2) ^ leftt) & 858993459;
        leftt ^= work;
        right ^= work << 2;
        work = ((right >>> 8) ^ leftt) & 16711935;
        leftt ^= work;
        right ^= work << 8;
        right = (right << 1) | ((right >>> 31) & 1);
        work = (leftt ^ right) & -1431655766;
        leftt ^= work;
        right ^= work;
        leftt = (leftt << 1) | ((leftt >>> 31) & 1);
        int keysi = 0;
        for (int round = 0; round < 8; round++) {
            int keysi2 = keysi + 1;
            work = ((right << 28) | (right >>> 4)) ^ keys[keysi];
            int fval = ((SP7[work & 63] | SP5[(work >>> 8) & 63]) | SP3[(work >>> 16) & 63]) | SP1[(work >>> 24) & 63];
            keysi = keysi2 + 1;
            work = right ^ keys[keysi2];
            leftt ^= (((fval | SP8[work & 63]) | SP6[(work >>> 8) & 63]) | SP4[(work >>> 16) & 63]) | SP2[(work >>> 24) & 63];
            keysi2 = keysi + 1;
            work = ((leftt << 28) | (leftt >>> 4)) ^ keys[keysi];
            fval = ((SP7[work & 63] | SP5[(work >>> 8) & 63]) | SP3[(work >>> 16) & 63]) | SP1[(work >>> 24) & 63];
            keysi = keysi2 + 1;
            work = leftt ^ keys[keysi2];
            right ^= (((fval | SP8[work & 63]) | SP6[(work >>> 8) & 63]) | SP4[(work >>> 16) & 63]) | SP2[(work >>> 24) & 63];
        }
        right = (right << 31) | (right >>> 1);
        work = (leftt ^ right) & -1431655766;
        leftt ^= work;
        right ^= work;
        leftt = (leftt << 31) | (leftt >>> 1);
        work = ((leftt >>> 8) ^ right) & 16711935;
        right ^= work;
        leftt ^= work << 8;
        work = ((leftt >>> 2) ^ right) & 858993459;
        right ^= work;
        leftt ^= work << 2;
        work = ((right >>> 16) ^ leftt) & Message.MAXLENGTH;
        leftt ^= work;
        right ^= work << 16;
        work = ((right >>> 4) ^ leftt) & 252645135;
        leftt ^= work;
        outInts[0] = right ^ (work << 4);
        outInts[1] = leftt;
    }

    public void encrypt(byte[] clearText, byte[] cipherText) {
        encrypt(clearText, 0, cipherText, 0);
    }

    public void decrypt(byte[] cipherText, byte[] clearText) {
        decrypt(cipherText, 0, clearText, 0);
    }

    public byte[] encrypt(byte[] clearText) {
        int length = clearText.length;
        if (length % 8 != 0) {
            System.out.println("Array must be a multiple of 8");
            return null;
        }
        byte[] cipherText = new byte[length];
        int count = length / 8;
        for (int i = 0; i < count; i++) {
            encrypt(clearText, i * 8, cipherText, i * 8);
        }
        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText) {
        int length = cipherText.length;
        if (length % 8 != 0) {
            System.out.println("Array must be a multiple of 8");
            return null;
        }
        byte[] clearText = new byte[length];
        int count = length / 8;
        for (int i = 0; i < count; i++) {
            encrypt(cipherText, i * 8, clearText, i * 8);
        }
        return clearText;
    }

    public static void squashBytesToInts(byte[] inBytes, int inOff, int[] outInts, int outOff, int intLen) {
        for (int i = 0; i < intLen; i++) {
            outInts[outOff + i] = ((((inBytes[(i * 4) + inOff] & Type.ANY) << 24) | ((inBytes[((i * 4) + inOff) + 1] & Type.ANY) << 16)) | ((inBytes[((i * 4) + inOff) + 2] & Type.ANY) << 8)) | (inBytes[((i * 4) + inOff) + 3] & Type.ANY);
        }
    }

    public static void spreadIntsToBytes(int[] inInts, int inOff, byte[] outBytes, int outOff, int intLen) {
        for (int i = 0; i < intLen; i++) {
            outBytes[(i * 4) + outOff] = (byte) (inInts[inOff + i] >>> 24);
            outBytes[((i * 4) + outOff) + 1] = (byte) (inInts[inOff + i] >>> 16);
            outBytes[((i * 4) + outOff) + 2] = (byte) (inInts[inOff + i] >>> 8);
            outBytes[((i * 4) + outOff) + 3] = (byte) inInts[inOff + i];
        }
    }
}
