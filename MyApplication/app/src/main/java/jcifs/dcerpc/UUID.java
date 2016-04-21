package jcifs.dcerpc;

import jcifs.dcerpc.rpc.uuid_t;
import org.xbill.DNS.Message;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;

public class UUID extends uuid_t {
    static final char[] HEXCHARS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public static int hex_to_bin(char[] arr, int offset, int length) {
        int value = 0;
        int count = 0;
        for (int ai = offset; ai < arr.length && count < length; ai++) {
            value <<= 4;
            switch (arr[ai]) {
                case Type.DNSKEY /*48*/:
                case Service.LOGIN /*49*/:
                case Type.NSEC3 /*50*/:
                case Service.LA_MAINT /*51*/:
                case Type.TLSA /*52*/:
                case Service.DOMAIN /*53*/:
                case '6':
                case Service.ISI_GL /*55*/:
                case '8':
                case '9':
                    value += arr[ai] - 48;
                    break;
                case Service.TACACS_DS /*65*/:
                case Protocol.RVD /*66*/:
                case Service.BOOTPS /*67*/:
                case Service.BOOTPC /*68*/:
                case Service.TFTP /*69*/:
                case 'F':
                    value += (arr[ai] - 65) + 10;
                    break;
                case Service.SWIFT_RVF /*97*/:
                case Service.TACNEWS /*98*/:
                case Service.METAGRAM /*99*/:
                case 'd':
                case Service.HOSTNAME /*101*/:
                case Service.ISO_TSAP /*102*/:
                    value += (arr[ai] - 97) + 10;
                    break;
                default:
                    throw new IllegalArgumentException(new String(arr, offset, length));
            }
            count++;
        }
        return value;
    }

    public static String bin_to_hex(int value, int length) {
        char[] arr = new char[length];
        int ai = arr.length;
        while (true) {
            int ai2 = ai - 1;
            if (ai <= 0) {
                return new String(arr);
            }
            arr[ai2] = HEXCHARS[value & 15];
            value >>>= 4;
            ai = ai2;
        }
    }

    private static byte B(int i) {
        return (byte) (i & Type.ANY);
    }

    private static short S(int i) {
        return (short) (Message.MAXLENGTH & i);
    }

    public UUID(String str) {
        char[] arr = str.toCharArray();
        this.time_low = hex_to_bin(arr, 0, 8);
        this.time_mid = S(hex_to_bin(arr, 9, 4));
        this.time_hi_and_version = S(hex_to_bin(arr, 14, 4));
        this.clock_seq_hi_and_reserved = B(hex_to_bin(arr, 19, 2));
        this.clock_seq_low = B(hex_to_bin(arr, 21, 2));
        this.node = new byte[6];
        this.node[0] = B(hex_to_bin(arr, 24, 2));
        this.node[1] = B(hex_to_bin(arr, 26, 2));
        this.node[2] = B(hex_to_bin(arr, 28, 2));
        this.node[3] = B(hex_to_bin(arr, 30, 2));
        this.node[4] = B(hex_to_bin(arr, 32, 2));
        this.node[5] = B(hex_to_bin(arr, 34, 2));
    }

    public String toString() {
        return new StringBuffer().append(bin_to_hex(this.time_low, 8)).append('-').append(bin_to_hex(this.time_mid, 4)).append('-').append(bin_to_hex(this.time_hi_and_version, 4)).append('-').append(bin_to_hex(this.clock_seq_hi_and_reserved, 2)).append(bin_to_hex(this.clock_seq_low, 2)).append('-').append(bin_to_hex(this.node[0], 2)).append(bin_to_hex(this.node[1], 2)).append(bin_to_hex(this.node[2], 2)).append(bin_to_hex(this.node[3], 2)).append(bin_to_hex(this.node[4], 2)).append(bin_to_hex(this.node[5], 2)).toString();
    }
}
