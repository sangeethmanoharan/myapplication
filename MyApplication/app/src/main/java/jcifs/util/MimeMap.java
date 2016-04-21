package jcifs.util;

import java.io.IOException;
import java.io.InputStream;

public class MimeMap {
    private static final int IN_SIZE = 7000;
    private static final int ST_COMM = 2;
    private static final int ST_EXT = 5;
    private static final int ST_GAP = 4;
    private static final int ST_START = 1;
    private static final int ST_TYPE = 3;
    private byte[] in = new byte[IN_SIZE];
    private int inLen;

    public MimeMap() throws IOException {
        InputStream is = getClass().getClassLoader().getResourceAsStream("jcifs/util/mime.map");
        this.inLen = 0;
        while (true) {
            int n = is.read(this.in, this.inLen, 7000 - this.inLen);
            if (n == -1) {
                break;
            }
            this.inLen += n;
        }
        if (this.inLen < 100 || this.inLen == IN_SIZE) {
            throw new IOException("Error reading jcifs/util/mime.map resource");
        }
        is.close();
    }

    public String getMimeType(String extension) throws IOException {
        return getMimeType(extension, "application/octet-stream");
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public java.lang.String getMimeType(java.lang.String r14, java.lang.String r15) throws java.io.IOException {
        /*
        r13 = this;
        r11 = 128; // 0x80 float:1.8E-43 double:6.3E-322;
        r8 = new byte[r11];
        r11 = 16;
        r0 = new byte[r11];
        r11 = r14.toLowerCase();
        r12 = "ASCII";
        r2 = r11.getBytes(r12);
        r5 = 1;
        r3 = 0;
        r9 = r3;
        r6 = r3;
        r4 = 0;
    L_0x0017:
        r11 = r13.inLen;
        if (r4 >= r11) goto L_0x0079;
    L_0x001b:
        r11 = r13.in;
        r1 = r11[r4];
        switch(r5) {
            case 1: goto L_0x0025;
            case 2: goto L_0x0044;
            case 3: goto L_0x0034;
            case 4: goto L_0x004d;
            case 5: goto L_0x0056;
            default: goto L_0x0022;
        };
    L_0x0022:
        r4 = r4 + 1;
        goto L_0x0017;
    L_0x0025:
        r11 = 32;
        if (r1 == r11) goto L_0x0022;
    L_0x0029:
        r11 = 9;
        if (r1 == r11) goto L_0x0022;
    L_0x002d:
        r11 = 35;
        if (r1 != r11) goto L_0x0033;
    L_0x0031:
        r5 = 2;
        goto L_0x0022;
    L_0x0033:
        r5 = 3;
    L_0x0034:
        r11 = 32;
        if (r1 == r11) goto L_0x003c;
    L_0x0038:
        r11 = 9;
        if (r1 != r11) goto L_0x003e;
    L_0x003c:
        r5 = 4;
        goto L_0x0022;
    L_0x003e:
        r7 = r6 + 1;
        r8[r6] = r1;
        r6 = r7;
        goto L_0x0022;
    L_0x0044:
        r11 = 10;
        if (r1 != r11) goto L_0x0022;
    L_0x0048:
        r3 = 0;
        r9 = r3;
        r6 = r3;
        r5 = 1;
        goto L_0x0022;
    L_0x004d:
        r11 = 32;
        if (r1 == r11) goto L_0x0022;
    L_0x0051:
        r11 = 9;
        if (r1 == r11) goto L_0x0022;
    L_0x0055:
        r5 = 5;
    L_0x0056:
        switch(r1) {
            case 9: goto L_0x005f;
            case 10: goto L_0x005f;
            case 32: goto L_0x005f;
            case 35: goto L_0x005f;
            default: goto L_0x0059;
        };
    L_0x0059:
        r10 = r9 + 1;
        r0[r9] = r1;
        r9 = r10;
        goto L_0x0022;
    L_0x005f:
        r3 = 0;
    L_0x0060:
        if (r3 >= r9) goto L_0x006e;
    L_0x0062:
        r11 = r2.length;
        if (r9 != r11) goto L_0x006e;
    L_0x0065:
        r11 = r0[r3];
        r12 = r2[r3];
        if (r11 != r12) goto L_0x006e;
    L_0x006b:
        r3 = r3 + 1;
        goto L_0x0060;
    L_0x006e:
        r11 = r2.length;
        if (r3 != r11) goto L_0x007a;
    L_0x0071:
        r15 = new java.lang.String;
        r11 = 0;
        r12 = "ASCII";
        r15.<init>(r8, r11, r6, r12);
    L_0x0079:
        return r15;
    L_0x007a:
        r11 = 35;
        if (r1 != r11) goto L_0x0081;
    L_0x007e:
        r5 = 2;
    L_0x007f:
        r9 = 0;
        goto L_0x0022;
    L_0x0081:
        r11 = 10;
        if (r1 != r11) goto L_0x007f;
    L_0x0085:
        r3 = 0;
        r9 = r3;
        r6 = r3;
        r5 = 1;
        goto L_0x007f;
        */
        throw new UnsupportedOperationException("Method not decompiled: jcifs.util.MimeMap.getMimeType(java.lang.String, java.lang.String):java.lang.String");
    }
}
