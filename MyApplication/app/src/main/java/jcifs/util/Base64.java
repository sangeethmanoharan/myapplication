package jcifs.util;

import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.Type;

public class Base64 {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static String encode(byte[] bytes) {
        int length = bytes.length;
        if (length == 0) {
            return BuildConfig.VERSION_NAME;
        }
        StringBuffer buffer = new StringBuffer(((int) Math.ceil(((double) length) / 3.0d)) * 4);
        int remainder = length % 3;
        length -= remainder;
        int i = 0;
        while (i < length) {
            int i2 = i + 1;
            i = i2 + 1;
            i2 = i + 1;
            int block = (((bytes[i] & Type.ANY) << 16) | ((bytes[i2] & Type.ANY) << 8)) | (bytes[i] & Type.ANY);
            buffer.append(ALPHABET.charAt(block >>> 18));
            buffer.append(ALPHABET.charAt((block >>> 12) & 63));
            buffer.append(ALPHABET.charAt((block >>> 6) & 63));
            buffer.append(ALPHABET.charAt(block & 63));
            i = i2;
        }
        if (remainder == 0) {
            return buffer.toString();
        }
        if (remainder == 1) {
            block = (bytes[i] & Type.ANY) << 4;
            buffer.append(ALPHABET.charAt(block >>> 6));
            buffer.append(ALPHABET.charAt(block & 63));
            buffer.append("==");
            return buffer.toString();
        }
        block = (((bytes[i] & Type.ANY) << 8) | (bytes[i + 1] & Type.ANY)) << 2;
        buffer.append(ALPHABET.charAt(block >>> 12));
        buffer.append(ALPHABET.charAt((block >>> 6) & 63));
        buffer.append(ALPHABET.charAt(block & 63));
        buffer.append("=");
        return buffer.toString();
    }

    public static byte[] decode(String string) {
        int pad = 0;
        int length = string.length();
        if (length == 0) {
            return new byte[0];
        }
        if (string.charAt(length - 2) == '=') {
            pad = 2;
        } else if (string.charAt(length - 1) == '=') {
            pad = 1;
        }
        int size = ((length * 3) / 4) - pad;
        byte[] buffer = new byte[size];
        int index = 0;
        int i = 0;
        while (i < length) {
            int i2 = i + 1;
            i = i2 + 1;
            i2 = i + 1;
            i = i2 + 1;
            int block = ((((ALPHABET.indexOf(string.charAt(i)) & Type.ANY) << 18) | ((ALPHABET.indexOf(string.charAt(i2)) & Type.ANY) << 12)) | ((ALPHABET.indexOf(string.charAt(i)) & Type.ANY) << 6)) | (ALPHABET.indexOf(string.charAt(i2)) & Type.ANY);
            int index2 = index + 1;
            buffer[index] = (byte) (block >>> 16);
            if (index2 < size) {
                index = index2 + 1;
                buffer[index2] = (byte) ((block >>> 8) & Type.ANY);
            } else {
                index = index2;
            }
            if (index < size) {
                index2 = index + 1;
                buffer[index] = (byte) (block & Type.ANY);
                index = index2;
            }
        }
        return buffer;
    }
}
