package org.xbill.DNS;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public final class Address {
    public static final int IPv4 = 1;
    public static final int IPv6 = 2;

    private Address() {
    }

    private static byte[] parseV4(String s) {
        byte[] values = new byte[4];
        int length = s.length();
        int currentValue = 0;
        int numDigits = 0;
        int i = 0;
        int currentOctet = 0;
        while (i < length) {
            int currentOctet2;
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                if (c != '.') {
                    return null;
                }
                if (currentOctet == 3) {
                    return null;
                }
                if (numDigits == 0) {
                    return null;
                }
                currentOctet2 = currentOctet + IPv4;
                values[currentOctet] = (byte) currentValue;
                currentValue = 0;
                numDigits = 0;
            } else if (numDigits == 3) {
                return null;
            } else {
                if (numDigits > 0 && currentValue == 0) {
                    return null;
                }
                numDigits += IPv4;
                currentValue = (currentValue * 10) + (c - 48);
                if (currentValue > Type.ANY) {
                    return null;
                }
                currentOctet2 = currentOctet;
            }
            i += IPv4;
            currentOctet = currentOctet2;
        }
        if (currentOctet != 3) {
            return null;
        }
        if (numDigits == 0) {
            return null;
        }
        values[currentOctet] = (byte) currentValue;
        return values;
    }

    private static byte[] parseV6(String s) {
        int range = -1;
        byte[] data = new byte[16];
        String[] tokens = s.split(":", -1);
        int first = 0;
        int last = tokens.length - 1;
        if (tokens[0].length() == 0) {
            if (last - 0 <= 0 || tokens[IPv4].length() != 0) {
                return null;
            }
            first = 0 + IPv4;
        }
        if (tokens[last].length() == 0) {
            if (last - first <= 0 || tokens[last - 1].length() != 0) {
                return null;
            }
            last--;
        }
        if ((last - first) + IPv4 > 8) {
            return null;
        }
        int j;
        int empty;
        int i = first;
        int j2 = 0;
        while (i <= last) {
            if (tokens[i].length() == 0) {
                if (range >= 0) {
                    return null;
                }
                range = j2;
                j = j2;
            } else if (tokens[i].indexOf(46) < 0) {
                for (k = 0; k < tokens[i].length(); k += IPv4) {
                    if (Character.digit(tokens[i].charAt(k), 16) < 0) {
                        return null;
                    }
                }
                int x = Integer.parseInt(tokens[i], 16);
                if (x > 65535 || x < 0) {
                    return null;
                }
                j = j2 + IPv4;
                try {
                    data[j2] = (byte) (x >>> 8);
                    j2 = j + IPv4;
                } catch (NumberFormatException e) {
                }
                try {
                    data[j] = (byte) (x & Type.ANY);
                    j = j2;
                } catch (NumberFormatException e2) {
                    j = j2;
                }
            } else if (i < last) {
                return null;
            } else {
                if (i > 6) {
                    return null;
                }
                byte[] v4addr = toByteArray(tokens[i], IPv4);
                if (v4addr == null) {
                    return null;
                }
                k = 0;
                while (k < 4) {
                    j = j2 + IPv4;
                    data[j2] = v4addr[k];
                    k += IPv4;
                    j2 = j;
                }
                j = j2;
                if (j >= 16 && range < 0) {
                    return null;
                }
                if (range >= 0) {
                    return data;
                }
                empty = 16 - j;
                System.arraycopy(data, range, data, range + empty, j - range);
                for (i = range; i < range + empty; i += IPv4) {
                    data[i] = (byte) 0;
                }
                return data;
            }
            i += IPv4;
            j2 = j;
        }
        j = j2;
        if (j >= 16) {
        }
        if (range >= 0) {
            return data;
        }
        empty = 16 - j;
        System.arraycopy(data, range, data, range + empty, j - range);
        for (i = range; i < range + empty; i += IPv4) {
            data[i] = (byte) 0;
        }
        return data;
        return null;
    }

    public static int[] toArray(String s, int family) {
        byte[] byteArray = toByteArray(s, family);
        if (byteArray == null) {
            return null;
        }
        int[] intArray = new int[byteArray.length];
        for (int i = 0; i < byteArray.length; i += IPv4) {
            intArray[i] = byteArray[i] & Type.ANY;
        }
        return intArray;
    }

    public static int[] toArray(String s) {
        return toArray(s, IPv4);
    }

    public static byte[] toByteArray(String s, int family) {
        if (family == IPv4) {
            return parseV4(s);
        }
        if (family == IPv6) {
            return parseV6(s);
        }
        throw new IllegalArgumentException("unknown address family");
    }

    public static boolean isDottedQuad(String s) {
        if (toByteArray(s, IPv4) != null) {
            return true;
        }
        return false;
    }

    public static String toDottedQuad(byte[] addr) {
        return new StringBuffer().append(addr[0] & Type.ANY).append(".").append(addr[IPv4] & Type.ANY).append(".").append(addr[IPv6] & Type.ANY).append(".").append(addr[3] & Type.ANY).toString();
    }

    public static String toDottedQuad(int[] addr) {
        return new StringBuffer().append(addr[0]).append(".").append(addr[IPv4]).append(".").append(addr[IPv6]).append(".").append(addr[3]).toString();
    }

    private static Record[] lookupHostName(String name) throws UnknownHostException {
        try {
            Record[] records = new Lookup(name).run();
            if (records != null) {
                return records;
            }
            throw new UnknownHostException("unknown host");
        } catch (TextParseException e) {
            throw new UnknownHostException("invalid name");
        }
    }

    private static InetAddress addrFromRecord(String name, Record r) throws UnknownHostException {
        return InetAddress.getByAddress(name, ((ARecord) r).getAddress().getAddress());
    }

    public static InetAddress getByName(String name) throws UnknownHostException {
        try {
            return getByAddress(name);
        } catch (UnknownHostException e) {
            return addrFromRecord(name, lookupHostName(name)[0]);
        }
    }

    public static InetAddress[] getAllByName(String name) throws UnknownHostException {
        InetAddress[] inetAddressArr;
        try {
            inetAddressArr = new InetAddress[IPv4];
            inetAddressArr[0] = getByAddress(name);
            return inetAddressArr;
        } catch (UnknownHostException e) {
            Record[] records = lookupHostName(name);
            inetAddressArr = new InetAddress[records.length];
            for (int i = 0; i < records.length; i += IPv4) {
                inetAddressArr[i] = addrFromRecord(name, records[i]);
            }
            return inetAddressArr;
        }
    }

    public static InetAddress getByAddress(String addr) throws UnknownHostException {
        byte[] bytes = toByteArray(addr, IPv4);
        if (bytes != null) {
            return InetAddress.getByAddress(addr, bytes);
        }
        bytes = toByteArray(addr, IPv6);
        if (bytes != null) {
            return InetAddress.getByAddress(addr, bytes);
        }
        throw new UnknownHostException(new StringBuffer().append("Invalid address: ").append(addr).toString());
    }

    public static InetAddress getByAddress(String addr, int family) throws UnknownHostException {
        if (family == IPv4 || family == IPv6) {
            byte[] bytes = toByteArray(addr, family);
            if (bytes != null) {
                return InetAddress.getByAddress(addr, bytes);
            }
            throw new UnknownHostException(new StringBuffer().append("Invalid address: ").append(addr).toString());
        }
        throw new IllegalArgumentException("unknown address family");
    }

    public static String getHostName(InetAddress addr) throws UnknownHostException {
        Record[] records = new Lookup(ReverseMap.fromAddress(addr), 12).run();
        if (records != null) {
            return records[0].getTarget().toString();
        }
        throw new UnknownHostException("unknown address");
    }

    public static int familyOf(InetAddress address) {
        if (address instanceof Inet4Address) {
            return IPv4;
        }
        if (address instanceof Inet6Address) {
            return IPv6;
        }
        throw new IllegalArgumentException("unknown address family");
    }

    public static int addressLength(int family) {
        if (family == IPv4) {
            return 4;
        }
        if (family == IPv6) {
            return 16;
        }
        throw new IllegalArgumentException("unknown address family");
    }

    public static InetAddress truncate(InetAddress address, int maskLength) {
        int maxMaskLength = addressLength(familyOf(address)) * 8;
        if (maskLength < 0 || maskLength > maxMaskLength) {
            throw new IllegalArgumentException("invalid mask length");
        }
        if (maskLength != maxMaskLength) {
            int i;
            byte[] bytes = address.getAddress();
            for (i = (maskLength / 8) + IPv4; i < bytes.length; i += IPv4) {
                bytes[i] = (byte) 0;
            }
            int bitmask = 0;
            for (i = 0; i < maskLength % 8; i += IPv4) {
                bitmask |= IPv4 << (7 - i);
            }
            int i2 = maskLength / 8;
            bytes[i2] = (byte) (bytes[i2] & bitmask);
            try {
                address = InetAddress.getByAddress(bytes);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("invalid address");
            }
        }
        return address;
    }
}
