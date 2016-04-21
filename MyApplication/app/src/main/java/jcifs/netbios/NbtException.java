package jcifs.netbios;

import java.io.IOException;
import lksystems.wifiintruder.BuildConfig;

public class NbtException extends IOException {
    public static final int ACT_ERR = 6;
    public static final int CALLED_NOT_PRESENT = 130;
    public static final int CFT_ERR = 7;
    public static final int CONNECTION_REFUSED = -1;
    public static final int ERR_NAM_SRVC = 1;
    public static final int ERR_SSN_SRVC = 2;
    public static final int FMT_ERR = 1;
    public static final int IMP_ERR = 4;
    public static final int NOT_LISTENING_CALLED = 128;
    public static final int NOT_LISTENING_CALLING = 129;
    public static final int NO_RESOURCES = 131;
    public static final int RFS_ERR = 5;
    public static final int SRV_ERR = 2;
    public static final int SUCCESS = 0;
    public static final int UNSPECIFIED = 143;
    public int errorClass;
    public int errorCode;

    public static String getErrorString(int errorClass, int errorCode) {
        String result = BuildConfig.VERSION_NAME;
        switch (errorClass) {
            case SUCCESS /*0*/:
                return new StringBuffer().append(result).append("SUCCESS").toString();
            case FMT_ERR /*1*/:
                result = new StringBuffer().append(result).append("ERR_NAM_SRVC/").toString();
                switch (errorCode) {
                    case FMT_ERR /*1*/:
                        result = new StringBuffer().append(result).append("FMT_ERR: Format Error").toString();
                        break;
                }
                return new StringBuffer().append(result).append("Unknown error code: ").append(errorCode).toString();
            case SRV_ERR /*2*/:
                result = new StringBuffer().append(result).append("ERR_SSN_SRVC/").toString();
                switch (errorCode) {
                    case CONNECTION_REFUSED /*-1*/:
                        return new StringBuffer().append(result).append("Connection refused").toString();
                    case NOT_LISTENING_CALLED /*128*/:
                        return new StringBuffer().append(result).append("Not listening on called name").toString();
                    case NOT_LISTENING_CALLING /*129*/:
                        return new StringBuffer().append(result).append("Not listening for calling name").toString();
                    case CALLED_NOT_PRESENT /*130*/:
                        return new StringBuffer().append(result).append("Called name not present").toString();
                    case NO_RESOURCES /*131*/:
                        return new StringBuffer().append(result).append("Called name present, but insufficient resources").toString();
                    case UNSPECIFIED /*143*/:
                        return new StringBuffer().append(result).append("Unspecified error").toString();
                    default:
                        return new StringBuffer().append(result).append("Unknown error code: ").append(errorCode).toString();
                }
            default:
                return new StringBuffer().append(result).append("unknown error class: ").append(errorClass).toString();
        }
    }

    public NbtException(int errorClass, int errorCode) {
        super(getErrorString(errorClass, errorCode));
        this.errorClass = errorClass;
        this.errorCode = errorCode;
    }

    public String toString() {
        return new String(new StringBuffer().append("errorClass=").append(this.errorClass).append(",errorCode=").append(this.errorCode).append(",errorString=").append(getErrorString(this.errorClass, this.errorCode)).toString());
    }
}
