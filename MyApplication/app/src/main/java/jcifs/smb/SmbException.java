package jcifs.smb;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import jcifs.util.Hexdump;
import lksystems.wifiintruder.BuildConfig;

public class SmbException extends IOException implements DosError, NtStatus, WinError {
    private Throwable rootCause;
    private int status;

    static String getMessageByCode(int errcode) {
        if (errcode == 0) {
            return "NT_STATUS_SUCCESS";
        }
        int min;
        int max;
        int mid;
        if ((errcode & -1073741824) == -1073741824) {
            min = 1;
            max = NtStatus.NT_STATUS_CODES.length - 1;
            while (max >= min) {
                mid = (min + max) / 2;
                if (errcode > NtStatus.NT_STATUS_CODES[mid]) {
                    min = mid + 1;
                } else if (errcode >= NtStatus.NT_STATUS_CODES[mid]) {
                    return NtStatus.NT_STATUS_MESSAGES[mid];
                } else {
                    max = mid - 1;
                }
            }
        } else {
            min = 0;
            max = DosError.DOS_ERROR_CODES.length - 1;
            while (max >= min) {
                mid = (min + max) / 2;
                if (errcode > DosError.DOS_ERROR_CODES[mid][0]) {
                    min = mid + 1;
                } else if (errcode >= DosError.DOS_ERROR_CODES[mid][0]) {
                    return DosError.DOS_ERROR_MESSAGES[mid];
                } else {
                    max = mid - 1;
                }
            }
        }
        return new StringBuffer().append("0x").append(Hexdump.toHexString(errcode, 8)).toString();
    }

    static int getStatusByCode(int errcode) {
        if ((-1073741824 & errcode) != 0) {
            return errcode;
        }
        int min = 0;
        int max = DosError.DOS_ERROR_CODES.length - 1;
        while (max >= min) {
            int mid = (min + max) / 2;
            if (errcode > DosError.DOS_ERROR_CODES[mid][0]) {
                min = mid + 1;
            } else if (errcode >= DosError.DOS_ERROR_CODES[mid][0]) {
                return DosError.DOS_ERROR_CODES[mid][1];
            } else {
                max = mid - 1;
            }
        }
        return NtStatus.NT_STATUS_UNSUCCESSFUL;
    }

    static String getMessageByWinerrCode(int errcode) {
        int min = 0;
        int max = WinError.WINERR_CODES.length - 1;
        while (max >= min) {
            int mid = (min + max) / 2;
            if (errcode > WinError.WINERR_CODES[mid]) {
                min = mid + 1;
            } else if (errcode >= WinError.WINERR_CODES[mid]) {
                return WinError.WINERR_MESSAGES[mid];
            } else {
                max = mid - 1;
            }
        }
        return new StringBuffer().append(errcode).append(BuildConfig.VERSION_NAME).toString();
    }

    SmbException() {
    }

    SmbException(int errcode, Throwable rootCause) {
        super(getMessageByCode(errcode));
        this.status = getStatusByCode(errcode);
        this.rootCause = rootCause;
    }

    SmbException(String msg) {
        super(msg);
        this.status = NtStatus.NT_STATUS_UNSUCCESSFUL;
    }

    SmbException(String msg, Throwable rootCause) {
        super(msg);
        this.rootCause = rootCause;
        this.status = NtStatus.NT_STATUS_UNSUCCESSFUL;
    }

    public SmbException(int errcode, boolean winerr) {
        super(winerr ? getMessageByWinerrCode(errcode) : getMessageByCode(errcode));
        if (!winerr) {
            errcode = getStatusByCode(errcode);
        }
        this.status = errcode;
    }

    public int getNtStatus() {
        return this.status;
    }

    public Throwable getRootCause() {
        return this.rootCause;
    }

    public String toString() {
        if (this.rootCause == null) {
            return super.toString();
        }
        StringWriter sw = new StringWriter();
        this.rootCause.printStackTrace(new PrintWriter(sw));
        return new StringBuffer().append(super.toString()).append("\n").append(sw).toString();
    }
}
