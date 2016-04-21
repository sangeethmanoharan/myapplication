package jcifs.smb;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import jcifs.util.LogStream;

class Trans2FindFirst2Response extends SmbComTransactionResponse {
    static final int SMB_FILE_BOTH_DIRECTORY_INFO = 260;
    static final int SMB_FILE_NAMES_INFO = 259;
    static final int SMB_FIND_FILE_DIRECTORY_INFO = 257;
    static final int SMB_FIND_FILE_FULL_DIRECTORY_INFO = 258;
    static final int SMB_INFO_QUERY_EAS_FROM_LIST = 3;
    static final int SMB_INFO_QUERY_EA_SIZE = 2;
    static final int SMB_INFO_STANDARD = 1;
    int eaErrorOffset;
    boolean isEndOfSearch;
    String lastName;
    int lastNameBufferIndex;
    int lastNameOffset;
    int resumeKey;
    int sid;

    class SmbFindFileBothDirectoryInfo implements FileEntry {
        long allocationSize;
        long changeTime;
        long creationTime;
        int eaSize;
        long endOfFile;
        int extFileAttributes;
        int fileIndex;
        int fileNameLength;
        String filename;
        long lastAccessTime;
        long lastWriteTime;
        int nextEntryOffset;
        String shortName;
        int shortNameLength;
        private final Trans2FindFirst2Response this$0;

        SmbFindFileBothDirectoryInfo(Trans2FindFirst2Response this$0) {
            this.this$0 = this$0;
        }

        public String getName() {
            return this.filename;
        }

        public int getType() {
            return Trans2FindFirst2Response.SMB_INFO_STANDARD;
        }

        public int getAttributes() {
            return this.extFileAttributes;
        }

        public long createTime() {
            return this.creationTime;
        }

        public long lastModified() {
            return this.lastWriteTime;
        }

        public long length() {
            return this.endOfFile;
        }

        public String toString() {
            return new String(new StringBuffer().append("SmbFindFileBothDirectoryInfo[nextEntryOffset=").append(this.nextEntryOffset).append(",fileIndex=").append(this.fileIndex).append(",creationTime=").append(new Date(this.creationTime)).append(",lastAccessTime=").append(new Date(this.lastAccessTime)).append(",lastWriteTime=").append(new Date(this.lastWriteTime)).append(",changeTime=").append(new Date(this.changeTime)).append(",endOfFile=").append(this.endOfFile).append(",allocationSize=").append(this.allocationSize).append(",extFileAttributes=").append(this.extFileAttributes).append(",fileNameLength=").append(this.fileNameLength).append(",eaSize=").append(this.eaSize).append(",shortNameLength=").append(this.shortNameLength).append(",shortName=").append(this.shortName).append(",filename=").append(this.filename).append("]").toString());
        }
    }

    Trans2FindFirst2Response() {
        this.command = (byte) 50;
        this.subCommand = (byte) 1;
    }

    String readString(byte[] src, int srcIndex, int len) {
        try {
            if (this.useUnicode) {
                return new String(src, srcIndex, len, "UnicodeLittleUnmarked");
            }
            if (len > 0 && src[(srcIndex + len) - 1] == (byte) 0) {
                len--;
            }
            return new String(src, srcIndex, len, SmbConstants.OEM_ENCODING);
        } catch (UnsupportedEncodingException uee) {
            LogStream logStream = log;
            if (LogStream.level <= SMB_INFO_STANDARD) {
                return null;
            }
            uee.printStackTrace(log);
            return null;
        }
    }

    int writeSetupWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeParametersWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int writeDataWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
        boolean z = true;
        int start = bufferIndex;
        if (this.subCommand == (byte) 1) {
            this.sid = ServerMessageBlock.readInt2(buffer, bufferIndex);
            bufferIndex += SMB_INFO_QUERY_EA_SIZE;
        }
        this.numEntries = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += SMB_INFO_QUERY_EA_SIZE;
        if ((buffer[bufferIndex] & SMB_INFO_STANDARD) != SMB_INFO_STANDARD) {
            z = false;
        }
        this.isEndOfSearch = z;
        bufferIndex += SMB_INFO_QUERY_EA_SIZE;
        this.eaErrorOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += SMB_INFO_QUERY_EA_SIZE;
        this.lastNameOffset = ServerMessageBlock.readInt2(buffer, bufferIndex);
        return (bufferIndex + SMB_INFO_QUERY_EA_SIZE) - start;
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
        int start = bufferIndex;
        this.lastNameBufferIndex = this.lastNameOffset + bufferIndex;
        this.results = new SmbFindFileBothDirectoryInfo[this.numEntries];
        for (int i = 0; i < this.numEntries; i += SMB_INFO_STANDARD) {
            FileEntry[] fileEntryArr = this.results;
            SmbFindFileBothDirectoryInfo e = new SmbFindFileBothDirectoryInfo(this);
            fileEntryArr[i] = e;
            e.nextEntryOffset = ServerMessageBlock.readInt4(buffer, bufferIndex);
            e.fileIndex = ServerMessageBlock.readInt4(buffer, bufferIndex + 4);
            e.creationTime = ServerMessageBlock.readTime(buffer, bufferIndex + 8);
            e.lastWriteTime = ServerMessageBlock.readTime(buffer, bufferIndex + 24);
            e.endOfFile = ServerMessageBlock.readInt8(buffer, bufferIndex + 40);
            e.extFileAttributes = ServerMessageBlock.readInt4(buffer, bufferIndex + 56);
            e.fileNameLength = ServerMessageBlock.readInt4(buffer, bufferIndex + 60);
            e.filename = readString(buffer, bufferIndex + 94, e.fileNameLength);
            if (this.lastNameBufferIndex >= bufferIndex && (e.nextEntryOffset == 0 || this.lastNameBufferIndex < e.nextEntryOffset + bufferIndex)) {
                this.lastName = e.filename;
                this.resumeKey = e.fileIndex;
            }
            bufferIndex += e.nextEntryOffset;
        }
        return this.dataCount;
    }

    public String toString() {
        String c;
        if (this.subCommand == (byte) 1) {
            c = "Trans2FindFirst2Response[";
        } else {
            c = "Trans2FindNext2Response[";
        }
        return new String(new StringBuffer().append(c).append(super.toString()).append(",sid=").append(this.sid).append(",searchCount=").append(this.numEntries).append(",isEndOfSearch=").append(this.isEndOfSearch).append(",eaErrorOffset=").append(this.eaErrorOffset).append(",lastNameOffset=").append(this.lastNameOffset).append(",lastName=").append(this.lastName).append("]").toString());
    }
}
