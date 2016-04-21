package jcifs.smb;

public class DfsReferral extends SmbException {
    public long expiration;
    public String link;
    public String path;
    public int pathConsumed;
    public boolean resolveHashes;
    public String server;
    public String share;
    public long ttl;

    public String toString() {
        return new StringBuffer().append("DfsReferral[pathConsumed=").append(this.pathConsumed).append(",server=").append(this.server).append(",share=").append(this.share).append(",link=").append(this.link).append(",path=").append(this.path).append(",ttl=").append(this.ttl).append(",expiration=").append(this.expiration).append(",resolveHashes=").append(this.resolveHashes).append("]").toString();
    }
}
