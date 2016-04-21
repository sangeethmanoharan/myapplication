package jcifs.smb;

import java.io.IOException;
import java.util.HashMap;
import jcifs.Config;
import jcifs.UniAddress;
import jcifs.util.LogStream;
import lksystems.wifiintruder.BuildConfig;

public class Dfs {
    static final boolean DISABLED = Config.getBoolean("jcifs.smb.client.dfs.disabled", false);
    protected static CacheEntry FALSE_ENTRY = new CacheEntry(0);
    static final long TTL = Config.getLong("jcifs.smb.client.dfs.ttl", 300);
    static LogStream log = LogStream.getInstance();
    static final boolean strictView = Config.getBoolean("jcifs.smb.client.dfs.strictView", false);
    protected CacheEntry _domains = null;
    protected CacheEntry referrals = null;

    static class CacheEntry {
        long expiration;
        HashMap map;

        CacheEntry(long ttl) {
            if (ttl == 0) {
                ttl = Dfs.TTL;
            }
            this.expiration = System.currentTimeMillis() + (1000 * ttl);
            this.map = new HashMap();
        }
    }

    public HashMap getTrustedDomains(NtlmPasswordAuthentication auth) throws SmbAuthException {
        if (DISABLED) {
            return null;
        }
        if (this._domains != null && System.currentTimeMillis() > this._domains.expiration) {
            this._domains = null;
        }
        if (this._domains != null) {
            return this._domains.map;
        }
        try {
            DfsReferral[] dr = SmbTransport.getSmbTransport(UniAddress.getByName(auth.domain, true), 0).getDfsReferrals(auth, BuildConfig.VERSION_NAME, 0);
            CacheEntry entry = new CacheEntry(TTL * 10);
            for (DfsReferral dfsReferral : dr) {
                entry.map.put(dfsReferral.server, new HashMap());
            }
            this._domains = entry;
            return this._domains.map;
        } catch (IOException ioe) {
            LogStream logStream = log;
            if (LogStream.level >= 3) {
                ioe.printStackTrace(log);
            }
            if (!strictView || !(ioe instanceof SmbAuthException)) {
                return null;
            }
            throw ((SmbAuthException) ioe);
        }
    }

    public boolean isTrustedDomain(String domain, NtlmPasswordAuthentication auth) throws SmbAuthException {
        HashMap domains = getTrustedDomains(auth);
        if (domains == null || domains.get(domain.toLowerCase()) == null) {
            return false;
        }
        return true;
    }

    public SmbTransport getDc(String domain, NtlmPasswordAuthentication auth) throws SmbAuthException {
        SmbTransport smbTransport = null;
        if (!DISABLED) {
            try {
                DfsReferral[] dr = SmbTransport.getSmbTransport(UniAddress.getByName(domain, true), 0).getDfsReferrals(auth, new StringBuffer().append("\\").append(domain).toString(), 1);
                if (dr.length == 1) {
                    smbTransport = SmbTransport.getSmbTransport(UniAddress.getByName(dr[0].server), 0);
                }
            } catch (IOException ioe) {
                LogStream logStream = log;
                if (LogStream.level >= 3) {
                    ioe.printStackTrace(log);
                }
                if (strictView && (ioe instanceof SmbAuthException)) {
                    throw ((SmbAuthException) ioe);
                }
            }
        }
        return smbTransport;
    }

    public DfsReferral getReferral(SmbTransport trans, String domain, String root, String path, NtlmPasswordAuthentication auth) throws SmbAuthException {
        DfsReferral dfsReferral = null;
        if (!DISABLED) {
            try {
                String p = new StringBuffer().append("\\").append(domain).append("\\").append(root).toString();
                if (path != null) {
                    p = new StringBuffer().append(p).append(path).toString();
                }
                DfsReferral[] dr = trans.getDfsReferrals(auth, p, 1);
                if (dr.length == 1) {
                    dfsReferral = dr[0];
                }
            } catch (IOException ioe) {
                LogStream logStream = log;
                if (LogStream.level >= 3) {
                    ioe.printStackTrace(log);
                }
                if (strictView && (ioe instanceof SmbAuthException)) {
                    throw ((SmbAuthException) ioe);
                }
            }
        }
        return dfsReferral;
    }

    public synchronized DfsReferral resolve(String domain, String root, String path, NtlmPasswordAuthentication auth) throws SmbAuthException {
        DfsReferral dfsReferral;
        DfsReferral dr = null;
        long now = System.currentTimeMillis();
        if (!DISABLED) {
            if (!root.equals("IPC$")) {
                HashMap domains = getTrustedDomains(auth);
                if (domains != null) {
                    domain = domain.toLowerCase();
                    HashMap roots = (HashMap) domains.get(domain);
                    if (roots != null) {
                        SmbTransport trans = null;
                        root = root.toLowerCase();
                        CacheEntry links = (CacheEntry) roots.get(root);
                        if (links != null && now > links.expiration) {
                            roots.remove(root);
                            links = null;
                        }
                        if (links == null) {
                            trans = getDc(domain, auth);
                            if (trans == null) {
                                dfsReferral = null;
                            } else {
                                dr = getReferral(trans, domain, root, path, auth);
                                if (dr != null) {
                                    dr.pathConsumed -= ((domain.length() + 1) + 1) + root.length();
                                    CacheEntry cacheEntry = new CacheEntry(0);
                                    if (path == null) {
                                        cacheEntry.map.put("\\", dr);
                                    }
                                    roots.put(root, cacheEntry);
                                } else if (path == null) {
                                    roots.put(root, FALSE_ENTRY);
                                }
                            }
                        } else if (links == FALSE_ENTRY) {
                            links = null;
                        }
                        if (links != null) {
                            String link = "\\";
                            if (path != null) {
                                int i = path.indexOf("\\", 1);
                                link = i > 0 ? path.substring(1, i) : path.substring(1);
                            }
                            dr = (DfsReferral) links.map.get(link);
                            if (dr != null && now > dr.expiration) {
                                dr = null;
                                links.map.remove(link);
                            }
                            if (dr == null) {
                                if (trans == null) {
                                    trans = getDc(domain, auth);
                                    if (trans == null) {
                                        dfsReferral = null;
                                    }
                                }
                                dr = getReferral(trans, domain, root, path, auth);
                                if (dr != null) {
                                    dr.pathConsumed -= ((domain.length() + 1) + 1) + root.length();
                                    dr.link = link;
                                    links.map.put(link, dr);
                                }
                            }
                        }
                    }
                }
                if (dr == null && path != null) {
                    if (this.referrals != null && now > this.referrals.expiration) {
                        this.referrals = null;
                    }
                    if (this.referrals == null) {
                        this.referrals = new CacheEntry(0);
                    }
                    String key = new StringBuffer().append("\\").append(domain).append("\\").append(root).toString();
                    if (!path.equals("\\")) {
                        key = new StringBuffer().append(key).append(path).toString();
                    }
                    key = key.toLowerCase();
                    for (String _key : this.referrals.map.keySet()) {
                        int _klen = _key.length();
                        boolean match = false;
                        if (_klen == key.length()) {
                            match = _key.equals(key);
                        } else if (_klen < key.length()) {
                            match = _key.regionMatches(0, key, 0, _klen) && key.charAt(_klen) == '\\';
                        }
                        if (match) {
                            dr = (DfsReferral) this.referrals.map.get(_key);
                        }
                    }
                }
                dfsReferral = dr;
            }
        }
        dfsReferral = null;
        return dfsReferral;
    }

    synchronized void insert(String path, DfsReferral dr) {
        if (!DISABLED) {
            int s1 = path.indexOf(92, 1);
            int s2 = path.indexOf(92, s1 + 1);
            String server = path.substring(1, s1);
            String share = path.substring(s1 + 1, s2);
            String key = path.substring(0, dr.pathConsumed).toLowerCase();
            dr.pathConsumed -= ((server.length() + 1) + 1) + share.length();
            if (this.referrals != null && System.currentTimeMillis() + 10000 > this.referrals.expiration) {
                this.referrals = null;
            }
            if (this.referrals == null) {
                this.referrals = new CacheEntry(0);
            }
            this.referrals.map.put(key, dr);
        }
    }
}
