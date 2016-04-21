package jcifs.http;

import java.io.IOException;
import java.util.Enumeration;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jcifs.Config;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.util.LogStream;

public class NtlmHttpFilter implements Filter {
    private static LogStream log = LogStream.getInstance();
    private String defaultDomain;
    private String domainController;
    private boolean enableBasic;
    private boolean insecureBasic;
    private boolean loadBalance;
    private String realm;

    public void init(FilterConfig filterConfig) throws ServletException {
        Config.setProperty("jcifs.smb.client.soTimeout", "300000");
        Config.setProperty("jcifs.netbios.cachePolicy", "1200");
        Enumeration e = filterConfig.getInitParameterNames();
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            if (name.startsWith("jcifs.")) {
                Config.setProperty(name, filterConfig.getInitParameter(name));
            }
        }
        this.defaultDomain = Config.getProperty("jcifs.smb.client.domain");
        this.domainController = Config.getProperty("jcifs.http.domainController");
        if (this.domainController == null) {
            this.domainController = this.defaultDomain;
            this.loadBalance = Config.getBoolean("jcifs.http.loadBalance", true);
        }
        this.enableBasic = Boolean.valueOf(Config.getProperty("jcifs.http.enableBasic")).booleanValue();
        this.insecureBasic = Boolean.valueOf(Config.getProperty("jcifs.http.insecureBasic")).booleanValue();
        this.realm = Config.getProperty("jcifs.http.basicRealm");
        if (this.realm == null) {
            this.realm = "jCIFS";
        }
        int level = Config.getInt("jcifs.util.loglevel", -1);
        if (level != -1) {
            LogStream.setLevel(level);
        }
        LogStream logStream = log;
        if (LogStream.level > 2) {
            try {
                Config.store(log, "JCIFS PROPERTIES");
            } catch (IOException e2) {
            }
        }
    }

    public void destroy() {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        NtlmPasswordAuthentication ntlm = negotiate(req, (HttpServletResponse) response, false);
        if (ntlm != null) {
            chain.doFilter(new NtlmHttpServletRequest(req, ntlm), response);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    protected jcifs.smb.NtlmPasswordAuthentication negotiate(javax.servlet.http.HttpServletRequest r20, javax.servlet.http.HttpServletResponse r21, boolean r22) throws java.io.IOException, javax.servlet.ServletException {
        /*
        r19 = this;
        r9 = 0;
        r15 = "Authorization";
        r0 = r20;
        r8 = r0.getHeader(r15);
        r0 = r19;
        r15 = r0.enableBasic;
        if (r15 == 0) goto L_0x0065;
    L_0x000f:
        r0 = r19;
        r15 = r0.insecureBasic;
        if (r15 != 0) goto L_0x001b;
    L_0x0015:
        r15 = r20.isSecure();
        if (r15 == 0) goto L_0x0065;
    L_0x001b:
        r10 = 1;
    L_0x001c:
        if (r8 == 0) goto L_0x01c7;
    L_0x001e:
        r15 = "NTLM ";
        r15 = r8.startsWith(r15);
        if (r15 != 0) goto L_0x0030;
    L_0x0026:
        if (r10 == 0) goto L_0x01c7;
    L_0x0028:
        r15 = "Basic ";
        r15 = r8.startsWith(r15);
        if (r15 == 0) goto L_0x01c7;
    L_0x0030:
        r15 = "NTLM ";
        r15 = r8.startsWith(r15);
        if (r15 == 0) goto L_0x00bb;
    L_0x0038:
        r13 = r20.getSession();
        r0 = r19;
        r15 = r0.loadBalance;
        if (r15 == 0) goto L_0x0067;
    L_0x0042:
        r15 = "NtlmHttpChal";
        r3 = r13.getAttribute(r15);
        r3 = (jcifs.smb.NtlmChallenge) r3;
        if (r3 != 0) goto L_0x0055;
    L_0x004c:
        r3 = jcifs.smb.SmbSession.getChallengeForDomain();
        r15 = "NtlmHttpChal";
        r13.setAttribute(r15, r3);
    L_0x0055:
        r5 = r3.dc;
        r4 = r3.challenge;
    L_0x0059:
        r0 = r20;
        r1 = r21;
        r9 = jcifs.http.NtlmSsp.authenticate(r0, r1, r4);
        if (r9 != 0) goto L_0x0076;
    L_0x0063:
        r15 = 0;
    L_0x0064:
        return r15;
    L_0x0065:
        r10 = 0;
        goto L_0x001c;
    L_0x0067:
        r0 = r19;
        r15 = r0.domainController;
        r16 = 1;
        r5 = jcifs.UniAddress.getByName(r15, r16);
        r4 = jcifs.smb.SmbSession.getChallenge(r5);
        goto L_0x0059;
    L_0x0076:
        r15 = "NtlmHttpChal";
        r13.removeAttribute(r15);
    L_0x007b:
        jcifs.smb.SmbSession.logon(r5, r9);	 Catch:{ SmbAuthException -> 0x011f }
        r15 = log;	 Catch:{ SmbAuthException -> 0x011f }
        r15 = jcifs.util.LogStream.level;	 Catch:{ SmbAuthException -> 0x011f }
        r16 = 2;
        r0 = r16;
        if (r15 <= r0) goto L_0x00ae;
    L_0x0088:
        r15 = log;	 Catch:{ SmbAuthException -> 0x011f }
        r16 = new java.lang.StringBuffer;	 Catch:{ SmbAuthException -> 0x011f }
        r16.<init>();	 Catch:{ SmbAuthException -> 0x011f }
        r17 = "NtlmHttpFilter: ";
        r16 = r16.append(r17);	 Catch:{ SmbAuthException -> 0x011f }
        r0 = r16;
        r16 = r0.append(r9);	 Catch:{ SmbAuthException -> 0x011f }
        r17 = " successfully authenticated against ";
        r16 = r16.append(r17);	 Catch:{ SmbAuthException -> 0x011f }
        r0 = r16;
        r16 = r0.append(r5);	 Catch:{ SmbAuthException -> 0x011f }
        r16 = r16.toString();	 Catch:{ SmbAuthException -> 0x011f }
        r15.println(r16);	 Catch:{ SmbAuthException -> 0x011f }
    L_0x00ae:
        r15 = r20.getSession();
        r16 = "NtlmHttpAuth";
        r0 = r16;
        r15.setAttribute(r0, r9);
    L_0x00b9:
        r15 = r9;
        goto L_0x0064;
    L_0x00bb:
        r2 = new java.lang.String;
        r15 = 6;
        r15 = r8.substring(r15);
        r15 = jcifs.util.Base64.decode(r15);
        r16 = "US-ASCII";
        r0 = r16;
        r2.<init>(r15, r0);
        r15 = 58;
        r7 = r2.indexOf(r15);
        r15 = -1;
        if (r7 == r15) goto L_0x0115;
    L_0x00d6:
        r15 = 0;
        r14 = r2.substring(r15, r7);
    L_0x00db:
        r15 = -1;
        if (r7 == r15) goto L_0x0117;
    L_0x00de:
        r15 = r7 + 1;
        r11 = r2.substring(r15);
    L_0x00e4:
        r15 = 92;
        r7 = r14.indexOf(r15);
        r15 = -1;
        if (r7 != r15) goto L_0x00f3;
    L_0x00ed:
        r15 = 47;
        r7 = r14.indexOf(r15);
    L_0x00f3:
        r15 = -1;
        if (r7 == r15) goto L_0x011a;
    L_0x00f6:
        r15 = 0;
        r6 = r14.substring(r15, r7);
    L_0x00fb:
        r15 = -1;
        if (r7 == r15) goto L_0x0104;
    L_0x00fe:
        r15 = r7 + 1;
        r14 = r14.substring(r15);
    L_0x0104:
        r9 = new jcifs.smb.NtlmPasswordAuthentication;
        r9.<init>(r6, r14, r11);
        r0 = r19;
        r15 = r0.domainController;
        r16 = 1;
        r5 = jcifs.UniAddress.getByName(r15, r16);
        goto L_0x007b;
    L_0x0115:
        r14 = r2;
        goto L_0x00db;
    L_0x0117:
        r11 = "";
        goto L_0x00e4;
    L_0x011a:
        r0 = r19;
        r6 = r0.defaultDomain;
        goto L_0x00fb;
    L_0x011f:
        r12 = move-exception;
        r15 = log;
        r15 = jcifs.util.LogStream.level;
        r16 = 1;
        r0 = r16;
        if (r15 <= r0) goto L_0x0166;
    L_0x012a:
        r15 = log;
        r16 = new java.lang.StringBuffer;
        r16.<init>();
        r17 = "NtlmHttpFilter: ";
        r16 = r16.append(r17);
        r17 = r9.getName();
        r16 = r16.append(r17);
        r17 = ": 0x";
        r16 = r16.append(r17);
        r17 = r12.getNtStatus();
        r18 = 8;
        r17 = jcifs.util.Hexdump.toHexString(r17, r18);
        r16 = r16.append(r17);
        r17 = ": ";
        r16 = r16.append(r17);
        r0 = r16;
        r16 = r0.append(r12);
        r16 = r16.toString();
        r15.println(r16);
    L_0x0166:
        r15 = r12.getNtStatus();
        r16 = -1073741819; // 0xffffffffc0000005 float:-2.0000012 double:NaN;
        r0 = r16;
        if (r15 != r0) goto L_0x017f;
    L_0x0171:
        r15 = 0;
        r0 = r20;
        r13 = r0.getSession(r15);
        if (r13 == 0) goto L_0x017f;
    L_0x017a:
        r15 = "NtlmHttpAuth";
        r13.removeAttribute(r15);
    L_0x017f:
        r15 = "WWW-Authenticate";
        r16 = "NTLM";
        r0 = r21;
        r1 = r16;
        r0.setHeader(r15, r1);
        if (r10 == 0) goto L_0x01b4;
    L_0x018c:
        r15 = "WWW-Authenticate";
        r16 = new java.lang.StringBuffer;
        r16.<init>();
        r17 = "Basic realm=\"";
        r16 = r16.append(r17);
        r0 = r19;
        r0 = r0.realm;
        r17 = r0;
        r16 = r16.append(r17);
        r17 = "\"";
        r16 = r16.append(r17);
        r16 = r16.toString();
        r0 = r21;
        r1 = r16;
        r0.addHeader(r15, r1);
    L_0x01b4:
        r15 = 401; // 0x191 float:5.62E-43 double:1.98E-321;
        r0 = r21;
        r0.setStatus(r15);
        r15 = 0;
        r0 = r21;
        r0.setContentLength(r15);
        r21.flushBuffer();
        r15 = 0;
        goto L_0x0064;
    L_0x01c7:
        if (r22 != 0) goto L_0x00b9;
    L_0x01c9:
        r15 = 0;
        r0 = r20;
        r13 = r0.getSession(r15);
        if (r13 == 0) goto L_0x01dc;
    L_0x01d2:
        r15 = "NtlmHttpAuth";
        r9 = r13.getAttribute(r15);
        r9 = (jcifs.smb.NtlmPasswordAuthentication) r9;
        if (r9 != 0) goto L_0x00b9;
    L_0x01dc:
        r15 = "WWW-Authenticate";
        r16 = "NTLM";
        r0 = r21;
        r1 = r16;
        r0.setHeader(r15, r1);
        if (r10 == 0) goto L_0x0211;
    L_0x01e9:
        r15 = "WWW-Authenticate";
        r16 = new java.lang.StringBuffer;
        r16.<init>();
        r17 = "Basic realm=\"";
        r16 = r16.append(r17);
        r0 = r19;
        r0 = r0.realm;
        r17 = r0;
        r16 = r16.append(r17);
        r17 = "\"";
        r16 = r16.append(r17);
        r16 = r16.toString();
        r0 = r21;
        r1 = r16;
        r0.addHeader(r15, r1);
    L_0x0211:
        r15 = 401; // 0x191 float:5.62E-43 double:1.98E-321;
        r0 = r21;
        r0.setStatus(r15);
        r15 = 0;
        r0 = r21;
        r0.setContentLength(r15);
        r21.flushBuffer();
        r15 = 0;
        goto L_0x0064;
        */
        throw new UnsupportedOperationException("Method not decompiled: jcifs.http.NtlmHttpFilter.negotiate(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, boolean):jcifs.smb.NtlmPasswordAuthentication");
    }

    public void setFilterConfig(FilterConfig f) {
        try {
            init(f);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public FilterConfig getFilterConfig() {
        return null;
    }
}
