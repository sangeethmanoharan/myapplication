package jcifs.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import jcifs.Config;
import jcifs.https.Handler;
import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Base64;
import lksystems.wifiintruder.BuildConfig;
import org.xbill.DNS.KEYRecord.Flags;

public class NtlmHttpURLConnection extends HttpURLConnection {
    private static final String DEFAULT_DOMAIN;
    private static final int LM_COMPATIBILITY = Config.getInt("jcifs.smb.lmCompatibility", 0);
    private static final int MAX_REDIRECTS = Integer.parseInt(System.getProperty("http.maxRedirects", "20"));
    private String authMethod;
    private String authProperty;
    private ByteArrayOutputStream cachedOutput;
    private HttpURLConnection connection;
    private boolean handshakeComplete;
    private Map headerFields;
    private Map requestProperties = new HashMap();

    private static class CacheStream extends OutputStream {
        private final OutputStream collector;
        private final OutputStream stream;

        public CacheStream(OutputStream stream, OutputStream collector) {
            this.stream = stream;
            this.collector = collector;
        }

        public void close() throws IOException {
            this.stream.close();
            this.collector.close();
        }

        public void flush() throws IOException {
            this.stream.flush();
            this.collector.flush();
        }

        public void write(byte[] b) throws IOException {
            this.stream.write(b);
            this.collector.write(b);
        }

        public void write(byte[] b, int off, int len) throws IOException {
            this.stream.write(b, off, len);
            this.collector.write(b, off, len);
        }

        public void write(int b) throws IOException {
            this.stream.write(b);
            this.collector.write(b);
        }
    }

    static {
        String domain = System.getProperty("http.auth.ntlm.domain");
        if (domain == null) {
            domain = Type3Message.getDefaultDomain();
        }
        DEFAULT_DOMAIN = domain;
    }

    public NtlmHttpURLConnection(HttpURLConnection connection) {
        super(connection.getURL());
        this.connection = connection;
    }

    public void connect() throws IOException {
        if (!this.connected) {
            this.connection.connect();
            this.connected = true;
        }
    }

    private void handshake() throws IOException {
        if (!this.handshakeComplete) {
            doHandshake();
            this.handshakeComplete = true;
        }
    }

    public URL getURL() {
        return this.connection.getURL();
    }

    public int getContentLength() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getContentLength();
    }

    public String getContentType() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getContentType();
    }

    public String getContentEncoding() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getContentEncoding();
    }

    public long getExpiration() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getExpiration();
    }

    public long getDate() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getDate();
    }

    public long getLastModified() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getLastModified();
    }

    public String getHeaderField(String header) {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getHeaderField(header);
    }

    private Map getHeaderFields0() {
        if (this.headerFields != null) {
            return this.headerFields;
        }
        Map map = new HashMap();
        String key = this.connection.getHeaderFieldKey(0);
        String value = this.connection.getHeaderField(0);
        int i = 1;
        while (true) {
            if (key == null && value == null) {
                break;
            }
            List values = (List) map.get(key);
            if (values == null) {
                values = new ArrayList();
                map.put(key, values);
            }
            values.add(value);
            key = this.connection.getHeaderFieldKey(i);
            value = this.connection.getHeaderField(i);
            i++;
        }
        for (Entry entry : map.entrySet()) {
            entry.setValue(Collections.unmodifiableList((List) entry.getValue()));
        }
        Map unmodifiableMap = Collections.unmodifiableMap(map);
        this.headerFields = unmodifiableMap;
        return unmodifiableMap;
    }

    public Map getHeaderFields() {
        if (this.headerFields != null) {
            return this.headerFields;
        }
        try {
            handshake();
        } catch (IOException e) {
        }
        return getHeaderFields0();
    }

    public int getHeaderFieldInt(String header, int def) {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getHeaderFieldInt(header, def);
    }

    public long getHeaderFieldDate(String header, long def) {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getHeaderFieldDate(header, def);
    }

    public String getHeaderFieldKey(int index) {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getHeaderFieldKey(index);
    }

    public String getHeaderField(int index) {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getHeaderField(index);
    }

    public Object getContent() throws IOException {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getContent();
    }

    public Object getContent(Class[] classes) throws IOException {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getContent(classes);
    }

    public Permission getPermission() throws IOException {
        return this.connection.getPermission();
    }

    public InputStream getInputStream() throws IOException {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException {
        try {
            connect();
        } catch (IOException e) {
        }
        OutputStream output = this.connection.getOutputStream();
        this.cachedOutput = new ByteArrayOutputStream();
        return new CacheStream(output, this.cachedOutput);
    }

    public String toString() {
        return this.connection.toString();
    }

    public void setDoInput(boolean doInput) {
        this.connection.setDoInput(doInput);
        this.doInput = doInput;
    }

    public boolean getDoInput() {
        return this.connection.getDoInput();
    }

    public void setDoOutput(boolean doOutput) {
        this.connection.setDoOutput(doOutput);
        this.doOutput = doOutput;
    }

    public boolean getDoOutput() {
        return this.connection.getDoOutput();
    }

    public void setAllowUserInteraction(boolean allowUserInteraction) {
        this.connection.setAllowUserInteraction(allowUserInteraction);
        this.allowUserInteraction = allowUserInteraction;
    }

    public boolean getAllowUserInteraction() {
        return this.connection.getAllowUserInteraction();
    }

    public void setUseCaches(boolean useCaches) {
        this.connection.setUseCaches(useCaches);
        this.useCaches = useCaches;
    }

    public boolean getUseCaches() {
        return this.connection.getUseCaches();
    }

    public void setIfModifiedSince(long ifModifiedSince) {
        this.connection.setIfModifiedSince(ifModifiedSince);
        this.ifModifiedSince = ifModifiedSince;
    }

    public long getIfModifiedSince() {
        return this.connection.getIfModifiedSince();
    }

    public boolean getDefaultUseCaches() {
        return this.connection.getDefaultUseCaches();
    }

    public void setDefaultUseCaches(boolean defaultUseCaches) {
        this.connection.setDefaultUseCaches(defaultUseCaches);
    }

    public void setRequestProperty(String key, String value) {
        if (key == null) {
            throw new NullPointerException();
        }
        List values = new ArrayList();
        values.add(value);
        boolean found = false;
        for (Entry entry : this.requestProperties.entrySet()) {
            if (key.equalsIgnoreCase((String) entry.getKey())) {
                entry.setValue(values);
                found = true;
                break;
            }
        }
        if (!found) {
            this.requestProperties.put(key, values);
        }
        this.connection.setRequestProperty(key, value);
    }

    public void addRequestProperty(String key, String value) {
        if (key == null) {
            throw new NullPointerException();
        }
        List list = null;
        for (Entry entry : this.requestProperties.entrySet()) {
            if (key.equalsIgnoreCase((String) entry.getKey())) {
                list = (List) entry.getValue();
                list.add(value);
                break;
            }
        }
        if (list == null) {
            list = new ArrayList();
            list.add(value);
            this.requestProperties.put(key, list);
        }
        StringBuffer buffer = new StringBuffer();
        Iterator propertyValues = list.iterator();
        while (propertyValues.hasNext()) {
            buffer.append(propertyValues.next());
            if (propertyValues.hasNext()) {
                buffer.append(", ");
            }
        }
        this.connection.setRequestProperty(key, buffer.toString());
    }

    public String getRequestProperty(String key) {
        return this.connection.getRequestProperty(key);
    }

    public Map getRequestProperties() {
        Map map = new HashMap();
        for (Entry entry : this.requestProperties.entrySet()) {
            map.put(entry.getKey(), Collections.unmodifiableList((List) entry.getValue()));
        }
        return Collections.unmodifiableMap(map);
    }

    public void setInstanceFollowRedirects(boolean instanceFollowRedirects) {
        this.connection.setInstanceFollowRedirects(instanceFollowRedirects);
    }

    public boolean getInstanceFollowRedirects() {
        return this.connection.getInstanceFollowRedirects();
    }

    public void setRequestMethod(String requestMethod) throws ProtocolException {
        this.connection.setRequestMethod(requestMethod);
        this.method = requestMethod;
    }

    public String getRequestMethod() {
        return this.connection.getRequestMethod();
    }

    public int getResponseCode() throws IOException {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getResponseCode();
    }

    public String getResponseMessage() throws IOException {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getResponseMessage();
    }

    public void disconnect() {
        this.connection.disconnect();
        this.handshakeComplete = false;
        this.connected = false;
    }

    public boolean usingProxy() {
        return this.connection.usingProxy();
    }

    public InputStream getErrorStream() {
        try {
            handshake();
        } catch (IOException e) {
        }
        return this.connection.getErrorStream();
    }

    private int parseResponseCode() throws IOException {
        try {
            String response = this.connection.getHeaderField(0);
            int index = response.indexOf(32);
            while (response.charAt(index) == ' ') {
                index++;
            }
            return Integer.parseInt(response.substring(index, index + 3));
        } catch (Exception ex) {
            throw new IOException(ex.getMessage());
        }
    }

    private void doHandshake() throws IOException {
        connect();
        int response = parseResponseCode();
        if (response == 401 || response == 407) {
            try {
                Type1Message type1 = (Type1Message) attemptNegotiation(response);
                if (type1 == null) {
                    this.cachedOutput = null;
                    return;
                }
                int attempt = 0;
                while (attempt < MAX_REDIRECTS) {
                    this.connection.setRequestProperty(this.authProperty, new StringBuffer().append(this.authMethod).append(' ').append(Base64.encode(type1.toByteArray())).toString());
                    this.connection.connect();
                    response = parseResponseCode();
                    if (response == 401 || response == 407) {
                        Type3Message type3 = (Type3Message) attemptNegotiation(response);
                        if (type3 == null) {
                            this.cachedOutput = null;
                            return;
                        }
                        this.connection.setRequestProperty(this.authProperty, new StringBuffer().append(this.authMethod).append(' ').append(Base64.encode(type3.toByteArray())).toString());
                        this.connection.connect();
                        if (this.cachedOutput != null && this.doOutput) {
                            OutputStream output = this.connection.getOutputStream();
                            this.cachedOutput.writeTo(output);
                            output.flush();
                        }
                        response = parseResponseCode();
                        if (response == 401 || response == 407) {
                            attempt++;
                            if (this.allowUserInteraction && attempt < MAX_REDIRECTS) {
                                reconnect();
                            }
                        } else {
                            this.cachedOutput = null;
                            return;
                        }
                    }
                    this.cachedOutput = null;
                    return;
                }
                throw new IOException("Unable to negotiate NTLM authentication.");
            } finally {
                this.cachedOutput = null;
            }
        }
    }

    private NtlmMessage attemptNegotiation(int response) throws IOException {
        this.authProperty = null;
        this.authMethod = null;
        InputStream errorStream = this.connection.getErrorStream();
        String authHeader;
        String authorization;
        List<String> methods;
        NtlmMessage message;
        String domain;
        String user;
        String password;
        String userInfo;
        int index;
        String password2;
        String protocol;
        int port;
        PasswordAuthentication auth;
        if (errorStream == null || errorStream.available() == 0) {
            if (response != 401) {
                authHeader = "WWW-Authenticate";
                this.authProperty = "Authorization";
            } else {
                authHeader = "Proxy-Authenticate";
                this.authProperty = "Proxy-Authorization";
            }
            authorization = null;
            methods = (List) getHeaderFields0().get(authHeader);
            if (methods == null) {
                return null;
            }
            for (String currentAuthMethod : methods) {
                if (!currentAuthMethod.startsWith("NTLM")) {
                    if (currentAuthMethod.startsWith("Negotiate")) {
                        continue;
                    } else if (currentAuthMethod.length() != 9) {
                        this.authMethod = "Negotiate";
                        break;
                    } else if (currentAuthMethod.indexOf(32) == 9) {
                        this.authMethod = "Negotiate";
                        authorization = currentAuthMethod.substring(10).trim();
                        break;
                    }
                } else if (currentAuthMethod.length() != 4) {
                    this.authMethod = "NTLM";
                    break;
                } else if (currentAuthMethod.indexOf(32) == 4) {
                    this.authMethod = "NTLM";
                    authorization = currentAuthMethod.substring(5).trim();
                    break;
                }
            }
            if (this.authMethod == null) {
                return null;
            }
            message = authorization == null ? new Type2Message(Base64.decode(authorization)) : null;
            reconnect();
            if (message != null) {
                message = new Type1Message();
                if (LM_COMPATIBILITY > 2) {
                    return message;
                }
                message.setFlag(4, true);
                return message;
            }
            domain = DEFAULT_DOMAIN;
            user = Type3Message.getDefaultUser();
            password = Type3Message.getDefaultPassword();
            userInfo = this.url.getUserInfo();
            if (userInfo == null) {
                userInfo = URLDecoder.decode(userInfo);
                index = userInfo.indexOf(58);
                if (index == -1) {
                    user = userInfo.substring(0, index);
                } else {
                    user = userInfo;
                }
                if (index != -1) {
                    password = userInfo.substring(index + 1);
                }
                index = user.indexOf(92);
                if (index == -1) {
                    index = user.indexOf(47);
                }
                if (index != -1) {
                    domain = user.substring(0, index);
                }
                if (index != -1) {
                    user = user.substring(index + 1);
                }
                password2 = password;
            } else {
                password2 = password;
            }
            if (user == null) {
                password = password2;
            } else if (!this.allowUserInteraction) {
                return null;
            } else {
                try {
                    URL url = getURL();
                    protocol = url.getProtocol();
                    port = url.getPort();
                    if (port == -1) {
                        port = "https".equalsIgnoreCase(protocol) ? Handler.DEFAULT_HTTPS_PORT : 80;
                    }
                    auth = Authenticator.requestPasswordAuthentication(null, port, protocol, BuildConfig.VERSION_NAME, this.authMethod);
                    if (auth == null) {
                        return null;
                    }
                    user = auth.getUserName();
                    password = new String(auth.getPassword());
                } catch (Exception e) {
                    password = password2;
                }
            }
            return new Type3Message((Type2Message) message, password, domain, user, Type3Message.getDefaultWorkstation());
        }
        do {
        } while (errorStream.read(new byte[Flags.FLAG5], 0, Flags.FLAG5) != -1);
        if (response != 401) {
            authHeader = "Proxy-Authenticate";
            this.authProperty = "Proxy-Authorization";
        } else {
            authHeader = "WWW-Authenticate";
            this.authProperty = "Authorization";
        }
        authorization = null;
        methods = (List) getHeaderFields0().get(authHeader);
        if (methods == null) {
            return null;
        }
        for (String currentAuthMethod2 : methods) {
            if (!currentAuthMethod2.startsWith("NTLM")) {
                if (currentAuthMethod2.length() != 4) {
                    if (currentAuthMethod2.indexOf(32) == 4) {
                        this.authMethod = "NTLM";
                        authorization = currentAuthMethod2.substring(5).trim();
                        break;
                    }
                } else {
                    this.authMethod = "NTLM";
                    break;
                }
            } else if (currentAuthMethod2.startsWith("Negotiate")) {
                if (currentAuthMethod2.length() != 9) {
                    if (currentAuthMethod2.indexOf(32) == 9) {
                        this.authMethod = "Negotiate";
                        authorization = currentAuthMethod2.substring(10).trim();
                        break;
                    }
                } else {
                    this.authMethod = "Negotiate";
                    break;
                }
            } else {
                continue;
            }
        }
        if (this.authMethod == null) {
            return null;
        }
        if (authorization == null) {
        }
        reconnect();
        if (message != null) {
            domain = DEFAULT_DOMAIN;
            user = Type3Message.getDefaultUser();
            password = Type3Message.getDefaultPassword();
            userInfo = this.url.getUserInfo();
            if (userInfo == null) {
                password2 = password;
            } else {
                userInfo = URLDecoder.decode(userInfo);
                index = userInfo.indexOf(58);
                if (index == -1) {
                    user = userInfo;
                } else {
                    user = userInfo.substring(0, index);
                }
                if (index != -1) {
                    password = userInfo.substring(index + 1);
                }
                index = user.indexOf(92);
                if (index == -1) {
                    index = user.indexOf(47);
                }
                if (index != -1) {
                    domain = user.substring(0, index);
                }
                if (index != -1) {
                    user = user.substring(index + 1);
                }
                password2 = password;
            }
            if (user == null) {
                password = password2;
            } else if (!this.allowUserInteraction) {
                return null;
            } else {
                URL url2 = getURL();
                protocol = url2.getProtocol();
                port = url2.getPort();
                if (port == -1) {
                    if ("https".equalsIgnoreCase(protocol)) {
                    }
                }
                auth = Authenticator.requestPasswordAuthentication(null, port, protocol, BuildConfig.VERSION_NAME, this.authMethod);
                if (auth == null) {
                    return null;
                }
                user = auth.getUserName();
                password = new String(auth.getPassword());
            }
            return new Type3Message((Type2Message) message, password, domain, user, Type3Message.getDefaultWorkstation());
        }
        message = new Type1Message();
        if (LM_COMPATIBILITY > 2) {
            return message;
        }
        message.setFlag(4, true);
        return message;
    }

    private void reconnect() throws IOException {
        this.connection = (HttpURLConnection) this.connection.getURL().openConnection();
        this.connection.setRequestMethod(this.method);
        this.headerFields = null;
        for (Entry property : this.requestProperties.entrySet()) {
            String key = (String) property.getKey();
            StringBuffer value = new StringBuffer();
            Iterator values = ((List) property.getValue()).iterator();
            while (values.hasNext()) {
                value.append(values.next());
                if (values.hasNext()) {
                    value.append(", ");
                }
            }
            this.connection.setRequestProperty(key, value.toString());
        }
        this.connection.setAllowUserInteraction(this.allowUserInteraction);
        this.connection.setDoInput(this.doInput);
        this.connection.setDoOutput(this.doOutput);
        this.connection.setIfModifiedSince(this.ifModifiedSince);
        this.connection.setUseCaches(this.useCaches);
    }
}
