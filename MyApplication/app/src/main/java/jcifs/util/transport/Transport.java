package jcifs.util.transport;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import jcifs.util.LogStream;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.Zone;

public abstract class Transport implements Runnable {
    static int id = 0;
    static LogStream log = LogStream.getInstance();
    String name;
    protected HashMap response_map;
    public Object setupDiscoLock;
    int state = 0;
    TransportException te;
    Thread thread;

    protected abstract void doConnect() throws Exception;

    protected abstract void doDisconnect(boolean z) throws IOException;

    protected abstract void doRecv(Response response) throws IOException;

    protected abstract void doSend(Request request) throws IOException;

    protected abstract void doSkip() throws IOException;

    protected abstract void makeKey(Request request) throws IOException;

    protected abstract Request peekKey() throws IOException;

    public Transport() {
        StringBuffer append = new StringBuffer().append("Transport");
        int i = id;
        id = i + 1;
        this.name = append.append(i).toString();
        this.response_map = new HashMap(4);
        this.setupDiscoLock = new Object();
    }

    public static int readn(InputStream in, byte[] b, int off, int len) throws IOException {
        int i = 0;
        while (i < len) {
            int n = in.read(b, off + i, len - i);
            if (n <= 0) {
                break;
            }
            i += n;
        }
        return i;
    }

    public void sendrecv(Request request, Response response, long timeout) throws IOException {
        synchronized (this.response_map) {
            makeKey(request);
            response.isReceived = false;
            try {
                this.response_map.put(request, response);
                doSend(request);
                response.expiration = System.currentTimeMillis() + timeout;
                while (!response.isReceived) {
                    this.response_map.wait(timeout);
                    timeout = response.expiration - System.currentTimeMillis();
                    if (timeout <= 0) {
                        throw new TransportException(new StringBuffer().append(this.name).append(" timedout waiting for response to ").append(request).toString());
                    }
                }
                this.response_map.remove(request);
            } catch (IOException ioe) {
                LogStream logStream = log;
                if (LogStream.level > 2) {
                    ioe.printStackTrace(log);
                }
                try {
                    disconnect(true);
                } catch (IOException ioe2) {
                    ioe2.printStackTrace(log);
                }
                throw ioe;
            } catch (Throwable ie) {
                throw new TransportException(ie);
            } catch (Throwable th) {
                this.response_map.remove(request);
            }
        }
    }

    private void loop() {
        boolean timeout;
        boolean hard;
        while (this.thread == Thread.currentThread()) {
            LogStream logStream;
            try {
                Request key = peekKey();
                if (key == null) {
                    throw new IOException("end of stream");
                }
                synchronized (this.response_map) {
                    Response response = (Response) this.response_map.get(key);
                    if (response == null) {
                        logStream = log;
                        if (LogStream.level >= 4) {
                            log.println("Invalid key, skipping message");
                        }
                        doSkip();
                    } else {
                        doRecv(response);
                        response.isReceived = true;
                        this.response_map.notifyAll();
                    }
                }
            } catch (Exception ex) {
                String msg = ex.getMessage();
                if (msg == null || !msg.equals("Read timed out")) {
                    timeout = false;
                } else {
                    timeout = true;
                }
                if (timeout) {
                    hard = false;
                } else {
                    hard = true;
                }
                if (!timeout) {
                    logStream = log;
                    if (LogStream.level >= 3) {
                        ex.printStackTrace(log);
                    }
                }
                try {
                    disconnect(hard);
                } catch (IOException ioe) {
                    ioe.printStackTrace(log);
                }
            }
        }
    }

    public synchronized void connect(long timeout) throws TransportException {
        try {
            LogStream logStream;
            switch (this.state) {
                case Tokenizer.EOF /*0*/:
                    this.state = 1;
                    this.te = null;
                    this.thread = new Thread(this, this.name);
                    this.thread.setDaemon(true);
                    synchronized (this.thread) {
                        this.thread.start();
                        this.thread.wait(timeout);
                        switch (this.state) {
                            case Zone.PRIMARY /*1*/:
                                this.state = 0;
                                this.thread = null;
                                throw new TransportException("Connection timeout");
                            case Zone.SECONDARY /*2*/:
                                if (this.te == null) {
                                    this.state = 3;
                                    if (!(this.state == 0 || this.state == 3 || this.state == 4)) {
                                        logStream = log;
                                        if (LogStream.level >= 1) {
                                            log.println(new StringBuffer().append("Invalid state: ").append(this.state).toString());
                                        }
                                        this.state = 0;
                                        this.thread = null;
                                        break;
                                    }
                                }
                                this.state = 4;
                                this.thread = null;
                                throw this.te;
                            default:
                                if (!(this.state == 0 || this.state == 3 || this.state == 4)) {
                                    logStream = log;
                                    if (LogStream.level >= 1) {
                                        log.println(new StringBuffer().append("Invalid state: ").append(this.state).toString());
                                    }
                                    this.state = 0;
                                    this.thread = null;
                                    break;
                                }
                        }
                    }
                case Protocol.GGP /*3*/:
                    if (!(this.state == 0 || this.state == 3 || this.state == 4)) {
                        logStream = log;
                        if (LogStream.level >= 1) {
                            log.println(new StringBuffer().append("Invalid state: ").append(this.state).toString());
                        }
                        this.state = 0;
                        this.thread = null;
                        break;
                    }
                case Type.MF /*4*/:
                    this.state = 0;
                    throw new TransportException("Connection in error", this.te);
                default:
                    TransportException te = new TransportException(new StringBuffer().append("Invalid state: ").append(this.state).toString());
                    this.state = 0;
                    throw te;
            }
        } catch (Throwable ie) {
            this.state = 0;
            this.thread = null;
            throw new TransportException(ie);
        } catch (Throwable th) {
            if (!(this.state == 0 || this.state == 3 || this.state == 4)) {
                LogStream logStream2 = log;
                if (LogStream.level >= 1) {
                    log.println(new StringBuffer().append("Invalid state: ").append(this.state).toString());
                }
                this.state = 0;
                this.thread = null;
            }
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void disconnect(boolean r5) throws java.io.IOException {
        /*
        r4 = this;
        r1 = r4.setupDiscoLock;
        monitor-enter(r1);
        monitor-enter(r4);	 Catch:{ all -> 0x0036 }
        r0 = r4.state;	 Catch:{ all -> 0x004e }
        switch(r0) {
            case 0: goto L_0x0033;
            case 1: goto L_0x0009;
            case 2: goto L_0x0039;
            case 3: goto L_0x003a;
            case 4: goto L_0x0047;
            default: goto L_0x0009;
        };	 Catch:{ all -> 0x004e }
    L_0x0009:
        r0 = log;	 Catch:{ all -> 0x004e }
        r0 = jcifs.util.LogStream.level;	 Catch:{ all -> 0x004e }
        r2 = 1;
        if (r0 < r2) goto L_0x002a;
    L_0x0010:
        r0 = log;	 Catch:{ all -> 0x004e }
        r2 = new java.lang.StringBuffer;	 Catch:{ all -> 0x004e }
        r2.<init>();	 Catch:{ all -> 0x004e }
        r3 = "Invalid state: ";
        r2 = r2.append(r3);	 Catch:{ all -> 0x004e }
        r3 = r4.state;	 Catch:{ all -> 0x004e }
        r2 = r2.append(r3);	 Catch:{ all -> 0x004e }
        r2 = r2.toString();	 Catch:{ all -> 0x004e }
        r0.println(r2);	 Catch:{ all -> 0x004e }
    L_0x002a:
        r0 = 0;
        r4.thread = r0;	 Catch:{ all -> 0x004e }
        r0 = 0;
        r4.state = r0;	 Catch:{ all -> 0x004e }
    L_0x0030:
        monitor-exit(r4);	 Catch:{ all -> 0x004e }
        monitor-exit(r1);	 Catch:{ all -> 0x0036 }
    L_0x0032:
        return;
    L_0x0033:
        monitor-exit(r4);	 Catch:{ all -> 0x004e }
        monitor-exit(r1);	 Catch:{ all -> 0x0036 }
        goto L_0x0032;
    L_0x0036:
        r0 = move-exception;
        monitor-exit(r1);	 Catch:{ all -> 0x0036 }
        throw r0;
    L_0x0039:
        r5 = 1;
    L_0x003a:
        r0 = r4.response_map;	 Catch:{ all -> 0x004e }
        r0 = r0.size();	 Catch:{ all -> 0x004e }
        if (r0 == 0) goto L_0x0044;
    L_0x0042:
        if (r5 == 0) goto L_0x0030;
    L_0x0044:
        r4.doDisconnect(r5);	 Catch:{ all -> 0x004e }
    L_0x0047:
        r0 = 0;
        r4.thread = r0;	 Catch:{ all -> 0x004e }
        r0 = 0;
        r4.state = r0;	 Catch:{ all -> 0x004e }
        goto L_0x0030;
    L_0x004e:
        r0 = move-exception;
        monitor-exit(r4);	 Catch:{ all -> 0x004e }
        throw r0;	 Catch:{ all -> 0x0036 }
        */
        throw new UnsupportedOperationException("Method not decompiled: jcifs.util.transport.Transport.disconnect(boolean):void");
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void run() {
        /*
        r5 = this;
        r2 = java.lang.Thread.currentThread();
        r1 = 0;
        r5.doConnect();	 Catch:{ Exception -> 0x0014, all -> 0x004a }
        monitor-enter(r2);
        r3 = r5.thread;	 Catch:{ all -> 0x006b }
        if (r2 == r3) goto L_0x0036;
    L_0x000d:
        if (r1 == 0) goto L_0x0012;
    L_0x000f:
        r1.printStackTrace();	 Catch:{ all -> 0x006b }
    L_0x0012:
        monitor-exit(r2);	 Catch:{ all -> 0x006b }
    L_0x0013:
        return;
    L_0x0014:
        r0 = move-exception;
        r1 = r0;
        monitor-enter(r2);
        r3 = r5.thread;	 Catch:{ all -> 0x0022 }
        if (r2 == r3) goto L_0x005a;
    L_0x001b:
        if (r1 == 0) goto L_0x0020;
    L_0x001d:
        r1.printStackTrace();	 Catch:{ all -> 0x0022 }
    L_0x0020:
        monitor-exit(r2);	 Catch:{ all -> 0x0022 }
        goto L_0x0013;
    L_0x0022:
        r3 = move-exception;
        monitor-exit(r2);	 Catch:{ all -> 0x0022 }
        throw r3;
    L_0x0025:
        if (r1 == 0) goto L_0x002e;
    L_0x0027:
        r4 = new jcifs.util.transport.TransportException;	 Catch:{ all -> 0x0057 }
        r4.<init>(r1);	 Catch:{ all -> 0x0057 }
        r5.te = r4;	 Catch:{ all -> 0x0057 }
    L_0x002e:
        r4 = 2;
        r5.state = r4;	 Catch:{ all -> 0x0057 }
        r2.notify();	 Catch:{ all -> 0x0057 }
        monitor-exit(r2);	 Catch:{ all -> 0x0057 }
        throw r3;
    L_0x0036:
        if (r1 == 0) goto L_0x003f;
    L_0x0038:
        r3 = new jcifs.util.transport.TransportException;	 Catch:{ all -> 0x006b }
        r3.<init>(r1);	 Catch:{ all -> 0x006b }
        r5.te = r3;	 Catch:{ all -> 0x006b }
    L_0x003f:
        r3 = 2;
        r5.state = r3;	 Catch:{ all -> 0x006b }
        r2.notify();	 Catch:{ all -> 0x006b }
        monitor-exit(r2);	 Catch:{ all -> 0x006b }
        r5.loop();
        goto L_0x0013;
    L_0x004a:
        r3 = move-exception;
        monitor-enter(r2);
        r4 = r5.thread;	 Catch:{ all -> 0x0057 }
        if (r2 == r4) goto L_0x0025;
    L_0x0050:
        if (r1 == 0) goto L_0x0055;
    L_0x0052:
        r1.printStackTrace();	 Catch:{ all -> 0x0057 }
    L_0x0055:
        monitor-exit(r2);	 Catch:{ all -> 0x0057 }
        goto L_0x0013;
    L_0x0057:
        r3 = move-exception;
        monitor-exit(r2);	 Catch:{ all -> 0x0057 }
        throw r3;
    L_0x005a:
        if (r1 == 0) goto L_0x0063;
    L_0x005c:
        r3 = new jcifs.util.transport.TransportException;	 Catch:{ all -> 0x0022 }
        r3.<init>(r1);	 Catch:{ all -> 0x0022 }
        r5.te = r3;	 Catch:{ all -> 0x0022 }
    L_0x0063:
        r3 = 2;
        r5.state = r3;	 Catch:{ all -> 0x0022 }
        r2.notify();	 Catch:{ all -> 0x0022 }
        monitor-exit(r2);	 Catch:{ all -> 0x0022 }
        goto L_0x0013;
    L_0x006b:
        r3 = move-exception;
        monitor-exit(r2);	 Catch:{ all -> 0x006b }
        throw r3;
        */
        throw new UnsupportedOperationException("Method not decompiled: jcifs.util.transport.Transport.run():void");
    }

    public String toString() {
        return this.name;
    }
}
