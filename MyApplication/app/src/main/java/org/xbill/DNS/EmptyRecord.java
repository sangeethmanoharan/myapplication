package org.xbill.DNS;

import java.io.IOException;
import lksystems.wifiintruder.BuildConfig;

class EmptyRecord extends Record {
    private static final long serialVersionUID = 3601852050646429582L;

    EmptyRecord() {
    }

    Record getObject() {
        return new EmptyRecord();
    }

    void rrFromWire(DNSInput in) throws IOException {
    }

    void rdataFromString(Tokenizer st, Name origin) throws IOException {
    }

    String rrToString() {
        return BuildConfig.VERSION_NAME;
    }

    void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    }
}
