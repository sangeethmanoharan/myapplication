package jcifs.dcerpc.msrpc;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrObject;
import jcifs.dcerpc.ndr.NdrSmall;
import jcifs.dcerpc.rpc.policy_handle;
import jcifs.dcerpc.rpc.sid_t;
import jcifs.dcerpc.rpc.unicode_string;
import jcifs.dcerpc.rpc.uuid_t;
import org.xbill.DNS.Message;

public class lsarpc {
    public static final int POLICY_INFO_ACCOUNT_DOMAIN = 5;
    public static final int POLICY_INFO_AUDIT_EVENTS = 2;
    public static final int POLICY_INFO_DNS_DOMAIN = 12;
    public static final int POLICY_INFO_MODIFICATION = 9;
    public static final int POLICY_INFO_PRIMARY_DOMAIN = 3;
    public static final int POLICY_INFO_SERVER_ROLE = 6;
    public static final int SID_NAME_ALIAS = 4;
    public static final int SID_NAME_DELETED = 6;
    public static final int SID_NAME_DOMAIN = 3;
    public static final int SID_NAME_DOM_GRP = 2;
    public static final int SID_NAME_INVALID = 7;
    public static final int SID_NAME_UNKNOWN = 8;
    public static final int SID_NAME_USER = 1;
    public static final int SID_NAME_USE_NONE = 0;
    public static final int SID_NAME_WKN_GRP = 5;

    public static class LsarSidArray extends NdrObject {
        public int num_sids;
        public LsarSidPtr[] sids;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_long(this.num_sids);
            _dst.enc_ndr_referent(this.sids, lsarpc.SID_NAME_USER);
            if (this.sids != null) {
                _dst = _dst.deferred;
                int _sidss = this.num_sids;
                _dst.enc_ndr_long(_sidss);
                int _sidsi = _dst.index;
                _dst.advance(_sidss * lsarpc.SID_NAME_ALIAS);
                _dst = _dst.derive(_sidsi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _sidss; _i += lsarpc.SID_NAME_USER) {
                    this.sids[_i].encode(_dst);
                }
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.num_sids = _src.dec_ndr_long();
            if (_src.dec_ndr_long() != 0) {
                _src = _src.deferred;
                int _sidss = _src.dec_ndr_long();
                int _sidsi = _src.index;
                _src.advance(_sidss * lsarpc.SID_NAME_ALIAS);
                if (this.sids == null) {
                    if (_sidss < 0 || _sidss > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.sids = new LsarSidPtr[_sidss];
                }
                _src = _src.derive(_sidsi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _sidss; _i += lsarpc.SID_NAME_USER) {
                    if (this.sids[_i] == null) {
                        this.sids[_i] = new LsarSidPtr();
                    }
                    this.sids[_i].decode(_src);
                }
            }
        }
    }

    public static class LsarLookupSids extends DcerpcMessage {
        public int count;
        public LsarRefDomainList domains;
        public policy_handle handle;
        public short level;
        public LsarTransNameArray names;
        public int retval;
        public LsarSidArray sids;

        public int getOpnum() {
            return 15;
        }

        public LsarLookupSids(policy_handle handle, LsarSidArray sids, LsarRefDomainList domains, LsarTransNameArray names, short level, int count) {
            this.handle = handle;
            this.sids = sids;
            this.domains = domains;
            this.names = names;
            this.level = level;
            this.count = count;
        }

        public void encode_in(NdrBuffer _dst) throws NdrException {
            this.handle.encode(_dst);
            this.sids.encode(_dst);
            this.names.encode(_dst);
            _dst.enc_ndr_short(this.level);
            _dst.enc_ndr_long(this.count);
        }

        public void decode_out(NdrBuffer _src) throws NdrException {
            if (_src.dec_ndr_long() != 0) {
                if (this.domains == null) {
                    this.domains = new LsarRefDomainList();
                }
                this.domains.decode(_src);
            }
            this.names.decode(_src);
            this.count = _src.dec_ndr_long();
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class LsarOpenPolicy2 extends DcerpcMessage {
        public int desired_access;
        public LsarObjectAttributes object_attributes;
        public policy_handle policy_handle;
        public int retval;
        public String system_name;

        public int getOpnum() {
            return 44;
        }

        public LsarOpenPolicy2(String system_name, LsarObjectAttributes object_attributes, int desired_access, policy_handle policy_handle) {
            this.system_name = system_name;
            this.object_attributes = object_attributes;
            this.desired_access = desired_access;
            this.policy_handle = policy_handle;
        }

        public void encode_in(NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(this.system_name, lsarpc.SID_NAME_USER);
            if (this.system_name != null) {
                _dst.enc_ndr_string(this.system_name);
            }
            this.object_attributes.encode(_dst);
            _dst.enc_ndr_long(this.desired_access);
        }

        public void decode_out(NdrBuffer _src) throws NdrException {
            this.policy_handle.decode(_src);
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class LsarQueryInformationPolicy extends DcerpcMessage {
        public policy_handle handle;
        public NdrObject info;
        public short level;
        public int retval;

        public int getOpnum() {
            return lsarpc.SID_NAME_INVALID;
        }

        public LsarQueryInformationPolicy(policy_handle handle, short level, NdrObject info) {
            this.handle = handle;
            this.level = level;
            this.info = info;
        }

        public void encode_in(NdrBuffer _dst) throws NdrException {
            this.handle.encode(_dst);
            _dst.enc_ndr_short(this.level);
        }

        public void decode_out(NdrBuffer _src) throws NdrException {
            if (_src.dec_ndr_long() != 0) {
                _src.dec_ndr_short();
                this.info.decode(_src);
            }
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class LsarClose extends DcerpcMessage {
        public policy_handle handle;
        public int retval;

        public int getOpnum() {
            return lsarpc.SID_NAME_USE_NONE;
        }

        public LsarClose(policy_handle handle) {
            this.handle = handle;
        }

        public void encode_in(NdrBuffer _dst) throws NdrException {
            this.handle.encode(_dst);
        }

        public void decode_out(NdrBuffer _src) throws NdrException {
            this.handle.decode(_src);
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class LsarDnsDomainInfo extends NdrObject {
        public unicode_string dns_domain;
        public unicode_string dns_forest;
        public uuid_t domain_guid;
        public unicode_string name;
        public sid_t sid;

        public void encode(NdrBuffer _dst) throws NdrException {
            int _i;
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_short(this.name.length);
            _dst.enc_ndr_short(this.name.maximum_length);
            _dst.enc_ndr_referent(this.name.buffer, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_short(this.dns_domain.length);
            _dst.enc_ndr_short(this.dns_domain.maximum_length);
            _dst.enc_ndr_referent(this.dns_domain.buffer, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_short(this.dns_forest.length);
            _dst.enc_ndr_short(this.dns_forest.maximum_length);
            _dst.enc_ndr_referent(this.dns_forest.buffer, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_long(this.domain_guid.time_low);
            _dst.enc_ndr_short(this.domain_guid.time_mid);
            _dst.enc_ndr_short(this.domain_guid.time_hi_and_version);
            _dst.enc_ndr_small(this.domain_guid.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(this.domain_guid.clock_seq_low);
            int _domain_guid_nodei = _dst.index;
            _dst.advance(lsarpc.SID_NAME_DELETED);
            _dst.enc_ndr_referent(this.sid, lsarpc.SID_NAME_USER);
            if (this.name.buffer != null) {
                _dst = _dst.deferred;
                int _name_bufferl = this.name.length / lsarpc.SID_NAME_DOM_GRP;
                _dst.enc_ndr_long(this.name.maximum_length / lsarpc.SID_NAME_DOM_GRP);
                _dst.enc_ndr_long(lsarpc.SID_NAME_USE_NONE);
                _dst.enc_ndr_long(_name_bufferl);
                int _name_bufferi = _dst.index;
                _dst.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                _dst = _dst.derive(_name_bufferi);
                for (_i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    _dst.enc_ndr_short(this.name.buffer[_i]);
                }
            }
            if (this.dns_domain.buffer != null) {
                _dst = _dst.deferred;
                int _dns_domain_bufferl = this.dns_domain.length / lsarpc.SID_NAME_DOM_GRP;
                _dst.enc_ndr_long(this.dns_domain.maximum_length / lsarpc.SID_NAME_DOM_GRP);
                _dst.enc_ndr_long(lsarpc.SID_NAME_USE_NONE);
                _dst.enc_ndr_long(_dns_domain_bufferl);
                int _dns_domain_bufferi = _dst.index;
                _dst.advance(_dns_domain_bufferl * lsarpc.SID_NAME_DOM_GRP);
                _dst = _dst.derive(_dns_domain_bufferi);
                for (_i = lsarpc.SID_NAME_USE_NONE; _i < _dns_domain_bufferl; _i += lsarpc.SID_NAME_USER) {
                    _dst.enc_ndr_short(this.dns_domain.buffer[_i]);
                }
            }
            if (this.dns_forest.buffer != null) {
                _dst = _dst.deferred;
                int _dns_forest_bufferl = this.dns_forest.length / lsarpc.SID_NAME_DOM_GRP;
                _dst.enc_ndr_long(this.dns_forest.maximum_length / lsarpc.SID_NAME_DOM_GRP);
                _dst.enc_ndr_long(lsarpc.SID_NAME_USE_NONE);
                _dst.enc_ndr_long(_dns_forest_bufferl);
                int _dns_forest_bufferi = _dst.index;
                _dst.advance(_dns_forest_bufferl * lsarpc.SID_NAME_DOM_GRP);
                _dst = _dst.derive(_dns_forest_bufferi);
                for (_i = lsarpc.SID_NAME_USE_NONE; _i < _dns_forest_bufferl; _i += lsarpc.SID_NAME_USER) {
                    _dst.enc_ndr_short(this.dns_forest.buffer[_i]);
                }
            }
            _dst = _dst.derive(_domain_guid_nodei);
            for (_i = lsarpc.SID_NAME_USE_NONE; _i < lsarpc.SID_NAME_DELETED; _i += lsarpc.SID_NAME_USER) {
                _dst.enc_ndr_small(this.domain_guid.node[_i]);
            }
            if (this.sid != null) {
                this.sid.encode(_dst.deferred);
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            int _i;
            _src.align(lsarpc.SID_NAME_ALIAS);
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.name == null) {
                this.name = new unicode_string();
            }
            this.name.length = (short) _src.dec_ndr_short();
            this.name.maximum_length = (short) _src.dec_ndr_short();
            int _name_bufferp = _src.dec_ndr_long();
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.dns_domain == null) {
                this.dns_domain = new unicode_string();
            }
            this.dns_domain.length = (short) _src.dec_ndr_short();
            this.dns_domain.maximum_length = (short) _src.dec_ndr_short();
            int _dns_domain_bufferp = _src.dec_ndr_long();
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.dns_forest == null) {
                this.dns_forest = new unicode_string();
            }
            this.dns_forest.length = (short) _src.dec_ndr_short();
            this.dns_forest.maximum_length = (short) _src.dec_ndr_short();
            int _dns_forest_bufferp = _src.dec_ndr_long();
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.domain_guid == null) {
                this.domain_guid = new uuid_t();
            }
            this.domain_guid.time_low = _src.dec_ndr_long();
            this.domain_guid.time_mid = (short) _src.dec_ndr_short();
            this.domain_guid.time_hi_and_version = (short) _src.dec_ndr_short();
            this.domain_guid.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            this.domain_guid.clock_seq_low = (byte) _src.dec_ndr_small();
            int _domain_guid_nodei = _src.index;
            _src.advance(lsarpc.SID_NAME_DELETED);
            int _sidp = _src.dec_ndr_long();
            if (_name_bufferp != 0) {
                _src = _src.deferred;
                int _name_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _name_bufferl = _src.dec_ndr_long();
                int _name_bufferi = _src.index;
                _src.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                if (this.name.buffer == null) {
                    if (_name_buffers < 0 || _name_buffers > 65535) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.name.buffer = new short[_name_buffers];
                }
                _src = _src.derive(_name_bufferi);
                for (_i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    this.name.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (_dns_domain_bufferp != 0) {
                _src = _src.deferred;
                int _dns_domain_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _dns_domain_bufferl = _src.dec_ndr_long();
                int _dns_domain_bufferi = _src.index;
                _src.advance(_dns_domain_bufferl * lsarpc.SID_NAME_DOM_GRP);
                if (this.dns_domain.buffer == null) {
                    if (_dns_domain_buffers < 0 || _dns_domain_buffers > 65535) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.dns_domain.buffer = new short[_dns_domain_buffers];
                }
                _src = _src.derive(_dns_domain_bufferi);
                for (_i = lsarpc.SID_NAME_USE_NONE; _i < _dns_domain_bufferl; _i += lsarpc.SID_NAME_USER) {
                    this.dns_domain.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (_dns_forest_bufferp != 0) {
                _src = _src.deferred;
                int _dns_forest_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _dns_forest_bufferl = _src.dec_ndr_long();
                int _dns_forest_bufferi = _src.index;
                _src.advance(_dns_forest_bufferl * lsarpc.SID_NAME_DOM_GRP);
                if (this.dns_forest.buffer == null) {
                    if (_dns_forest_buffers < 0 || _dns_forest_buffers > 65535) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.dns_forest.buffer = new short[_dns_forest_buffers];
                }
                _src = _src.derive(_dns_forest_bufferi);
                for (_i = lsarpc.SID_NAME_USE_NONE; _i < _dns_forest_bufferl; _i += lsarpc.SID_NAME_USER) {
                    this.dns_forest.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (this.domain_guid.node == null) {
                if (lsarpc.SID_NAME_DELETED < null || lsarpc.SID_NAME_DELETED > 65535) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                this.domain_guid.node = new byte[lsarpc.SID_NAME_DELETED];
            }
            _src = _src.derive(_domain_guid_nodei);
            for (_i = lsarpc.SID_NAME_USE_NONE; _i < lsarpc.SID_NAME_DELETED; _i += lsarpc.SID_NAME_USER) {
                this.domain_guid.node[_i] = (byte) _src.dec_ndr_small();
            }
            if (_sidp != 0) {
                if (this.sid == null) {
                    this.sid = new sid_t();
                }
                this.sid.decode(_src.deferred);
            }
        }
    }

    public static class LsarDomainInfo extends NdrObject {
        public unicode_string name;
        public sid_t sid;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_short(this.name.length);
            _dst.enc_ndr_short(this.name.maximum_length);
            _dst.enc_ndr_referent(this.name.buffer, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_referent(this.sid, lsarpc.SID_NAME_USER);
            if (this.name.buffer != null) {
                _dst = _dst.deferred;
                int _name_bufferl = this.name.length / lsarpc.SID_NAME_DOM_GRP;
                _dst.enc_ndr_long(this.name.maximum_length / lsarpc.SID_NAME_DOM_GRP);
                _dst.enc_ndr_long(lsarpc.SID_NAME_USE_NONE);
                _dst.enc_ndr_long(_name_bufferl);
                int _name_bufferi = _dst.index;
                _dst.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                _dst = _dst.derive(_name_bufferi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    _dst.enc_ndr_short(this.name.buffer[_i]);
                }
            }
            if (this.sid != null) {
                this.sid.encode(_dst.deferred);
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.name == null) {
                this.name = new unicode_string();
            }
            this.name.length = (short) _src.dec_ndr_short();
            this.name.maximum_length = (short) _src.dec_ndr_short();
            int _name_bufferp = _src.dec_ndr_long();
            int _sidp = _src.dec_ndr_long();
            if (_name_bufferp != 0) {
                _src = _src.deferred;
                int _name_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _name_bufferl = _src.dec_ndr_long();
                int _name_bufferi = _src.index;
                _src.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                if (this.name.buffer == null) {
                    if (_name_buffers < 0 || _name_buffers > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.name.buffer = new short[_name_buffers];
                }
                _src = _src.derive(_name_bufferi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    this.name.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (_sidp != 0) {
                if (this.sid == null) {
                    this.sid = new sid_t();
                }
                this.sid.decode(_src.deferred);
            }
        }
    }

    public static class LsarObjectAttributes extends NdrObject {
        public int attributes;
        public int length = 24;
        public unicode_string object_name;
        public NdrSmall root_directory;
        public int security_descriptor;
        public LsarQosInfo security_quality_of_service;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_long(this.length);
            _dst.enc_ndr_referent(this.root_directory, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_referent(this.object_name, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_long(this.attributes);
            _dst.enc_ndr_long(this.security_descriptor);
            _dst.enc_ndr_referent(this.security_quality_of_service, lsarpc.SID_NAME_USER);
            if (this.root_directory != null) {
                _dst = _dst.deferred;
                this.root_directory.encode(_dst);
            }
            if (this.object_name != null) {
                _dst = _dst.deferred;
                this.object_name.encode(_dst);
            }
            if (this.security_quality_of_service != null) {
                this.security_quality_of_service.encode(_dst.deferred);
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.length = _src.dec_ndr_long();
            int _root_directoryp = _src.dec_ndr_long();
            int _object_namep = _src.dec_ndr_long();
            this.attributes = _src.dec_ndr_long();
            this.security_descriptor = _src.dec_ndr_long();
            int _security_quality_of_servicep = _src.dec_ndr_long();
            if (_root_directoryp != 0) {
                _src = _src.deferred;
                this.root_directory.decode(_src);
            }
            if (_object_namep != 0) {
                if (this.object_name == null) {
                    this.object_name = new unicode_string();
                }
                _src = _src.deferred;
                this.object_name.decode(_src);
            }
            if (_security_quality_of_servicep != 0) {
                if (this.security_quality_of_service == null) {
                    this.security_quality_of_service = new LsarQosInfo();
                }
                this.security_quality_of_service.decode(_src.deferred);
            }
        }
    }

    public static class LsarQosInfo extends NdrObject {
        public byte context_mode;
        public byte effective_only;
        public short impersonation_level;
        public int length;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_long(this.length);
            _dst.enc_ndr_short(this.impersonation_level);
            _dst.enc_ndr_small(this.context_mode);
            _dst.enc_ndr_small(this.effective_only);
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.length = _src.dec_ndr_long();
            this.impersonation_level = (short) _src.dec_ndr_short();
            this.context_mode = (byte) _src.dec_ndr_small();
            this.effective_only = (byte) _src.dec_ndr_small();
        }
    }

    public static class LsarQueryInformationPolicy2 extends DcerpcMessage {
        public policy_handle handle;
        public NdrObject info;
        public short level;
        public int retval;

        public int getOpnum() {
            return 46;
        }

        public LsarQueryInformationPolicy2(policy_handle handle, short level, NdrObject info) {
            this.handle = handle;
            this.level = level;
            this.info = info;
        }

        public void encode_in(NdrBuffer _dst) throws NdrException {
            this.handle.encode(_dst);
            _dst.enc_ndr_short(this.level);
        }

        public void decode_out(NdrBuffer _src) throws NdrException {
            if (_src.dec_ndr_long() != 0) {
                _src.dec_ndr_short();
                this.info.decode(_src);
            }
            this.retval = _src.dec_ndr_long();
        }
    }

    public static class LsarRefDomainList extends NdrObject {
        public int count;
        public LsarTrustInformation[] domains;
        public int max_count;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.domains, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_long(this.max_count);
            if (this.domains != null) {
                _dst = _dst.deferred;
                int _domainss = this.count;
                _dst.enc_ndr_long(_domainss);
                int _domainsi = _dst.index;
                _dst.advance(_domainss * lsarpc.POLICY_INFO_DNS_DOMAIN);
                _dst = _dst.derive(_domainsi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _domainss; _i += lsarpc.SID_NAME_USER) {
                    this.domains[_i].encode(_dst);
                }
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.count = _src.dec_ndr_long();
            int _domainsp = _src.dec_ndr_long();
            this.max_count = _src.dec_ndr_long();
            if (_domainsp != 0) {
                _src = _src.deferred;
                int _domainss = _src.dec_ndr_long();
                int _domainsi = _src.index;
                _src.advance(_domainss * lsarpc.POLICY_INFO_DNS_DOMAIN);
                if (this.domains == null) {
                    if (_domainss < 0 || _domainss > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.domains = new LsarTrustInformation[_domainss];
                }
                _src = _src.derive(_domainsi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _domainss; _i += lsarpc.SID_NAME_USER) {
                    if (this.domains[_i] == null) {
                        this.domains[_i] = new LsarTrustInformation();
                    }
                    this.domains[_i].decode(_src);
                }
            }
        }
    }

    public static class LsarSidPtr extends NdrObject {
        public sid_t sid;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_referent(this.sid, lsarpc.SID_NAME_USER);
            if (this.sid != null) {
                this.sid.encode(_dst.deferred);
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (_src.dec_ndr_long() != 0) {
                if (this.sid == null) {
                    this.sid = new sid_t();
                }
                this.sid.decode(_src.deferred);
            }
        }
    }

    public static class LsarTransNameArray extends NdrObject {
        public int count;
        public LsarTranslatedName[] names;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.names, lsarpc.SID_NAME_USER);
            if (this.names != null) {
                _dst = _dst.deferred;
                int _namess = this.count;
                _dst.enc_ndr_long(_namess);
                int _namesi = _dst.index;
                _dst.advance(_namess * 16);
                _dst = _dst.derive(_namesi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _namess; _i += lsarpc.SID_NAME_USER) {
                    this.names[_i].encode(_dst);
                }
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.count = _src.dec_ndr_long();
            if (_src.dec_ndr_long() != 0) {
                _src = _src.deferred;
                int _namess = _src.dec_ndr_long();
                int _namesi = _src.index;
                _src.advance(_namess * 16);
                if (this.names == null) {
                    if (_namess < 0 || _namess > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.names = new LsarTranslatedName[_namess];
                }
                _src = _src.derive(_namesi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _namess; _i += lsarpc.SID_NAME_USER) {
                    if (this.names[_i] == null) {
                        this.names[_i] = new LsarTranslatedName();
                    }
                    this.names[_i].decode(_src);
                }
            }
        }
    }

    public static class LsarTransSidArray extends NdrObject {
        public int count;
        public LsarTranslatedSid[] sids;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_long(this.count);
            _dst.enc_ndr_referent(this.sids, lsarpc.SID_NAME_USER);
            if (this.sids != null) {
                _dst = _dst.deferred;
                int _sidss = this.count;
                _dst.enc_ndr_long(_sidss);
                int _sidsi = _dst.index;
                _dst.advance(_sidss * lsarpc.POLICY_INFO_DNS_DOMAIN);
                _dst = _dst.derive(_sidsi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _sidss; _i += lsarpc.SID_NAME_USER) {
                    this.sids[_i].encode(_dst);
                }
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.count = _src.dec_ndr_long();
            if (_src.dec_ndr_long() != 0) {
                _src = _src.deferred;
                int _sidss = _src.dec_ndr_long();
                int _sidsi = _src.index;
                _src.advance(_sidss * lsarpc.POLICY_INFO_DNS_DOMAIN);
                if (this.sids == null) {
                    if (_sidss < 0 || _sidss > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.sids = new LsarTranslatedSid[_sidss];
                }
                _src = _src.derive(_sidsi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _sidss; _i += lsarpc.SID_NAME_USER) {
                    if (this.sids[_i] == null) {
                        this.sids[_i] = new LsarTranslatedSid();
                    }
                    this.sids[_i].decode(_src);
                }
            }
        }
    }

    public static class LsarTranslatedName extends NdrObject {
        public unicode_string name;
        public int sid_index;
        public short sid_type;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_short(this.sid_type);
            _dst.enc_ndr_short(this.name.length);
            _dst.enc_ndr_short(this.name.maximum_length);
            _dst.enc_ndr_referent(this.name.buffer, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_long(this.sid_index);
            if (this.name.buffer != null) {
                _dst = _dst.deferred;
                int _name_bufferl = this.name.length / lsarpc.SID_NAME_DOM_GRP;
                _dst.enc_ndr_long(this.name.maximum_length / lsarpc.SID_NAME_DOM_GRP);
                _dst.enc_ndr_long(lsarpc.SID_NAME_USE_NONE);
                _dst.enc_ndr_long(_name_bufferl);
                int _name_bufferi = _dst.index;
                _dst.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                _dst = _dst.derive(_name_bufferi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    _dst.enc_ndr_short(this.name.buffer[_i]);
                }
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.sid_type = (short) _src.dec_ndr_short();
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.name == null) {
                this.name = new unicode_string();
            }
            this.name.length = (short) _src.dec_ndr_short();
            this.name.maximum_length = (short) _src.dec_ndr_short();
            int _name_bufferp = _src.dec_ndr_long();
            this.sid_index = _src.dec_ndr_long();
            if (_name_bufferp != 0) {
                _src = _src.deferred;
                int _name_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _name_bufferl = _src.dec_ndr_long();
                int _name_bufferi = _src.index;
                _src.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                if (this.name.buffer == null) {
                    if (_name_buffers < 0 || _name_buffers > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.name.buffer = new short[_name_buffers];
                }
                _src = _src.derive(_name_bufferi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    this.name.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
        }
    }

    public static class LsarTranslatedSid extends NdrObject {
        public int rid;
        public int sid_index;
        public int sid_type;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_short(this.sid_type);
            _dst.enc_ndr_long(this.rid);
            _dst.enc_ndr_long(this.sid_index);
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            this.sid_type = _src.dec_ndr_short();
            this.rid = _src.dec_ndr_long();
            this.sid_index = _src.dec_ndr_long();
        }
    }

    public static class LsarTrustInformation extends NdrObject {
        public unicode_string name;
        public sid_t sid;

        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(lsarpc.SID_NAME_ALIAS);
            _dst.enc_ndr_short(this.name.length);
            _dst.enc_ndr_short(this.name.maximum_length);
            _dst.enc_ndr_referent(this.name.buffer, lsarpc.SID_NAME_USER);
            _dst.enc_ndr_referent(this.sid, lsarpc.SID_NAME_USER);
            if (this.name.buffer != null) {
                _dst = _dst.deferred;
                int _name_bufferl = this.name.length / lsarpc.SID_NAME_DOM_GRP;
                _dst.enc_ndr_long(this.name.maximum_length / lsarpc.SID_NAME_DOM_GRP);
                _dst.enc_ndr_long(lsarpc.SID_NAME_USE_NONE);
                _dst.enc_ndr_long(_name_bufferl);
                int _name_bufferi = _dst.index;
                _dst.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                _dst = _dst.derive(_name_bufferi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    _dst.enc_ndr_short(this.name.buffer[_i]);
                }
            }
            if (this.sid != null) {
                this.sid.encode(_dst.deferred);
            }
        }

        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(lsarpc.SID_NAME_ALIAS);
            _src.align(lsarpc.SID_NAME_ALIAS);
            if (this.name == null) {
                this.name = new unicode_string();
            }
            this.name.length = (short) _src.dec_ndr_short();
            this.name.maximum_length = (short) _src.dec_ndr_short();
            int _name_bufferp = _src.dec_ndr_long();
            int _sidp = _src.dec_ndr_long();
            if (_name_bufferp != 0) {
                _src = _src.deferred;
                int _name_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                int _name_bufferl = _src.dec_ndr_long();
                int _name_bufferi = _src.index;
                _src.advance(_name_bufferl * lsarpc.SID_NAME_DOM_GRP);
                if (this.name.buffer == null) {
                    if (_name_buffers < 0 || _name_buffers > Message.MAXLENGTH) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.name.buffer = new short[_name_buffers];
                }
                _src = _src.derive(_name_bufferi);
                for (int _i = lsarpc.SID_NAME_USE_NONE; _i < _name_bufferl; _i += lsarpc.SID_NAME_USER) {
                    this.name.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (_sidp != 0) {
                if (this.sid == null) {
                    this.sid = new sid_t();
                }
                this.sid.decode(_src.deferred);
            }
        }
    }

    public static String getSyntax() {
        return "12345778-1234-abcd-ef00-0123456789ab:0.0";
    }
}
