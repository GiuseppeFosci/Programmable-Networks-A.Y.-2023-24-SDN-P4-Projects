#include <core.p4>
#include <v1model.p4>

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<16> TYPE_IPV4 = 0x800;

const bit<32> ROLE_LAYER2 = 1;
const bit<32> ROLE_LAYER3 = 2;
const bit<32> ROLE_LAYER4 = 3;

const bit<32> THIS_NODE_ROLE = ROLE_LAYER2;
const bit<1>  THIS_NODE_IS_FINAL = 1;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  reserved;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header consensus_t {
    bit<8> allowed_count;
    bit<8> drop_count;
    bit<8> abstained_count;
}

struct metadata {
    bit<32> switch_role;
    bit<1>  is_final;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    consensus_t  consensus;
}

parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        pkt.extract(hdr.consensus);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action set_node_config() {
        meta.switch_role = THIS_NODE_ROLE;
        meta.is_final = THIS_NODE_IS_FINAL;
        log_msg("Nodo configurato con ruolo: {}", {meta.switch_role});
    }

    action vote_allowed() {
        hdr.consensus.allowed_count = hdr.consensus.allowed_count + 1;
        log_msg("Nodo {}: Voto CONSENTITO per pacchetto con destinazione: {} (timestamp-based)", {meta.switch_role, hdr.ipv4.dstAddr});
    }

    action vote_drop() {
        hdr.consensus.drop_count = hdr.consensus.drop_count + 1;
        log_msg("Nodo {}: Voto RIFIUTATO per pacchetto con destinazione: {} (timestamp-based)", {meta.switch_role, hdr.ipv4.dstAddr});
    }

    action vote_abstain() {
        hdr.consensus.abstained_count = hdr.consensus.abstained_count + 1;
        log_msg("Nodo {}: Voto ASTENUTO per pacchetto con destinazione: {} (timestamp-based)", {meta.switch_role, hdr.ipv4.dstAddr});
    }

    action drop() {
        mark_to_drop(standard_metadata);
        log_msg("Nodo {}: Pacchetto RIFIUTATO", {meta.switch_role});
    }

    action ipv4_forward(bit<9> outPort) {
        standard_metadata.egress_spec = outPort;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        log_msg("Nodo {}: Pacchetto INOLTRATO alla porta {}", {meta.switch_role, outPort});
    }

    action l2_forward(bit<9> outPort) {
        standard_metadata.egress_spec = outPort;
        log_msg("Nodo {}: Inoltro L2 pacchetto alla porta {}", {meta.switch_role, outPort});
    }

    table CMH_forwarding_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        set_node_config();

        if (meta.switch_role == ROLE_LAYER2) {
            bit<2> ts = standard_metadata.ingress_global_timestamp[1:0];
            bit<2> field = hdr.ethernet.srcAddr[1:0];
            bit<2> rnd = ts ^ field; 
            if (rnd < 2) {
                vote_allowed();
            } else if (rnd == 2) {
                vote_drop();
            } else {
                vote_abstain();
            }
            if (meta.is_final == 0) {
                l2_forward(2);
            }

        } else if (meta.switch_role == ROLE_LAYER3) {
            
            bit<2> ts = standard_metadata.ingress_global_timestamp[1:0];
            bit<2> field = hdr.ipv4.srcAddr[1:0];
            bit<2> rnd = ts ^ field; 
            if (rnd < 2) {
                vote_allowed();
            } else if (rnd == 2) {
                vote_drop();
            } else {
                vote_abstain();
            }
            CMH_forwarding_table.apply();

        } else if (meta.switch_role == ROLE_LAYER4) {
            if (hdr.tcp.isValid()) {
               
                bit<2> ts = standard_metadata.ingress_global_timestamp[1:0];
                bit<2> field = hdr.tcp.srcPort[1:0];
                bit<2> rnd = ts ^ field; 
                if (rnd < 2) {
                    vote_allowed();
                } else if (rnd == 2) {
                    vote_drop();
                } else {
                    vote_abstain();
                }
            }
            CMH_forwarding_table.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
        log_msg("Egress: Pacchetto RIFIUTATO dal consenso", {});
    }

    apply {
        if (meta.is_final == 1) {
            bit<8> allowed = hdr.consensus.allowed_count;
            bit<8> total = hdr.consensus.allowed_count +
                           hdr.consensus.drop_count +
                           hdr.consensus.abstained_count;

            log_msg("Egress: Consenso finale (consentito={}, rifiutato={}, astenuto={})", {
                hdr.consensus.allowed_count,
                hdr.consensus.drop_count,
                hdr.consensus.abstained_count
            });

            if (allowed * 2 <= total) {
                drop();
            } else {
                log_msg("Egress: Pacchetto INOLTRATO dal consenso", {});
            }
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.consensus);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
