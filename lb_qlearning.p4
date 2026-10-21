#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_TCP = 6;
const bit<8>  PROTO_UDP = 17;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* ----------------------------------------------------------------- headers */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header l4_ports_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    l4_ports_t l4;
}

struct metadata {
    bit<16> bucket;
    bit<16> link;
}

/* ------------------------------------------------------------------ parser */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_l4;
            PROTO_UDP: parse_l4;
            default:   accept;
        }
    }

    state parse_l4 {
        packet.extract(hdr.l4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* ----------------------------------------------------------------- ingress */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<8>>(4) lb_weights;
    counter(32, CounterType.packets) bucket_pkts;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(macAddr_t dmac, egressSpec_t port) {
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_lb_group(bit<16> count) {
        // Set flow bucket
        hash(
            meta.bucket,
            HashAlgorithm.crc16,
            16w0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                hdr.l4.srcPort,
                hdr.l4.dstPort,
            },
            count
        );
        bucket_pkts.count((bit<32>) meta.bucket);
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { set_nhop; set_lb_group; drop; }
        size = 1024;
        default_action = drop();
    }

    table lb_nhop {
        key = { meta.link: exact; }
        actions = { set_nhop; drop; }
        size = 64;
        default_action = drop();
    }


    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 1) {
            switch(ipv4_lpm.apply().action_run) {
                set_lb_group: {
                    // Set out put lb link
                    bit<8> w0;
                    lb_weights.read(w0, 0);
                    if (meta.bucket < (bit<16>) w0) {
                        meta.link = 0;
                    } else {
                        meta.link = 1;
                    }

                    // Set output Port
                    lb_nhop.apply();
                }
            }
        } else {
            drop();
        }
    }
}

/* ------------------------------------------------------------------ egress */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    counter(64, CounterType.packets) tx_per_port;

    action rewrite_mac(macAddr_t smac) {
        hdr.ethernet.srcAddr = smac;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table send_frame {
        key = {standard_metadata.egress_port: exact; }
        actions = {rewrite_mac; drop; }
        size = 64;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            send_frame.apply();
            tx_per_port.count((bit<32>) standard_metadata.egress_port);
        }
    }
}

/* ---------------------------------------------------------------- checksum */
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

/* ---------------------------------------------------------------- deparser */
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.l4);
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
