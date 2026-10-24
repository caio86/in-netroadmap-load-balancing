#include <core.p4>
#include <v1model.p4>

const bit<16> LINK_STATE1 = 16;
const bit<16> LINK_STATE2 = 32;
const bit<16> LINK_STATE3 = 48;

const bit<32> COST1 = 1;
const bit<32> COST2 = 4;
const bit<32> COST3 = 7;

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
    bit<8> link;
    bit<1> balanced;
}

register<bit<16>>(4) qdepth;

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

    register<bit<32>>(1)    last_time;
    register<bit<1>>(1)     valid_learning;
    register<bit<32>>(1)    iterations;
    register<bit<32>>(1)    last_state;
    register<bit<32>>(1)    last_action;
    register<bit<8>>(4)     lb_weights;
    register<bit<16>>(1)    total_buckets;
    register<bit<32>>(256)  q_table;
    register<bit<32>>(4)    dbg;
    counter(32, CounterType.packets) bucket_pkts;
    counter(32, CounterType.packets) link_pkts;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(macAddr_t dmac, egressSpec_t port) {
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_lb_group() {
        // Set flow bucket
        bit<16> n_buckets;
        total_buckets.read(n_buckets, 0);
        hash(
            meta.bucket,
            HashAlgorithm.crc32,
            16w0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                hdr.l4.srcPort,
                hdr.l4.dstPort,
            },
            n_buckets
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
        meta.balanced = 0;
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 1) {
            // Executar apartir daqui só se qlearning estiver ativado no switch
            // desativar para s2, s3, s4

            // 2^17 us ~= 130ms
            bit<32> current_time = (bit<32>) (standard_metadata.ingress_global_timestamp >> 17);
            bit<32> time;
            last_time.read(time, 0);

            if (current_time != time) {
                last_time.write(0, current_time);
                // 1. Capturar o estado atual
                // Onde qN é a queue do link N
                bit<16> q0;
                bit<16> q1;
                qdepth.read(q0, 0);
                qdepth.read(q1, 1);

                // Onde sN é a categoria do estado da queue do link N
                // Vai de 0 a 3
                // Dá pra mudar para uma MAT?
                bit<32> s0 = 0;
                if (q0 < LINK_STATE1) s0 = 0;
                else if (q0 < LINK_STATE2) s0 = 1;
                else if (q0 < LINK_STATE3) s0 = 2;
                else s0 = 3;

                bit<32> s1 = 0;
                if (q1 < LINK_STATE1) s1 = 0;
                else if (q1 < LINK_STATE2) s1 = 1;
                else if (q1 < LINK_STATE3) s1 = 2;
                else s1 = 3;

                // Tamanho dessas V variaveis devem mudar com a quantidade de links de saida
                bit<32> state = (s0 << 2) | s1;
                bit<32> q_idx = state << 2;

                // 2 Calcular o custo
                bit<32> cost = 0;
                if (s0 == 1) { cost = cost + COST1; } else { if (s0 == 2) { cost = cost + COST2 ; } else { if (s0 == 3) { cost = cost + COST3 ; }}}
                if (s1 == 1) { cost = cost + COST1; } else { if (s1 == 2) { cost = cost + COST2 ; } else { if (s1 == 3) { cost = cost + COST3 ; }}}

                // 3. Escolhendo melhor ação
                bit<32> ma; // Melhor ação
                bit<32> acao = 0; // Indice ação | Começando com fazer nada
                bit<32> qa; // Q-value da ação
                q_table.read(ma, q_idx); // fazer nada
                q_table.read(qa, q_idx | 1); if (qa < ma) { ma = qa; acao = 1; } // Mover de 0 para 1
                q_table.read(qa, q_idx | 2); if (qa < ma) { ma = qa; acao = 2; } // Mover de 1 para 0

                // 4. Atualizar tabela
                // Aplicar parametros depois: DISCOUNT, LEARNING_RATE

                bit<1> valid;
                valid_learning.read(valid, 0);
                if (valid == 1) {
                    bit<32> ls;
                    last_state.read(ls, 0);
                    bit<32> la;
                    last_action.read(la, 0);
                    bit<32> last_q_idx = ( ls << 2 ) | la;

                    // Custo é em inteiro
                    bit<32> cost_scaled = cost << 8;

                    bit<32> discounted_future = (bit<32>) ((((bit<64>) 230 * (bit<64>) ma)) >> 8);

                    bit<32> tgt = cost_scaled + discounted_future;

                    bit<32> old_q;
                    q_table.read(old_q, last_q_idx);

                    bit<32> td_err;
                    bit<32> delta;
                    bit<32> new_q;
                    bit<32> step;
                    bit<64> product;

                    if (tgt >= old_q) {
                        delta = tgt - old_q;

                        product = (bit<64>) 64 * (bit<64>) delta;

                        step = (bit<32>) (product >> 8);
                        new_q = old_q + step;
                    } else {
                        delta = old_q - tgt;

                        product = (bit<64>) 64 * (bit<64>) delta;

                        step = (bit<32>) (product >> 8);
                        new_q = old_q - step;
                    }

                    // Salvar resultado na tabela
                    q_table.write(last_q_idx, new_q);
                }


                // 5.1 Realizar ação

                // Provavelmente vira uma MAT
                bit<32> wi_index;
                bit<32> wj_index;
                if (acao == 1) {
                    wi_index = 0;
                    wj_index = 1;
                } else {
                    wi_index = 1;
                    wj_index = 0;
                }

                // 5.2 Atualizar pesos de acordo com a ação
                if (acao != 0) {
                    bit<8> wi;
                    bit<8> wj;
                    lb_weights.read(wi, wi_index);
                    if (wi > 1) { // 1 Sendo o valor minimo de cada peso
                        lb_weights.read(wj, wj_index);
                        lb_weights.write(wi_index, wi - 1);
                        lb_weights.write(wj_index, wj + 1);
                    }
                }

                // 5.3 Pos execução
                last_state.write(0, state);
                last_action.write(0, acao);
                valid_learning.write(0, 1);

                // 5.4 Modificar parametros
                // 5.5 Registrar logs

                bit<32> iter;
                iterations.read(iter, 0);
                iter = iter + 1;
                iterations.write(0, iter);

                dbg.write(0, state);
                bit<32> cc = 0;
                dbg.read(cc, 1);
                dbg.write(1, cc + cost);
                dbg.write(2, acao);
                dbg.write(3, iter);
            }

            // 6. Encaminhamento
            switch(ipv4_lpm.apply().action_run) {
                set_lb_group: {
                    // 5.1 Set out put lb link
                    bit<8> w0;
                    lb_weights.read(w0, 0);
                    if (meta.bucket < (bit<16>) w0) {
                        meta.link = 0;
                    } else {
                        meta.link = 1;
                    }
                    link_pkts.count((bit<32>) meta.link);
                    meta.balanced = 1;


                    // 5.2 Set output Port
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

            if (meta.balanced == 1) {
                bit<16> q;
                bit<16> sample_qdepth = (bit<16>) standard_metadata.deq_qdepth;
                qdepth.read(q, (bit<32>) meta.link);
                q = q - (q >> 2) + (sample_qdepth >> 2);
                qdepth.write((bit<32>) meta.link, q);
            }
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
