/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* Costanti per identificare protocollo e ruoli */
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;

/* Definizione dei ruoli del router */
const bit<32> ROLE_LAYER2 = 1; //  nodi s1 e s4
const bit<32> ROLE_LAYER3 = 2; //  nodo s2
const bit<32> ROLE_LAYER4 = 3; //  nodo s3

/* Configurazione del nodo corrente:
   Modifica queste costanti per impostare il ruolo e se il nodo è finale.
   Ad esempio:
   - Per S1: THIS_NODE_ROLE = ROLE_LAYER2 e THIS_NODE_IS_FINAL = 0.
   - Per S2: THIS_NODE_ROLE = ROLE_LAYER3 e THIS_NODE_IS_FINAL = 0.
   - Per S3: THIS_NODE_ROLE = ROLE_LAYER4 e THIS_NODE_IS_FINAL = 0.
   - Per S4: THIS_NODE_ROLE = ROLE_LAYER2 e THIS_NODE_IS_FINAL = 1. */
const bit<32> THIS_NODE_ROLE = ROLE_LAYER2;
const bit<1>  THIS_NODE_IS_FINAL = 0;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* Header Ethernet */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/* Header IPv4 */
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

/* Header TCP (necessario per ispezione L4) */
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

/* Header per il consenso - accumula i voti:
   ora si separano in allowed, drop e abstained */
header consensus_t {
    bit<8> allowed_count;
    bit<8> drop_count;
    bit<8> abstained_count;
}

/*************************************************************************
***********************  METADATI  ***************************************
*************************************************************************/

/* Metadati per l'ingresso e il parser */
struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

/* Metadati completi:
   - switch_role: indica il livello a cui il nodo è specializzato.
   - is_final: flag che indica se il nodo è finale (ultimo prima dell'host). */
struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t    parser_metadata;
    bit<32>              switch_role; // ROLE_LAYER2, ROLE_LAYER3 o ROLE_LAYER4
    bit<1>               is_final;    // Indica se il nodo è finale
}

/*************************************************************************
***********************  STRUCTURE DEGLI HEADER  ************************
*************************************************************************/
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    consensus_t  consensus;
}

/*************************************************************************
***************  DEFINITIONI DI ERRORE  **********************************
*************************************************************************/
error { IPHeaderTooShort }

/*************************************************************************
**************************  PARSER  **************************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* Estrai sempre l'header Ethernet */
        packet.extract(hdr.ethernet);
        /* Estrai il campo consenso, inizializzato a 0 */
        packet.extract(hdr.consensus);
        /* Sulla base del ruolo, decido quanto in profondità effettuare il parsing */
        transition select(meta.switch_role) {
            ROLE_LAYER2: accept;
            ROLE_LAYER3: parse_ipv4;
            ROLE_LAYER4: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(meta.switch_role) {
            ROLE_LAYER3: accept;
            ROLE_LAYER4: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
****************  VERIFY CHECKSUM  **************************************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
****************  INGRESS  ***********************************************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /* Imposta la configurazione del nodo (questa operazione potrebbe essere gestita dal control plane);
       qui la rendiamo esplicita nel programma */
    action set_node_config() {
        meta.switch_role = THIS_NODE_ROLE;
        meta.is_final = THIS_NODE_IS_FINAL;
    }

    /* Azioni per esprimere voto */
    action vote_allowed() {
         hdr.consensus.allowed_count = hdr.consensus.allowed_count + 1;
    }
    action vote_drop() {
         hdr.consensus.drop_count = hdr.consensus.drop_count + 1;
    }
    action vote_abstain() {
         hdr.consensus.abstained_count = hdr.consensus.abstained_count + 1;
    }

    /* Azione L2 per il forwarding: usata da nodi L2 non final (es. S1) */
    action l2_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* Azione IPv4 per il forwarding: usata da nodi L3 e L4 */
    action ipv4_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table forwarding_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            vote_drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
         /* Imposta la configurazione del nodo all'inizio */
         set_node_config();
         
         /* I nodi esprimono il proprio voto in modo differenziato in funzione del ruolo:
            • ROLE_LAYER2 (Ethernet): utilizza due bit dell'indirizzo MAC sorgente
            • ROLE_LAYER3 (IPv4): utilizza due bit dell'indirizzo IPv4 sorgente
            • ROLE_LAYER4 (TCP): utilizza due bit dal campo srcPort del TCP
            La distribuzione è la stessa:
               50% (valori 0,1) => vote_allowed;
               25% (valore 2)  => vote_drop;
               25% (valore 3)  => vote_abstain.
         */
         if (meta.switch_role == ROLE_LAYER2) {
             bit<2> random_bits;
             random_bits = hdr.ethernet.srcAddr[1:0];
             if (random_bits < 2) {
                 vote_allowed();
             } else if (random_bits == 2) {
                 vote_drop();
             } else {
                 vote_abstain();
             }
             /* Se il nodo non è finale (es. S1) allora esegue forwarding L2 verso il prossimo nodo */
             if (meta.is_final == 0) {
                 l2_forward(2); // 2 rappresenta la porta verso il prossimo nodo
             }
         } else if (meta.switch_role == ROLE_LAYER3) {
             bit<2> random_bits;
             random_bits = hdr.ipv4.srcAddr[1:0];
             if (random_bits < 2) {
                 vote_allowed();
             } else if (random_bits == 2) {
                 vote_drop();
             } else {
                 vote_abstain();
             }
         } else if (meta.switch_role == ROLE_LAYER4) {
             bit<2> random_bits;
             random_bits = hdr.tcp.srcPort[1:0];
             if (random_bits < 2) {
                 vote_allowed();
             } else if (random_bits == 2) {
                 vote_drop();
             } else {
                 vote_abstain();
             }
         }
         
         /* Applica la tabella di forwarding per i pacchetti IPv4 */
         if (hdr.ipv4.isValid()) {
             forwarding_table.apply();
         }
    }
}

/*************************************************************************
****************  EGRESS  ***********************************************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action decide_consensus() {
         /* Se i voti allowed superano la metà dei voti totali (allowed + drop + abstained)
            il pacchetto viene inoltrato verso l'host; altrimenti, scartato */
         if (hdr.consensus.allowed_count * 2 <= (hdr.consensus.allowed_count +
                                                 hdr.consensus.drop_count +
                                                 hdr.consensus.abstained_count)) {
             mark_to_drop(standard_metadata);
         }
    }

    apply {
         /* La decisione finale è eseguita solo se il nodo è finale (es. S4) */
         if (meta.is_final == 1) {
             decide_consensus();
         }
         /* Per i nodi non final, viene eseguito solo il forwarding (già impostato in Ingress) */
    }
}

/*************************************************************************
*************  COMPUTE CHECKSUM  *****************************************
*************************************************************************/
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

/*************************************************************************
***************  DEPARSE  *************************************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
         packet.emit(hdr.ethernet);
         if (hdr.ipv4.isValid()) {
             packet.emit(hdr.ipv4);
         }
         if (hdr.tcp.isValid()) {
             packet.emit(hdr.tcp);
         }
         /* L'header consensus può essere emesso per diagnosticare la votazione */
         packet.emit(hdr.consensus);
    }
}

/*************************************************************************
***********************  SWITCH  *****************************************
*************************************************************************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
