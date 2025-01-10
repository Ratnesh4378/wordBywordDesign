
// cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE/install \ 
// -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=bolt_tofino // -DP4_PATH=/home/abhik/BOLT-v2_modified/bolt_tofino.p4

#include <core.p4>
#include <tna.p4>

const bit<8> TABLE_NUM = 1;

const bit<16> ETHER_HEADER_LENGTH = 14;
const bit<16> IPV4_HEADER_LENGTH = 20;
const bit<16> ICMP_HEADER_LENGTH = 8;
const bit<16> TCP_HEADER_LENGTH = 20;
const bit<16> UDP_HEADER_LENGTH = 8;

#define ETH_TYPE_IPV4   0x800
#define ETH_TYPE_ARP    0x0806
// #define ETH_TYPE_RCLT   0x1000

#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_ID_RCLT       111

// Tofino interfaces
// #define IFACE_RCLT  68
#define IFACE_DUMMY 100  // Any dummy port

// Packet type for recirculation. Any dummy value will work
#define PACKET_TYPE_NORMAL      1
#define PACKET_TYPE_MIRROR      2
#define PACKET_ETH_TYPE_RCLT    3

#define CHAR_COMMA              0x2c

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// All typedefs will be here
typedef bit<8>  patrn_state_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> string_t;
typedef bit<16> state_t;
typedef bit<8> bucket_t;
// typedef bit<8> bucket_counter_t;
typedef bit<8>  pkt_type_t;

header mirror_h {
    // Used by Mirror extern
    pkt_type_t  pkt_type;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   ethType;
}

header rclt_t {
    state_t state;
    bit<8> rclt_count;
    bit<8> discardBytes;
    // #1: b1, b2 etc (Buckets)
    bucket_t b1;
    bucket_t b2;
    bucket_t b3;

    bit<8> packet_type;
    bit<8> cur_value_code;
    // #2: Entries for all possible values

    // #3: Space inside the rclt header to store direct match headers stuff

}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hp_addr_len;
    bit<8> protocol_len;
    bit<16> op_code;
    bit<48> senderMac;
    bit<32> senderIPv4;
    bit<48> targetMac;
    bit<32> targetIPv4;
}

header ipv4_t {
    // bit<4>    version;
    // bit<4>    ihl;
    // bit<8>    diffserv;
    bit<16>   pre;
    bit<14>   totalLen_msb;
    bit<2>    totalLen_lsb;
    bit<8>    id_msb;
    bit<8>    id;
    // bit<3>    flags;
    bit<16>   flags_fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_egress_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<8>    id_msb;
    bit<8>    id;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_opt_t {
    bit<32> op1;
    bit<32> op2;
    bit<32> op3;
}

header mirror_bridged_metadata_h {
    // Cut out during egress
    pkt_type_t pkt_type;
}

struct egress_header_t {
    mirror_bridged_metadata_h bridged_meta;
    ethernet_t ethernet;
    ipv4_egress_t ipv4_egress;
    rclt_t rclt;
}

struct egress_metadata_t {
    // Empty egress metadata. No egress processing as of now
}

header dummy_t {
    bit<8> c;
}

header dummy4B_t {
    bit<32> c;
}

header value_t {
    bit<8> c;
}

// Header definitions for direct matches


struct ingress_metadata_t {
    bit<1> mark_to_rec;
    bit<32> arpTargetIPv4_temp;
    pkt_type_t pkt_type;
    MirrorId_t ing_mir_ses;     // 10 bit
    bit<8> op_failed;
    
    // #3: cur_val_combined entries

    bit<8> packet_id;
    // #4: index_0 etc entries

}

header patrn_t {
    // #5 Each key width like 4 Byte, 2 Byte etc
    bit<32> pattern;
}

struct ingress_header_t {
    mirror_bridged_metadata_h bridged_meta;
    ethernet_t              ethernet;
    arp_t                   arp;
    ipv4_t                  ipv4;
    rclt_t                  rclt;
    tcp_t                   tcp;
    tcp_opt_t                tcp_op;
    // #6: Header entries for Dummies
    dummy_t    dummy_1;
    dummy_t    dummy_2;
    dummy_t    dummy_3;
    dummy_t    dummy_4;
    dummy4B_t  dummy4B_1;
    dummy4B_t  dummy4B_2;
    dummy4B_t  dummy4B_3;
    dummy4B_t  dummy4B_4;
    dummy4B_t  dummy4B_5;
    dummy4B_t  dummy4B_6;
    dummy4B_t  dummy4B_7;

    // #7: Header entries for Values
    value_t    v0;
    value_t    v1;
    value_t    v2;
    value_t    v3;
    value_t    v4;
    value_t    v5;
    value_t    v6;
    value_t    v7;

    // #8: Header entries for Patterns
    patrn_t    patrn_0;
    patrn_t    patrn_1;
    patrn_t    patrn_2;
    patrn_t    patrn_3;
    patrn_t    patrn_4;
    patrn_t    patrn_5;
    patrn_t    patrn_6;
    patrn_t    patrn_7;
    patrn_t    patrn_8;
    patrn_t    patrn_9;
    patrn_t    patrn_10;
    patrn_t    patrn_11;
    patrn_t    patrn_12;
    patrn_t    patrn_13;
    patrn_t    patrn_14;
    patrn_t    patrn_15;
    patrn_t    patrn_16;
    patrn_t    patrn_17;
    patrn_t    patrn_18;
    patrn_t    patrn_19;
    patrn_t    patrn_20;
    patrn_t    patrn_21;
    patrn_t    patrn_22;
    patrn_t    patrn_23;
    patrn_t    patrn_24;
    patrn_t    patrn_25;
    patrn_t    patrn_26;
    patrn_t    patrn_27;
    patrn_t    patrn_28;
    patrn_t    patrn_29;
    patrn_t    patrn_30;
    patrn_t    patrn_31;
    patrn_t    patrn_32;
    patrn_t    patrn_33;
    patrn_t    patrn_34;
    patrn_t    patrn_35;
    patrn_t    patrn_36;
    patrn_t    patrn_37;
    patrn_t    patrn_38;
    patrn_t    patrn_39;
    patrn_t    patrn_40;
    patrn_t    patrn_41;
    patrn_t    patrn_42;
    patrn_t    patrn_43;
    patrn_t    patrn_44;
    patrn_t    patrn_45;
    patrn_t    patrn_46;
    patrn_t    patrn_47;
    patrn_t    patrn_48;
    patrn_t    patrn_49;
    patrn_t    patrn_50;
    patrn_t    patrn_51;
    patrn_t    patrn_52;
    patrn_t    patrn_53;
    patrn_t    patrn_54;
    patrn_t    patrn_55;

    // #9: Header entries for Direct match headers - Fixed offset and size


}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

control IngressDeparser(
        packet_out packet,
        inout ingress_header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Mirror() mirror;
    
    apply {
        if (ig_dprsr_md.mirror_type == 1){
            mirror.emit<mirror_h>(ig_md.ing_mir_ses, {ig_md.pkt_type});
        }
        packet.emit(hdr.bridged_meta);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.rclt);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_op);

        // #1: Emitting value headers
        packet.emit(hdr.v0);
        packet.emit(hdr.v1);
        packet.emit(hdr.v2);
        packet.emit(hdr.v3);
        packet.emit(hdr.v4);
        packet.emit(hdr.v5);
        packet.emit(hdr.v6);
        packet.emit(hdr.v7);

        // #2 Individual emits excluding dummy headers
        packet.emit(hdr.patrn_0);
        packet.emit(hdr.patrn_1);
        packet.emit(hdr.patrn_2);
        packet.emit(hdr.patrn_3);
        packet.emit(hdr.patrn_4);
        packet.emit(hdr.patrn_5);
        packet.emit(hdr.patrn_6);
        packet.emit(hdr.patrn_7);
        packet.emit(hdr.patrn_8);
        packet.emit(hdr.patrn_9);
        packet.emit(hdr.patrn_10);
        packet.emit(hdr.patrn_11);
        packet.emit(hdr.patrn_12);
        packet.emit(hdr.patrn_13);
        packet.emit(hdr.patrn_14);
        packet.emit(hdr.patrn_15);
        packet.emit(hdr.patrn_16);
        packet.emit(hdr.patrn_17);
        packet.emit(hdr.patrn_18);
        packet.emit(hdr.patrn_19);
        packet.emit(hdr.patrn_20);
        packet.emit(hdr.patrn_21);
        packet.emit(hdr.patrn_22);
        packet.emit(hdr.patrn_23);
        packet.emit(hdr.patrn_24);
        packet.emit(hdr.patrn_25);
        packet.emit(hdr.patrn_26);
        packet.emit(hdr.patrn_27);
        packet.emit(hdr.patrn_28);
        packet.emit(hdr.patrn_29);
        packet.emit(hdr.patrn_30);
        packet.emit(hdr.patrn_31);
        packet.emit(hdr.patrn_32);
        packet.emit(hdr.patrn_33);
        packet.emit(hdr.patrn_34);
        packet.emit(hdr.patrn_35);
        packet.emit(hdr.patrn_36);
        packet.emit(hdr.patrn_37);
        packet.emit(hdr.patrn_38);
        packet.emit(hdr.patrn_39);
        packet.emit(hdr.patrn_40);
        packet.emit(hdr.patrn_41);
        packet.emit(hdr.patrn_42);
        packet.emit(hdr.patrn_43);
        packet.emit(hdr.patrn_44);
        packet.emit(hdr.patrn_45);
        packet.emit(hdr.patrn_46);
        packet.emit(hdr.patrn_47);
        packet.emit(hdr.patrn_48);
        packet.emit(hdr.patrn_49);
        packet.emit(hdr.patrn_50);
        packet.emit(hdr.patrn_51);
        packet.emit(hdr.patrn_52);
        packet.emit(hdr.patrn_53);
        packet.emit(hdr.patrn_54);
        packet.emit(hdr.patrn_55);

        // #3: Emitting direct match headers

    }
}

// Empty egress parser/control blocks
parser EgressParser(
        packet_in packet,
        out egress_header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        // Note: our bfidged_meta header and packet_type i.e. appended in front 
        // of mirrored packet is of same width. All subsequent recirculate packet
        // also have this appended. So, we can extract and remove this from all
        // packets without checking any value 
        packet.extract(hdr.bridged_meta);
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.ethType) {
            ETH_TYPE_IPV4: parse_ipv4_egress;
            default: accept;
        }        
    }

    state parse_ipv4_egress {
        packet.extract(hdr.ipv4_egress);
        transition select(hdr.ipv4_egress.id) {
            IP_ID_RCLT: parse_rclt;
            default: accept;
        }
    }

    state parse_rclt {
        packet.extract(hdr.rclt);
        transition accept;
    }
}

// Empty Egress Deparser
control EgressDeparser(
        packet_out packet,
        inout egress_header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {

    apply {
        // Selectively emmiting ethernet only
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4_egress);
        packet.emit(hdr.rclt);
    }
}

parser IngressParser(
        packet_in packet,
        out ingress_header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    // TNA specific code
    state start {
        transition parse_tofino;
    }

    state parse_tofino {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        ig_md.mark_to_rec = 0;
        transition select(hdr.ethernet.ethType){
            ETH_TYPE_IPV4 : parse_ipv4;
            ETH_TYPE_ARP : parse_arp;
            default : accept; 
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        ig_md.arpTargetIPv4_temp = hdr.arp.targetIPv4;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.id){
           IP_ID_RCLT: parse_rclt;
            default: parse_tcp_norclt;
        }
    }



    state parse_rclt {
        packet.extract(hdr.rclt);
        transition parse_tcp_rclt;
    }

    // Abhishek: This state wont be reached now if we are trying to do direct match extract in the first occurence of packet
    state parse_tcp_norclt {
        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_op);
        transition parse_value_or_pattern;
    }
    
    state parse_tcp_rclt {
        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_op);
        transition select(hdr.rclt.discardBytes){
            0: parse_value_or_pattern; // #3: parse_cut_actions generated below
            0: parse_value_or_pattern;
            2: parse_cut_2B;
            3: parse_cut_3B;
            4: parse_cut_4B;
            5: parse_cut_5B;
            6: parse_cut_6B;
            7: parse_cut_7B;
            8: parse_cut_8B;
            9: parse_cut_9B;
            10: parse_cut_10B;
            11: parse_cut_11B;
            12: parse_cut_12B;
            13: parse_cut_13B;
            14: parse_cut_14B;
            15: parse_cut_15B;
            16: parse_cut_16B;
            17: parse_cut_17B;
            18: parse_cut_18B;
            19: parse_cut_19B;
            20: parse_cut_20B;
            21: parse_cut_21B;
            22: parse_cut_22B;
            23: parse_cut_23B;
            24: parse_cut_24B;
            25: parse_cut_25B;
            26: parse_cut_26B;
            27: parse_cut_27B;
            28: parse_cut_28B;
            29: parse_cut_29B;
            30: parse_cut_30B;
            31: parse_cut_31B;
            32: parse_cut_32B;
            default: parse_value_or_pattern;

        }
    }

    // #4: Parse discard/dummy headers based on stride size
    state parse_cut_1B {
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_2B {
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_3B {
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_4B {
        packet.extract(hdr.dummy4B_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_5B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_6B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_7B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_8B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_9B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_10B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_11B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_12B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_13B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_14B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_15B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_16B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        transition parse_value_or_pattern;
    }

    state parse_cut_17B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_18B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_19B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_20B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        transition parse_value_or_pattern;
    }

    state parse_cut_21B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_22B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_23B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_24B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        transition parse_value_or_pattern;
    }

    state parse_cut_25B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_26B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_27B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_28B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy4B_7);
        transition parse_value_or_pattern;
    }

    state parse_cut_29B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy4B_7);
        packet.extract(hdr.dummy_1);
        transition parse_value_or_pattern;
    }

    state parse_cut_30B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy4B_7);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        transition parse_value_or_pattern;
    }

    state parse_cut_31B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy4B_7);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        transition parse_value_or_pattern;
    }

    state parse_cut_32B {
        packet.extract(hdr.dummy4B_1);
        packet.extract(hdr.dummy4B_2);
        packet.extract(hdr.dummy4B_3);
        packet.extract(hdr.dummy4B_4);
        packet.extract(hdr.dummy4B_5);
        packet.extract(hdr.dummy4B_6);
        packet.extract(hdr.dummy4B_7);
        packet.extract(hdr.dummy_1);
        packet.extract(hdr.dummy_2);
        packet.extract(hdr.dummy_3);
        packet.extract(hdr.dummy_4);
        transition parse_value_or_pattern;
    }

  
    // #5: state parse_value_or_pattern has to be generated
    state parse_value_or_pattern {
        ig_md.packet_id = 0;
        transition select(hdr.rclt.cur_value_code){
            default: parse_pattern_start;
        }
    }

    // #6: Parsing value headers
    state parse_value_0 {
        packet.extract(hdr.v0);
        transition select(hdr.v0.c){
            CHAR_COMMA: accept;
            default: parse_value_1;
        }
    }
    state parse_value_1 {
        packet.extract(hdr.v1);
        transition select(hdr.v1.c){
            CHAR_COMMA: accept;
            default: parse_value_2;
        }
    }
    state parse_value_2 {
        packet.extract(hdr.v2);
        transition select(hdr.v2.c){
            CHAR_COMMA: accept;
            default: parse_value_3;
        }
    }
    state parse_value_3 {
        packet.extract(hdr.v3);
        transition select(hdr.v3.c){
            CHAR_COMMA: accept;
            default: parse_value_4;
        }
    }
    state parse_value_4 {
        packet.extract(hdr.v4);
        transition select(hdr.v4.c){
            CHAR_COMMA: accept;
            default: parse_value_5;
        }
    }
    state parse_value_5 {
        packet.extract(hdr.v5);
        transition select(hdr.v5.c){
            CHAR_COMMA: accept;
            default: parse_value_6;
        }
    }
    state parse_value_6 {
        packet.extract(hdr.v6);
        transition select(hdr.v6.c){
            CHAR_COMMA: accept;
            default: parse_value_7;
        }
    }
    state parse_value_7 {
        packet.extract(hdr.v7);
        transition accept;
    }


    state parse_pattern_start {
        transition select (hdr.ipv4.totalLen_msb){
            12: accept;
            default: parse_pattern_0;
        }
    }

    // #7 Parsing Patterns' headers
    state parse_pattern_0 {
        packet.extract(hdr.patrn_0);
        transition select(hdr.ipv4.totalLen_msb){
            13: accept;
            default: parse_pattern_1;
        }
    }
    state parse_pattern_1 {
        packet.extract(hdr.patrn_1);
        transition select(hdr.ipv4.totalLen_msb){
            14: accept;
            default: parse_pattern_2;
        }
    }
    state parse_pattern_2 {
        packet.extract(hdr.patrn_2);
        transition select(hdr.ipv4.totalLen_msb){
            15: accept;
            default: parse_pattern_3;
        }
    }
    state parse_pattern_3 {
        packet.extract(hdr.patrn_3);
        transition select(hdr.ipv4.totalLen_msb){
            16: accept;
            default: parse_pattern_4;
        }
    }
    state parse_pattern_4 {
        packet.extract(hdr.patrn_4);
        transition select(hdr.ipv4.totalLen_msb){
            17: accept;
            default: parse_pattern_5;
        }
    }
    state parse_pattern_5 {
        packet.extract(hdr.patrn_5);
        transition select(hdr.ipv4.totalLen_msb){
            18: accept;
            default: parse_pattern_6;
        }
    }
    state parse_pattern_6 {
        packet.extract(hdr.patrn_6);
        transition select(hdr.ipv4.totalLen_msb){
            19: accept;
            default: parse_pattern_7;
        }
    }
    state parse_pattern_7 {
        packet.extract(hdr.patrn_7);
        transition select(hdr.ipv4.totalLen_msb){
            20: accept;
            default: parse_pattern_8;
        }
    }
    state parse_pattern_8 {
        packet.extract(hdr.patrn_8);
        transition select(hdr.ipv4.totalLen_msb){
            21: accept;
            default: parse_pattern_9;
        }
    }
    state parse_pattern_9 {
        packet.extract(hdr.patrn_9);
        transition select(hdr.ipv4.totalLen_msb){
            22: accept;
            default: parse_pattern_10;
        }
    }
    state parse_pattern_10 {
        packet.extract(hdr.patrn_10);
        transition select(hdr.ipv4.totalLen_msb){
            23: accept;
            default: parse_pattern_11;
        }
    }
    state parse_pattern_11 {
        packet.extract(hdr.patrn_11);
        transition select(hdr.ipv4.totalLen_msb){
            24: accept;
            default: parse_pattern_12;
        }
    }
    state parse_pattern_12 {
        packet.extract(hdr.patrn_12);
        transition select(hdr.ipv4.totalLen_msb){
            25: accept;
            default: parse_pattern_13;
        }
    }
    state parse_pattern_13 {
        packet.extract(hdr.patrn_13);
        transition select(hdr.ipv4.totalLen_msb){
            26: accept;
            default: parse_pattern_14;
        }
    }
    state parse_pattern_14 {
        packet.extract(hdr.patrn_14);
        transition select(hdr.ipv4.totalLen_msb){
            27: accept;
            default: parse_pattern_15;
        }
    }
    state parse_pattern_15 {
        packet.extract(hdr.patrn_15);
        transition select(hdr.ipv4.totalLen_msb){
            28: accept;
            default: parse_pattern_16;
        }
    }
    state parse_pattern_16 {
        packet.extract(hdr.patrn_16);
        transition select(hdr.ipv4.totalLen_msb){
            29: accept;
            default: parse_pattern_17;
        }
    }
    state parse_pattern_17 {
        packet.extract(hdr.patrn_17);
        transition select(hdr.ipv4.totalLen_msb){
            30: accept;
            default: parse_pattern_18;
        }
    }
    state parse_pattern_18 {
        packet.extract(hdr.patrn_18);
        transition select(hdr.ipv4.totalLen_msb){
            31: accept;
            default: parse_pattern_19;
        }
    }
    state parse_pattern_19 {
        packet.extract(hdr.patrn_19);
        transition select(hdr.ipv4.totalLen_msb){
            32: accept;
            default: parse_pattern_20;
        }
    }
    state parse_pattern_20 {
        packet.extract(hdr.patrn_20);
        transition select(hdr.ipv4.totalLen_msb){
            33: accept;
            default: parse_pattern_21;
        }
    }
    state parse_pattern_21 {
        packet.extract(hdr.patrn_21);
        transition select(hdr.ipv4.totalLen_msb){
            34: accept;
            default: parse_pattern_22;
        }
    }
    state parse_pattern_22 {
        packet.extract(hdr.patrn_22);
        transition select(hdr.ipv4.totalLen_msb){
            35: accept;
            default: parse_pattern_23;
        }
    }
    state parse_pattern_23 {
        packet.extract(hdr.patrn_23);
        transition select(hdr.ipv4.totalLen_msb){
            36: accept;
            default: parse_pattern_24;
        }
    }
    state parse_pattern_24 {
        packet.extract(hdr.patrn_24);
        transition select(hdr.ipv4.totalLen_msb){
            37: accept;
            default: parse_pattern_25;
        }
    }
    state parse_pattern_25 {
        packet.extract(hdr.patrn_25);
        transition select(hdr.ipv4.totalLen_msb){
            38: accept;
            default: parse_pattern_26;
        }
    }
    state parse_pattern_26 {
        packet.extract(hdr.patrn_26);
        transition select(hdr.ipv4.totalLen_msb){
            39: accept;
            default: parse_pattern_27;
        }
    }
    state parse_pattern_27 {
        packet.extract(hdr.patrn_27);
        transition select(hdr.ipv4.totalLen_msb){
            40: accept;
            default: parse_pattern_28;
        }
    }
    state parse_pattern_28 {
        packet.extract(hdr.patrn_28);
        transition select(hdr.ipv4.totalLen_msb){
            41: accept;
            default: parse_pattern_29;
        }
    }
    state parse_pattern_29 {
        packet.extract(hdr.patrn_29);
        transition select(hdr.ipv4.totalLen_msb){
            42: accept;
            default: parse_pattern_30;
        }
    }
    state parse_pattern_30 {
        packet.extract(hdr.patrn_30);
        transition select(hdr.ipv4.totalLen_msb){
            43: accept;
            default: parse_pattern_31;
        }
    }
    state parse_pattern_31 {
        packet.extract(hdr.patrn_31);
        transition select(hdr.ipv4.totalLen_msb){
            44: accept;
            default: parse_pattern_32;
        }
    }
    state parse_pattern_32 {
        packet.extract(hdr.patrn_32);
        transition select(hdr.ipv4.totalLen_msb){
            45: accept;
            default: parse_pattern_33;
        }
    }
    state parse_pattern_33 {
        packet.extract(hdr.patrn_33);
        transition select(hdr.ipv4.totalLen_msb){
            46: accept;
            default: parse_pattern_34;
        }
    }
    state parse_pattern_34 {
        packet.extract(hdr.patrn_34);
        transition select(hdr.ipv4.totalLen_msb){
            47: accept;
            default: parse_pattern_35;
        }
    }
    state parse_pattern_35 {
        packet.extract(hdr.patrn_35);
        transition select(hdr.ipv4.totalLen_msb){
            48: accept;
            default: parse_pattern_36;
        }
    }
    state parse_pattern_36 {
        packet.extract(hdr.patrn_36);
        transition select(hdr.ipv4.totalLen_msb){
            49: accept;
            default: parse_pattern_37;
        }
    }
    state parse_pattern_37 {
        packet.extract(hdr.patrn_37);
        transition select(hdr.ipv4.totalLen_msb){
            50: accept;
            default: parse_pattern_38;
        }
    }
    state parse_pattern_38 {
        packet.extract(hdr.patrn_38);
        transition select(hdr.ipv4.totalLen_msb){
            51: accept;
            default: parse_pattern_39;
        }
    }
    state parse_pattern_39 {
        packet.extract(hdr.patrn_39);
        transition select(hdr.ipv4.totalLen_msb){
            52: accept;
            default: parse_pattern_40;
        }
    }
    state parse_pattern_40 {
        packet.extract(hdr.patrn_40);
        transition select(hdr.ipv4.totalLen_msb){
            53: accept;
            default: parse_pattern_41;
        }
    }
    state parse_pattern_41 {
        packet.extract(hdr.patrn_41);
        transition select(hdr.ipv4.totalLen_msb){
            54: accept;
            default: parse_pattern_42;
        }
    }
    state parse_pattern_42 {
        packet.extract(hdr.patrn_42);
        transition select(hdr.ipv4.totalLen_msb){
            55: accept;
            default: parse_pattern_43;
        }
    }
    state parse_pattern_43 {
        packet.extract(hdr.patrn_43);
        transition select(hdr.ipv4.totalLen_msb){
            56: accept;
            default: parse_pattern_44;
        }
    }
    state parse_pattern_44 {
        packet.extract(hdr.patrn_44);
        transition select(hdr.ipv4.totalLen_msb){
            57: accept;
            default: parse_pattern_45;
        }
    }
    state parse_pattern_45 {
        packet.extract(hdr.patrn_45);
        transition select(hdr.ipv4.totalLen_msb){
            58: accept;
            default: parse_pattern_46;
        }
    }
    state parse_pattern_46 {
        packet.extract(hdr.patrn_46);
        transition select(hdr.ipv4.totalLen_msb){
            59: accept;
            default: parse_pattern_47;
        }
    }
    state parse_pattern_47 {
        packet.extract(hdr.patrn_47);
        transition select(hdr.ipv4.totalLen_msb){
            60: accept;
            default: parse_pattern_48;
        }
    }
    state parse_pattern_48 {
        packet.extract(hdr.patrn_48);
        transition select(hdr.ipv4.totalLen_msb){
            61: accept;
            default: parse_pattern_49;
        }
    }
    state parse_pattern_49 {
        packet.extract(hdr.patrn_49);
        transition select(hdr.ipv4.totalLen_msb){
            62: accept;
            default: parse_pattern_50;
        }
    }
    state parse_pattern_50 {
        packet.extract(hdr.patrn_50);
        transition select(hdr.ipv4.totalLen_msb){
            63: accept;
            default: parse_pattern_51;
        }
    }
    state parse_pattern_51 {
        packet.extract(hdr.patrn_51);
        transition select(hdr.ipv4.totalLen_msb){
            64: accept;
            default: parse_pattern_52;
        }
    }
    state parse_pattern_52 {
        packet.extract(hdr.patrn_52);
        transition select(hdr.ipv4.totalLen_msb){
            65: accept;
            default: parse_pattern_53;
        }
    }
    state parse_pattern_53 {
        packet.extract(hdr.patrn_53);
        transition select(hdr.ipv4.totalLen_msb){
            66: accept;
            default: parse_pattern_54;
        }
    }
    state parse_pattern_54 {
        packet.extract(hdr.patrn_54);
        transition select(hdr.ipv4.totalLen_msb){
            67: accept;
            default: parse_pattern_55;
        }
    }
    state parse_pattern_55 {
        packet.extract(hdr.patrn_55);
        transition accept;
    }


}

control EgressControl(
        inout egress_header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    // Counter<bit<32>, bit<8>>(256, CounterType_t.PACKETS_AND_BYTES) c_egress;
    // DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) c_iplenReduce;
    
    // #1 define a_iplenReduce action
    action a_iplenReduce_1B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 1;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_2B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 2;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_3B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 3;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_4B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 4;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_5B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 5;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_6B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 6;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_7B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 7;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_8B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 8;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_9B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 9;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_10B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 10;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_11B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 11;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_12B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 12;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_13B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 13;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_14B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 14;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_15B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 15;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_16B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 16;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_17B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 17;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_18B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 18;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_19B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 19;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_20B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 20;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_21B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 21;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_22B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 22;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_23B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 23;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_24B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 24;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_25B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 25;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_26B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 26;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_27B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 27;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_28B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 28;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_29B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 29;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_30B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 30;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_31B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 31;
        // c_iplenReduce.count();
    }

    action a_iplenReduce_32B(){
        hdr.ipv4_egress.totalLen = hdr.ipv4_egress.totalLen - 32;
        // c_iplenReduce.count();
    }


    // #2 define a_iplenReduce table

    table t_iplenReduce {
        key = {
        hdr.rclt.discardBytes : exact;
    }
        actions = {
            a_iplenReduce_1B;
            a_iplenReduce_2B;
            a_iplenReduce_3B;
            a_iplenReduce_4B;
            a_iplenReduce_5B;
            a_iplenReduce_6B;
            a_iplenReduce_7B;
            a_iplenReduce_8B;
            a_iplenReduce_9B;
            a_iplenReduce_10B;
            a_iplenReduce_11B;
            a_iplenReduce_12B;
            a_iplenReduce_13B;
            a_iplenReduce_14B;
            a_iplenReduce_15B;
            a_iplenReduce_16B;
            a_iplenReduce_17B;
            a_iplenReduce_18B;
            a_iplenReduce_19B;
            a_iplenReduce_20B;
            a_iplenReduce_21B;
            a_iplenReduce_22B;
            a_iplenReduce_23B;
            a_iplenReduce_24B;
            a_iplenReduce_25B;
            a_iplenReduce_26B;
            a_iplenReduce_27B;
            a_iplenReduce_28B;
            a_iplenReduce_29B;
            a_iplenReduce_30B;
            a_iplenReduce_31B;
            a_iplenReduce_32B;
        }
        size = 64;
        // counters = c_iplenReduce;
    }


    apply {
        if (hdr.rclt.isValid()){
            t_iplenReduce.apply();
        }
    
        // c_egress.count(0);
    }
}

control IngressControl(
        inout ingress_header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    Counter<bit<32>, bit<8>>(256, CounterType_t.PACKETS_AND_BYTES) c_bucket;        
    Counter<bit<32>, bit<8>>(1, CounterType_t.PACKETS_AND_BYTES) c_rclt;

    Register<bit<8>, bit<8>>(1) r_max_rclt;
    bit<8> max_rclt;
    
    // This registers and counters are for debug purpouses
    // Counter<bit<32>, bit<8>>(1, CounterType_t.PACKETS_AND_BYTES) c_save_state_and_recirculate;
    // Counter<bit<32>, bit<8>>(1, CounterType_t.PACKETS_AND_BYTES) c_retrive_state;    
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) c_DFA0;
    // DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) c_DFA1;
    // DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) c_iplenReduce;
    // DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) c_setup_mirror_rclt;

    // # 3: Debug registers for all the buckets
    Counter<bit<32>, bit<16>>(65536,                 CounterType_t.PACKETS_AND_BYTES) c_tot_cnt;
    Register<bucket_t,bit<8>>(1) r_b1;
    Register<bucket_t,bit<8>>(1) r_b2;
    Register<bucket_t,bit<8>>(1) r_b3;

    // Other debug registers
    Register<bit<16>,bit<8>>(1) r_iplen;
    Register<bit<32>,bit<8>>(1) r_pattern_0;
    Register<bit<16>,bit<8>>(2) r_index_0;
    Register<bit<16>,bit<8>>(1) r_index_1;
    Register<bit<32>,bit<8>>(2) r_value_debug;
    // Register<bit<32>,bit<8>>(1) r_value_1_0;
    Counter<bit<32>, bit<8>>(1, CounterType_t.PACKETS_AND_BYTES) c_random_debug;
    // Register<bit<8>,bit<8>>(1) r_discardByte;
    Register<bit<32>,bit<8>>(1) r_cur_val_combined_0;
    Register<bit<8>,bit<8>>(1) r_v0;
    Register<bit<8>,bit<8>>(1) r_v1;
    Register<bit<8>,bit<8>>(1) r_v2;
    Register<bit<8>,bit<8>>(1) r_v3;
    Register<bit<8>,bit<8>>(1) r_packet_id;

    // Register to save data
    Register<bit<32>,bit<16>>(65536) r_value_0;
    Register<bit<32>,bit<16>>(65536) r_value_1;
    Register<bit<16>,bit<16>>(65536) r_value_2;
    
    // Hash to generate index
    Hash<bit<16>>(HashAlgorithm_t.CRC32) Hash_0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) Hash_1;

    // Counter to store groupby result
    Counter<bit<32>, bit<16>>(65536, CounterType_t.PACKETS_AND_BYTES) c_grpby_0;

    // Actions Start
    action a_nop() {}

    action a_drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action a_arp(bit<48> ifaceMac){
        // Sending packet back to incoming port
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

        // Changing Ethernet headers
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = ifaceMac;

        // Changing ARP headers
        hdr.arp.op_code = 2; // Arp req = 1, ARP reply = 2
        hdr.arp.targetMac = hdr.arp.senderMac;
        hdr.arp.senderMac = ifaceMac;

        // Swaping sender and target IPv4
        // ip4_addr_t targetIPv4_temp = hdr.arp.targetIPv4;
        // arpTargetIPv4_temp set in parser = hdr.arp.targetIPv4 to avoid warning
        hdr.arp.targetIPv4 = hdr.arp.senderIPv4;
        hdr.arp.senderIPv4 = ig_md.arpTargetIPv4_temp;
    
        // Disabling l3 table. This need not to be done bcz arp packets doesn't have ipv4
        // l3_disabled = true;

        // Egress will remove this from all packets. So we need to add this
        hdr.bridged_meta.setValid();
        hdr.bridged_meta.pkt_type = PACKET_TYPE_NORMAL;
    }

    action a_setup_mirror_rclt(PortId_t egressPort, PortId_t iface_rclt) {
        // By checking this field we will clone packet in ingress deparser
        ig_dprsr_md.mirror_type = 1;
        // This field will be appended at the beggining of the mirrored packet
        // This is the argument is {} of the mirror.emit
        ig_md.pkt_type = PACKET_TYPE_MIRROR;
        // 1st argument of mirror.emit. This is matched by the inbuilt
        // mirror.cfg table as the key sid to choose egress port
        // This action will fill this. We will use this in mirror.cfg to match
        // and enque the mirrored packet to the proper destination port and
        // keep recirculating the original packet.
        ig_md.ing_mir_ses = (MirrorId_t)egressPort;
        // This is added in front of the orginal packet. The 1st field of this
        // shall atleast be of same width what is appended in front of the 
        // mirrored packet. The first field value may be used to differentiate
        // between mirrored and original packet in egress parser. Egress deparser
        // must emit selectively and must not emit this header.
        // When cloned in ingress deparser any change made in the original packet
        // is not carried forward. Opposit true for when mirror is made at the
        // egress deparser
        hdr.bridged_meta.setValid();
        hdr.bridged_meta.pkt_type = PACKET_TYPE_NORMAL;
        // Set the egress port of the original packet to recirculate port
        ig_tm_md.ucast_egress_port = iface_rclt;
        hdr.rclt.setValid();
        //hdr.rclt.ethType = hdr.ethernet.ethType;
        //hdr.ethernet.ethType = ETH_TYPE_RCLT;
        hdr.ipv4.id = IP_ID_RCLT;
        hdr.rclt.discardBytes = 0;
        hdr.rclt.rclt_count = 0;
        ig_md.mark_to_rec = 0;
        // Note: None of the above change will go to the mirrored packet which
        // will reach to the destination

        // c_setup_mirror_rclt.count(); // Debug

        // #2: Clearing the buckets by making them 0

        // #3: Saving the extracted values for direct match in rclt header

    }      

    action a_increase_counter(bit<8> packet_id){
        c_bucket.count(packet_id);
        // Once a match found in pattern2_bucket table we will drop the packet
        hdr.rclt.rclt_count = max_rclt;
        ig_md.packet_id = packet_id;
        // TODO: Hardcoded as of now, need to be GENERATED
        //ig_md.index_0 = Hash_0.get({hdr.rclt.value_0_0, hdr.rclt.value_0_1, 
        //                            hdr.rclt.value_0_2});
    }
    
    action a_send_to_dummy_port(){
        ig_tm_md.ucast_egress_port = IFACE_DUMMY;
        ig_dprsr_md.drop_ctl = 1;
    }

    table t_arp {
        key = {
            hdr.arp.targetIPv4 : exact;
        }

        actions = {
            a_arp;
            a_nop;
        }

        const default_action = a_nop();
        size =16;
    }

    table t_setup_mirror_rclt {
        key = {
            hdr.ipv4.dstAddr : exact;
        }

        actions = {
            a_setup_mirror_rclt;
            a_nop;
        }
        
        // const default_action = a_nop();  // common act, can't use with DirectCounter
        size = 32;
        
        // Debug
        // counters = c_setup_mirror_rclt;
    }

    action a_vfind(){
        ig_md.op_failed = 1;
    }

    action a_DFA0_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_0.setInvalid();
        hdr.patrn_1.setInvalid();
        hdr.patrn_2.setInvalid();
        hdr.patrn_3.setInvalid();
        hdr.patrn_4.setInvalid();
        hdr.patrn_5.setInvalid();
        hdr.patrn_6.setInvalid();
        hdr.patrn_7.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA1_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_8.setInvalid();
        hdr.patrn_9.setInvalid();
        hdr.patrn_10.setInvalid();
        hdr.patrn_11.setInvalid();
        hdr.patrn_12.setInvalid();
        hdr.patrn_13.setInvalid();
        hdr.patrn_14.setInvalid();
        hdr.patrn_15.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA2_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_16.setInvalid();
        hdr.patrn_17.setInvalid();
        hdr.patrn_18.setInvalid();
        hdr.patrn_19.setInvalid();
        hdr.patrn_20.setInvalid();
        hdr.patrn_21.setInvalid();
        hdr.patrn_22.setInvalid();
        hdr.patrn_23.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA3_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_24.setInvalid();
        hdr.patrn_25.setInvalid();
        hdr.patrn_26.setInvalid();
        hdr.patrn_27.setInvalid();
        hdr.patrn_28.setInvalid();
        hdr.patrn_29.setInvalid();
        hdr.patrn_30.setInvalid();
        hdr.patrn_31.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA4_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_32.setInvalid();
        hdr.patrn_33.setInvalid();
        hdr.patrn_34.setInvalid();
        hdr.patrn_35.setInvalid();
        hdr.patrn_36.setInvalid();
        hdr.patrn_37.setInvalid();
        hdr.patrn_38.setInvalid();
        hdr.patrn_39.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA5_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_40.setInvalid();
        hdr.patrn_41.setInvalid();
        hdr.patrn_42.setInvalid();
        hdr.patrn_43.setInvalid();
        hdr.patrn_44.setInvalid();
        hdr.patrn_45.setInvalid();
        hdr.patrn_46.setInvalid();
        hdr.patrn_47.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA6_cut_32(state_t _state) {
        hdr.rclt.state = _state;
        hdr.ipv4.totalLen_msb = hdr.ipv4.totalLen_msb - 8;
        hdr.patrn_48.setInvalid();
        hdr.patrn_49.setInvalid();
        hdr.patrn_50.setInvalid();
        hdr.patrn_51.setInvalid();
        hdr.patrn_52.setInvalid();
        hdr.patrn_53.setInvalid();
        hdr.patrn_54.setInvalid();
        hdr.patrn_55.setInvalid();
        //  c_DFA0.count();
    }
    action a_DFA0_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA0.count();
    }
    
    action a_DFA0_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA0.count();
    }
    
    action a_DFA0_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA0.count();
    }
    
    action a_DFA1_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA1.count();
    }
    
    action a_DFA1_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA1.count();
    }
    
    action a_DFA1_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA1.count();
    }
    
    action a_DFA2_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA2.count();
    }
    
    action a_DFA2_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA2.count();
    }
    
    action a_DFA2_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA2.count();
    }
    
    action a_DFA3_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA3.count();
    }
    
    action a_DFA3_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA3.count();
    }
    
    action a_DFA3_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA3.count();
    }
    
    action a_DFA4_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA4.count();
    }
    
    action a_DFA4_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA4.count();
    }
    
    action a_DFA4_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA4.count();
    }
    
    action a_DFA5_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA5.count();
    }
    
    action a_DFA5_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA5.count();
    }
    
    action a_DFA5_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA5.count();
    }
    
    action a_DFA6_cut_set_b1(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b1 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA6.count();
    }
    
    action a_DFA6_cut_set_b2(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b2 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA6.count();
    }
    
    action a_DFA6_cut_set_b3(state_t _state, bucket_t pattern_code, bit<8> cutBytes){
        hdr.rclt.state = _state;
        hdr.rclt.b3 = pattern_code;
        hdr.rclt.cur_value_code = pattern_code;
        hdr.rclt.discardBytes = cutBytes;
        ig_md.mark_to_rec = 1;
        // c_DFA6.count();
    }
    
    action a_save_state_and_recirculate(PortId_t iface_rclt){
        ig_tm_md.ucast_egress_port = iface_rclt;
        // hdr.ethernet.ethType = ETH_TYPE_RCLT; // Already this is the value
        hdr.ipv4.id = IP_ID_RCLT; // Already this is the value
        // hdr.rclt.state = ig_md.state;
        // hdr.rclt.b1 = ig_md.b1;
        // hdr.rclt.b2 = ig_md.b2;
        // hdr.rclt.b3 = ig_md.b3;
        hdr.rclt.rclt_count = hdr.rclt.rclt_count + 1;
    }
    action a_retrive_state(){
        // Egress parser and deparser always remove this field. So need to
        // enable this
        hdr.bridged_meta.setValid();
        hdr.bridged_meta.pkt_type = PACKET_ETH_TYPE_RCLT;   // Any dummy value is ok
        // hdr.rclt.state = hdr.rclt.state;
        // hdr.rclt.b1 = hdr.rclt.b1;
        // hdr.rclt.b2 = hdr.rclt.b2;
        // hdr.rclt.b3 = hdr.rclt.b3;
        // This parameter should be reset after each recirculation;
        hdr.rclt.discardBytes = 0;
        ig_md.mark_to_rec = 0;
    }
    
    table t_save_state_and_recirculate {
        key = {
            ig_intr_md.ingress_mac_tstamp : ternary;
        }
        actions = {
             a_save_state_and_recirculate;
        }
        size = 16;
    }
    
    table t_DFA_match_0 {
        key = {
            hdr.patrn_0.pattern : ternary;
            hdr.patrn_1.pattern : ternary;
            hdr.patrn_2.pattern : ternary;
            hdr.patrn_3.pattern : ternary;
            hdr.patrn_4.pattern : ternary;
            hdr.patrn_5.pattern : ternary;
            hdr.patrn_6.pattern : ternary;
            hdr.patrn_7.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA0_cut_32;
            a_DFA0_cut_set_b1;
            a_DFA0_cut_set_b2;
            a_DFA0_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_DFA_match_1 {
        key = {
            hdr.patrn_8.pattern : ternary;
            hdr.patrn_9.pattern : ternary;
            hdr.patrn_10.pattern : ternary;
            hdr.patrn_11.pattern : ternary;
            hdr.patrn_12.pattern : ternary;
            hdr.patrn_13.pattern : ternary;
            hdr.patrn_14.pattern : ternary;
            hdr.patrn_15.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA1_cut_32;
            a_DFA1_cut_set_b1;
            a_DFA1_cut_set_b2;
            a_DFA1_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_DFA_match_2 {
        key = {
            hdr.patrn_16.pattern : ternary;
            hdr.patrn_17.pattern : ternary;
            hdr.patrn_18.pattern : ternary;
            hdr.patrn_19.pattern : ternary;
            hdr.patrn_20.pattern : ternary;
            hdr.patrn_21.pattern : ternary;
            hdr.patrn_22.pattern : ternary;
            hdr.patrn_23.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA2_cut_32;
            a_DFA2_cut_set_b1;
            a_DFA2_cut_set_b2;
            a_DFA2_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_DFA_match_3 {
        key = {
            hdr.patrn_24.pattern : ternary;
            hdr.patrn_25.pattern : ternary;
            hdr.patrn_26.pattern : ternary;
            hdr.patrn_27.pattern : ternary;
            hdr.patrn_28.pattern : ternary;
            hdr.patrn_29.pattern : ternary;
            hdr.patrn_30.pattern : ternary;
            hdr.patrn_31.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA3_cut_32;
            a_DFA3_cut_set_b1;
            a_DFA3_cut_set_b2;
            a_DFA3_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_DFA_match_4 {
        key = {
            hdr.patrn_32.pattern : ternary;
            hdr.patrn_33.pattern : ternary;
            hdr.patrn_34.pattern : ternary;
            hdr.patrn_35.pattern : ternary;
            hdr.patrn_36.pattern : ternary;
            hdr.patrn_37.pattern : ternary;
            hdr.patrn_38.pattern : ternary;
            hdr.patrn_39.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA4_cut_32;
            a_DFA4_cut_set_b1;
            a_DFA4_cut_set_b2;
            a_DFA4_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_DFA_match_5 {
        key = {
            hdr.patrn_40.pattern : ternary;
            hdr.patrn_41.pattern : ternary;
            hdr.patrn_42.pattern : ternary;
            hdr.patrn_43.pattern : ternary;
            hdr.patrn_44.pattern : ternary;
            hdr.patrn_45.pattern : ternary;
            hdr.patrn_46.pattern : ternary;
            hdr.patrn_47.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA5_cut_32;
            a_DFA5_cut_set_b1;
            a_DFA5_cut_set_b2;
            a_DFA5_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_DFA_match_6 {
        key = {
            hdr.patrn_48.pattern : ternary;
            hdr.patrn_49.pattern : ternary;
            hdr.patrn_50.pattern : ternary;
            hdr.patrn_51.pattern : ternary;
            hdr.patrn_52.pattern : ternary;
            hdr.patrn_53.pattern : ternary;
            hdr.patrn_54.pattern : ternary;
            hdr.patrn_55.pattern : ternary;
            hdr.rclt.state: ternary;
        }
        actions = {
            a_DFA6_cut_32;
            a_DFA6_cut_set_b1;
            a_DFA6_cut_set_b2;
            a_DFA6_cut_set_b3;
        }
        size = 1024;
        //counters = c_DFA0;
    }
    
    table t_pattern2rule {
        key = {
            hdr.rclt.b1: exact;
            hdr.rclt.b2: exact;
            hdr.rclt.b3: exact;
        }
        actions = {
            a_increase_counter;
        }
        size = 1024;
    }
    
    
    

    apply {
        if (hdr.arp.isValid()){
            t_arp.apply();
        }
        else if (hdr.ipv4.protocol != IP_PROTOCOLS_TCP){
            a_drop();
        }
        else if (hdr.ipv4.isValid()){
            // Debug
            c_rclt.count(0);
            
            if (hdr.rclt.isValid()){
                // This packet is continuing recirculation
                // hdr.rclt is already valid. Also we don't need to mirror this
                // NOTE: We need to setValid bridged metadata
                a_retrive_state();
            }
            else {
                // This is the 1st encounter of a packet. Set hdr.rclt valid. 
                // set up bridged metadata. and set deparser metadata for mirror
                t_setup_mirror_rclt.apply();
            }
            
            if (hdr.v0.isValid()){
            // Store value from key value pair in rclt header
                {
                    hdr.rclt.discardBytes = 1;
                }
            
                // Concatenate values for easy saving
                // t_concatvalue.apply();
                // r_cur_val_combined_0.write(0, ig_md.cur_val_combined_0);
            
                // Match current patern type, save// reset cur_value_code i.e. pattern code for next recirculation
                hdr.rclt.cur_value_code = 0;
            }
            else{
                // Bolt pattern matching. Can be done outside else too
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_0.apply();
                }
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_1.apply();
                }
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_2.apply();
                }
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_3.apply();
                }
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_4.apply();
                }
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_5.apply();
                }
                if(ig_md.mark_to_rec == 0){
                    t_DFA_match_6.apply();
                }
            }
            
            // Debug bucket Registrs;
            r_b1.write(0, hdr.rclt.b1);
            r_b2.write(0, hdr.rclt.b2);
            r_b3.write(0, hdr.rclt.b3);
            r_iplen.write(0, (bit<16>)hdr.ipv4.totalLen_msb);
            
            
            // Reading value from Control Plane
            // max_rclt = r_max_rclt.read(0);  // Compilation error
            max_rclt = 10;
            if (hdr.rclt.cur_value_code == 0){
                t_pattern2rule.apply();
            }
                    
            if (ig_md.packet_id == 1){
                c_tot_cnt.count(0);
            }

            // Reading value from Control Plane
            max_rclt = r_max_rclt.read(0);
            if (hdr.rclt.rclt_count == max_rclt){
                a_send_to_dummy_port();
            }
            else{
                t_save_state_and_recirculate.apply();
            }
        }
    }
}
        
Pipeline(IngressParser(),
         IngressControl(),
         IngressDeparser(),
         EgressParser(),
         EgressControl(),
         EgressDeparser()) pipe;

Switch(pipe) main;
