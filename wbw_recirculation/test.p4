
// P4 code for IRs/query5.json

// cmake $SDE/p4studio/ -DCMAKE_INSTALL_PREFIX=$SDE/install \ 
// -DCMAKE_MODULE_PATH=$SDE/cmake -DP4_NAME=bolt_tofino // -DP4_PATH=/home/abhik/BOLT-v2_modified/bolt_tofino.p4

#include <core.p4>
#include <tna.p4>

#define ETH_TYPE_IPV4   0x800
#define ETH_TYPE_ARP    0x0806

#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17

#define VARBIT_LEN      64
#define LEN_WIDTH       8   // Width of gRPC length for each attribute
#define LEN_EOP         255 // End of gRPC data
#define KEY_LEN         256
#define VAL_LEN         256

#define CHAR_COMMA      0x2c

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   ethType;
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
    bit<16>   totalLen;
    // bit<2>    totalLen_lsb;
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


header b32_t {
    bit<32> c;
}

header b16_t {
    bit<16> c;
}

header b8_t {
    bit<8> c;
}

header fixed_parse_t {
    bit<64> c64;
    bit<32> c32;
    bit<8> c8;
}

struct egress_header_t {
    // Empty
}

struct egress_metadata_t {
    // Empty egress metadata. No egress processing as of now
}



struct ingress_metadata_t {
    bit<32> arpTargetIPv4_temp;
    bit<LEN_WIDTH> index;
    bit<1> id;
    bit<1> fixed_parse_found;
    bit<1> filter0_found;
    bit<1> filter1_found;
    bit<32> filterKey_0_0;
    bit<32> filterKey_0_1;
    bit<32> filterKey_0_2;
    bit<32> filterKey_0_3;
    bit<32> filterKey_0_4;
    bit<32> filterKey_0_5;
    bit<32> filterKey_0_6;
    bit<32> filterKey_0_l32;
    bit<16> filterKey_0_l16;
    bit<8> filterKey_0_l8;
    bit<32> filterVal_0_0;
    bit<32> filterVal_0_1;
    bit<32> filterVal_0_2;
    bit<32> filterVal_0_3;
    bit<32> filterVal_0_4;
    bit<32> filterVal_0_5;
    bit<32> filterVal_0_6;
    bit<32> filterVal_0_l32;
    bit<16> filterVal_0_l16;
    bit<8> filterVal_0_l8;
    bit<32> filterKey_1_0;
    bit<32> filterKey_1_1;
    bit<32> filterKey_1_2;
    bit<32> filterKey_1_3;
    bit<32> filterKey_1_4;
    bit<32> filterKey_1_5;
    bit<32> filterKey_1_6;
    bit<32> filterKey_1_l32;
    bit<16> filterKey_1_l16;
    bit<8> filterKey_1_l8;
    bit<32> filterVal_1_0;
    bit<32> filterVal_1_1;
    bit<32> filterVal_1_2;
    bit<32> filterVal_1_3;
    bit<32> filterVal_1_4;
    bit<32> filterVal_1_5;
    bit<32> filterVal_1_6;
    bit<32> filterVal_1_l32;
    bit<16> filterVal_1_l16;
    bit<8> filterVal_1_l8;
}

struct ingress_header_t {
    ethernet_t              ethernet;
    arp_t                   arp;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    tcp_opt_t               tcp_op;

    fixed_parse_t           fixed_parse;
     b32_t               key_0_0;
     b32_t               key_0_1;
     b32_t               key_0_2;
     b32_t               key_0_3;
     b32_t               key_0_4;
     b32_t               key_0_5;
     b32_t               key_0_6;

     b32_t               key_1_0;
     b32_t               key_1_1;
     b32_t               key_1_2;
     b32_t               key_1_3;
     b32_t               key_1_4;
     b32_t               key_1_5;
     b32_t               key_1_6;

     b32_t               val_0_0;
     b32_t               val_0_1;
     b32_t               val_0_2;
     b32_t               val_0_3;
     b32_t               val_0_4;
     b32_t               val_0_5;
     b32_t               val_0_6;

     b32_t               val_1_0;
     b32_t               val_1_1;
     b32_t               val_1_2;
     b32_t               val_1_3;
     b32_t               val_1_4;
     b32_t               val_1_5;
     b32_t               val_1_6;

     b32_t               key_0_l32;
      b16_t               key_0_l16;
      b8_t                key_0_l8;

     b32_t               key_1_l32;
      b16_t               key_1_l16;
      b8_t                key_1_l8;

     b32_t               val_0_l32;
      b16_t               val_0_l16;
      b8_t                val_0_l8;

     b32_t               val_1_l32;
      b16_t               val_1_l16;
      b8_t                val_1_l8;

}
control IngressDeparser(
        packet_out packet,
        inout ingress_header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        packet.emit(hdr);
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
        packet.emit(hdr);
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
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        ig_md.filter0_found=0;
        ig_md.filter1_found=0;
        ig_md.fixed_parse_found=0;
        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_op);
        ig_md.id = 0;
        
        // transition parse_fixed;
        transition parse_key_0_0;
    }
    state parse_fixed {
        packet.extract(hdr.fixed_parse);
        transition parse_key_0_0;
    }

    state parse_key_0_0 {
        
        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_1;
        }
    }
    

    state parse_key_0_1 {
        packet.extract(hdr.key_0_0);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_2;
        }
    }
    

    state parse_key_0_2 {
        packet.extract(hdr.key_0_1);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_3;
        }
    }
    

    state parse_key_0_3 {
        packet.extract(hdr.key_0_2);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_4;
        }
    }
    

    state parse_key_0_4 {
        packet.extract(hdr.key_0_3);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_5;
        }
    }
    

    state parse_key_0_5 {
        packet.extract(hdr.key_0_4);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_6;
        }
    }
    

    state parse_key_0_6 {
        packet.extract(hdr.key_0_5);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: parse_key_0_7;
        }
    }
    

    state parse_key_0_7 {
        packet.extract(hdr.key_0_6);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_0_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_0_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_0_l24;
            0x0000003a &&& 0x000000ff:  parse_key_0_l32;
            default: accept;
        }
    }
    

    state parse_key_0_l8 {
        packet.extract(hdr.key_0_l8);
        transition parse_val_0_0;
    }

    state parse_key_0_l16 {
        packet.extract(hdr.key_0_l16);
        transition parse_val_0_0;
    }

    state parse_key_0_l24 {
        packet.extract(hdr.key_0_l8);
        packet.extract(hdr.key_0_l16);
        transition parse_val_0_0;
    }

    state parse_key_0_l32 {
        packet.extract(hdr.key_0_l32);
        transition parse_val_0_0;
    }
 


    state parse_val_0_0 {
        
        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_1;
        }
    }

 

    state parse_val_0_1 {
        packet.extract(hdr.val_0_0);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_2;
        }
    }

 

    state parse_val_0_2 {
        packet.extract(hdr.val_0_1);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_3;
        }
    }

 

    state parse_val_0_3 {
        packet.extract(hdr.val_0_2);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_4;
        }
    }

 

    state parse_val_0_4 {
        packet.extract(hdr.val_0_3);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_5;
        }
    }

 

    state parse_val_0_5 {
        packet.extract(hdr.val_0_4);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_6;
        }
    }

 

    state parse_val_0_6 {
        packet.extract(hdr.val_0_5);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: parse_val_0_7;
        }
    }

 

    state parse_val_0_7 {
        packet.extract(hdr.val_0_6);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_0_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_0_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_0_l24;
            0x0000002c &&& 0x000000ff:  parse_val_0_l32;
            default: accept;
        }
    }

 

    state parse_val_0_l8 {
        packet.extract(hdr.val_0_l8);
        transition parse_key_1_0;
    }

    state parse_val_0_l16 {
        packet.extract(hdr.val_0_l16);
        transition parse_key_1_0;
    }

    state parse_val_0_l24 {
        packet.extract(hdr.val_0_l8);
        packet.extract(hdr.val_0_l16);
        transition parse_key_1_0;
    }

    state parse_val_0_l32 {
        packet.extract(hdr.val_0_l32);
        transition parse_key_1_0;
    }


    state parse_key_1_0 {
        
        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_1;
        }
    }
    

    state parse_key_1_1 {
        packet.extract(hdr.key_1_0);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_2;
        }
    }
    

    state parse_key_1_2 {
        packet.extract(hdr.key_1_1);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_3;
        }
    }
    

    state parse_key_1_3 {
        packet.extract(hdr.key_1_2);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_4;
        }
    }
    

    state parse_key_1_4 {
        packet.extract(hdr.key_1_3);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_5;
        }
    }
    

    state parse_key_1_5 {
        packet.extract(hdr.key_1_4);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_6;
        }
    }
    

    state parse_key_1_6 {
        packet.extract(hdr.key_1_5);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: parse_key_1_7;
        }
    }
    

    state parse_key_1_7 {
        packet.extract(hdr.key_1_6);

        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_1_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_1_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_1_l24;
            0x0000003a &&& 0x000000ff:  parse_key_1_l32;
            default: accept;
        }
    }
    

    state parse_key_1_l8 {
        packet.extract(hdr.key_1_l8);
        transition parse_val_1_0;
    }

    state parse_key_1_l16 {
        packet.extract(hdr.key_1_l16);
        transition parse_val_1_0;
    }

    state parse_key_1_l24 {
        packet.extract(hdr.key_1_l8);
        packet.extract(hdr.key_1_l16);
        transition parse_val_1_0;
    }

    state parse_key_1_l32 {
        packet.extract(hdr.key_1_l32);
        transition parse_val_1_0;
    }
 


    state parse_val_1_0 {
        
        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_1;
        }
    }

 

    state parse_val_1_1 {
        packet.extract(hdr.val_1_0);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_2;
        }
    }

 

    state parse_val_1_2 {
        packet.extract(hdr.val_1_1);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_3;
        }
    }

 

    state parse_val_1_3 {
        packet.extract(hdr.val_1_2);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_4;
        }
    }

 

    state parse_val_1_4 {
        packet.extract(hdr.val_1_3);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_5;
        }
    }

 

    state parse_val_1_5 {
        packet.extract(hdr.val_1_4);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_6;
        }
    }

 

    state parse_val_1_6 {
        packet.extract(hdr.val_1_5);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: parse_val_1_7;
        }
    }

 

    state parse_val_1_7 {
        packet.extract(hdr.val_1_6);

        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_1_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_1_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_1_l24;
            0x0000002c &&& 0x000000ff:  parse_val_1_l32;
            default: accept;
        }
    }

 

    state parse_val_1_l8 {
        packet.extract(hdr.val_1_l8);
        transition parse_key_2_0;
    }

    state parse_val_1_l16 {
        packet.extract(hdr.val_1_l16);
        transition parse_key_2_0;
    }

    state parse_val_1_l24 {
        packet.extract(hdr.val_1_l8);
        packet.extract(hdr.val_1_l16);
        transition parse_key_2_0;
    }

    state parse_val_1_l32 {
        packet.extract(hdr.val_1_l32);
        transition parse_key_2_0;
    }



    state parse_key_2_0 {
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
    apply {
        // Do nothing
    }
}

control IngressControl(
        inout ingress_header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) Hash_0;
    bit<16> index;

    Counter<bit<32>, bit<16>>(65536, CounterType_t.PACKETS_AND_BYTES)c_tot_cnt;
    Register<bit<32>,bit<8>>(1) check0;  // debug
    Register<bit<32>,bit<8>>(1) check2;  // debug
    Register<bit<32>,bit<8>>(1) check01;  // debug
    Register<bit<16>,bit<8>>(1) check02;  // debug
    Register<bit<8>,bit<8>>(1) check03;  // debug
    Register<bit<32>,bit<8>>(1) check1;  // debug


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
    }

    table t_arp {
        key = {
            hdr.arp.targetIPv4 : exact;
        }

        actions = {
            a_arp;
        }

        size =16;
    }

    action a_drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action a_forward(PortId_t dstPort){
        ig_tm_md.ucast_egress_port = dstPort;
    }

    table t_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }

        actions = {
            a_forward;
            a_drop;
        }

        const default_action = a_drop();
        size = 4;
    }
    action a_fixed_parse () {
        ig_md.fixed_parse_found=1;
    }
    table t_fixed_parse {
        key = {
            hdr.fixed_parse.c64: exact;
            hdr.fixed_parse.c32: exact;
            hdr.fixed_parse.c8: exact;
        }
        actions = {
            a_fixed_parse;
        }
        size = 256;
    }
    action a_filter_0_0(){
        ig_md.filter0_found = 1;
        ig_md.filterKey_0_0 = hdr.key_0_0.c;
        ig_md.filterKey_0_1 = hdr.key_0_1.c;
        ig_md.filterKey_0_2 = hdr.key_0_2.c;
        ig_md.filterKey_0_3 = hdr.key_0_3.c;
        ig_md.filterKey_0_4 = hdr.key_0_4.c;
        ig_md.filterKey_0_5 = hdr.key_0_5.c;
        ig_md.filterKey_0_6 = hdr.key_0_6.c;
        ig_md.filterKey_0_l32 = hdr.key_0_l32.c;
        ig_md.filterKey_0_l16 = hdr.key_0_l16.c;
        ig_md.filterKey_0_l8 = hdr.key_0_l8.c;
        ig_md.filterVal_0_0 = hdr.val_0_0.c;
        ig_md.filterVal_0_1 = hdr.val_0_1.c;
        ig_md.filterVal_0_2 = hdr.val_0_2.c;
        ig_md.filterVal_0_3 = hdr.val_0_3.c;
        ig_md.filterVal_0_4 = hdr.val_0_4.c;
        ig_md.filterVal_0_5 = hdr.val_0_5.c;
        ig_md.filterVal_0_6 = hdr.val_0_6.c;
        ig_md.filterVal_0_l32 = hdr.val_0_l32.c;
        ig_md.filterVal_0_l16 = hdr.val_0_l16.c;
        ig_md.filterVal_0_l8 = hdr.val_0_l8.c;
    }
   table t_filter_0_0{
        key = {
            hdr.key_0_0.c: exact;
            hdr.key_0_1.c: exact;
            hdr.key_0_2.c: exact;
            hdr.key_0_3.c: exact;
            hdr.key_0_4.c: exact;
            hdr.key_0_5.c: exact;
            hdr.key_0_6.c: exact;
            hdr.key_0_l32.c: exact;
            hdr.key_0_l16.c: exact;
            hdr.key_0_l8.c: exact;
            hdr.val_0_0.c: exact;
            hdr.val_0_1.c: exact;
            hdr.val_0_2.c: exact;
            hdr.val_0_3.c: exact;
            hdr.val_0_4.c: exact;
            hdr.val_0_5.c: exact;
            hdr.val_0_6.c: exact;
            hdr.val_0_l32.c: exact;
            hdr.val_0_l16.c: exact;
            hdr.val_0_l8.c: exact;
        }
        actions={
            a_filter_0_0;
        }
        size = 512;
    }
    action a_filter_0_1(){
        ig_md.filter0_found = 1;
        ig_md.filterKey_0_0 = hdr.key_1_0.c;
        ig_md.filterKey_0_1 = hdr.key_1_1.c;
        ig_md.filterKey_0_2 = hdr.key_1_2.c;
        ig_md.filterKey_0_3 = hdr.key_1_3.c;
        ig_md.filterKey_0_4 = hdr.key_1_4.c;
        ig_md.filterKey_0_5 = hdr.key_1_5.c;
        ig_md.filterKey_0_6 = hdr.key_1_6.c;
        ig_md.filterKey_0_l32 = hdr.key_1_l32.c;
        ig_md.filterKey_0_l16 = hdr.key_1_l16.c;
        ig_md.filterKey_0_l8 = hdr.key_1_l8.c;
        ig_md.filterVal_0_0 = hdr.val_1_0.c;
        ig_md.filterVal_0_1 = hdr.val_1_1.c;
        ig_md.filterVal_0_2 = hdr.val_1_2.c;
        ig_md.filterVal_0_3 = hdr.val_1_3.c;
        ig_md.filterVal_0_4 = hdr.val_1_4.c;
        ig_md.filterVal_0_5 = hdr.val_1_5.c;
        ig_md.filterVal_0_6 = hdr.val_1_6.c;
        ig_md.filterVal_0_l32 = hdr.val_1_l32.c;
        ig_md.filterVal_0_l16 = hdr.val_1_l16.c;
        ig_md.filterVal_0_l8 = hdr.val_1_l8.c;
    }
   table t_filter_0_1{
        key = {
            hdr.key_1_0.c: exact;
            hdr.key_1_1.c: exact;
            hdr.key_1_2.c: exact;
            hdr.key_1_3.c: exact;
            hdr.key_1_4.c: exact;
            hdr.key_1_5.c: exact;
            hdr.key_1_6.c: exact;
            hdr.key_1_l32.c: exact;
            hdr.key_1_l16.c: exact;
            hdr.key_1_l8.c: exact;
            hdr.val_1_0.c: exact;
            hdr.val_1_1.c: exact;
            hdr.val_1_2.c: exact;
            hdr.val_1_3.c: exact;
            hdr.val_1_4.c: exact;
            hdr.val_1_5.c: exact;
            hdr.val_1_6.c: exact;
            hdr.val_1_l32.c: exact;
            hdr.val_1_l16.c: exact;
            hdr.val_1_l8.c: exact;
        }
        actions={
            a_filter_0_1;
        }
        size = 512;
    }
    action a_filter_1_0(){
        ig_md.filter1_found = 1;
        ig_md.filterKey_1_0 = hdr.key_0_0.c;
        ig_md.filterKey_1_1 = hdr.key_0_1.c;
        ig_md.filterKey_1_2 = hdr.key_0_2.c;
        ig_md.filterKey_1_3 = hdr.key_0_3.c;
        ig_md.filterKey_1_4 = hdr.key_0_4.c;
        ig_md.filterKey_1_5 = hdr.key_0_5.c;
        ig_md.filterKey_1_6 = hdr.key_0_6.c;
        ig_md.filterKey_1_l32 = hdr.key_0_l32.c;
        ig_md.filterKey_1_l16 = hdr.key_0_l16.c;
        ig_md.filterKey_1_l8 = hdr.key_0_l8.c;
        ig_md.filterVal_1_0 = hdr.val_0_0.c;
        ig_md.filterVal_1_1 = hdr.val_0_1.c;
        ig_md.filterVal_1_2 = hdr.val_0_2.c;
        ig_md.filterVal_1_3 = hdr.val_0_3.c;
        ig_md.filterVal_1_4 = hdr.val_0_4.c;
        ig_md.filterVal_1_5 = hdr.val_0_5.c;
        ig_md.filterVal_1_6 = hdr.val_0_6.c;
        ig_md.filterVal_1_l32 = hdr.val_0_l32.c;
        ig_md.filterVal_1_l16 = hdr.val_0_l16.c;
        ig_md.filterVal_1_l8 = hdr.val_0_l8.c;
    }
   table t_filter_1_0{
        key = {
            hdr.key_0_0.c: exact;
            hdr.key_0_1.c: exact;
            hdr.key_0_2.c: exact;
            hdr.key_0_3.c: exact;
            hdr.key_0_4.c: exact;
            hdr.key_0_5.c: exact;
            hdr.key_0_6.c: exact;
            hdr.key_0_l32.c: exact;
            hdr.key_0_l16.c: exact;
            hdr.key_0_l8.c: exact;
            hdr.val_0_0.c: exact;
            hdr.val_0_1.c: exact;
            hdr.val_0_2.c: exact;
            hdr.val_0_3.c: exact;
            hdr.val_0_4.c: exact;
            hdr.val_0_5.c: exact;
            hdr.val_0_6.c: exact;
            hdr.val_0_l32.c: exact;
            hdr.val_0_l16.c: exact;
            hdr.val_0_l8.c: exact;
        }
        actions={
            a_filter_1_0;
        }
        size = 512;
    }
    action a_filter_1_1(){
        ig_md.filter1_found = 1;
        ig_md.filterKey_1_0 = hdr.key_1_0.c;
        ig_md.filterKey_1_1 = hdr.key_1_1.c;
        ig_md.filterKey_1_2 = hdr.key_1_2.c;
        ig_md.filterKey_1_3 = hdr.key_1_3.c;
        ig_md.filterKey_1_4 = hdr.key_1_4.c;
        ig_md.filterKey_1_5 = hdr.key_1_5.c;
        ig_md.filterKey_1_6 = hdr.key_1_6.c;
        ig_md.filterKey_1_l32 = hdr.key_1_l32.c;
        ig_md.filterKey_1_l16 = hdr.key_1_l16.c;
        ig_md.filterKey_1_l8 = hdr.key_1_l8.c;
        ig_md.filterVal_1_0 = hdr.val_1_0.c;
        ig_md.filterVal_1_1 = hdr.val_1_1.c;
        ig_md.filterVal_1_2 = hdr.val_1_2.c;
        ig_md.filterVal_1_3 = hdr.val_1_3.c;
        ig_md.filterVal_1_4 = hdr.val_1_4.c;
        ig_md.filterVal_1_5 = hdr.val_1_5.c;
        ig_md.filterVal_1_6 = hdr.val_1_6.c;
        ig_md.filterVal_1_l32 = hdr.val_1_l32.c;
        ig_md.filterVal_1_l16 = hdr.val_1_l16.c;
        ig_md.filterVal_1_l8 = hdr.val_1_l8.c;
    }
   table t_filter_1_1{
        key = {
            hdr.key_1_0.c: exact;
            hdr.key_1_1.c: exact;
            hdr.key_1_2.c: exact;
            hdr.key_1_3.c: exact;
            hdr.key_1_4.c: exact;
            hdr.key_1_5.c: exact;
            hdr.key_1_6.c: exact;
            hdr.key_1_l32.c: exact;
            hdr.key_1_l16.c: exact;
            hdr.key_1_l8.c: exact;
            hdr.val_1_0.c: exact;
            hdr.val_1_1.c: exact;
            hdr.val_1_2.c: exact;
            hdr.val_1_3.c: exact;
            hdr.val_1_4.c: exact;
            hdr.val_1_5.c: exact;
            hdr.val_1_6.c: exact;
            hdr.val_1_l32.c: exact;
            hdr.val_1_l16.c: exact;
            hdr.val_1_l8.c: exact;
        }
        actions={
            a_filter_1_1;
        }
        size = 512;
    }

    apply {
        if (hdr.arp.isValid()){
            t_arp.apply();
        }


        if(!hdr.key_0_l32.isValid()){
            hdr.key_0_l32.c=0;
        }

        if(!hdr.key_0_l16.isValid()){
            hdr.key_0_l16.c=0;
        }

        if(!hdr.key_0_l8.isValid()){
            hdr.key_0_l8.c=0;
        }


        if(!hdr.key_0_6.isValid()){
            hdr.key_0_6.c=0;
        }

        if(!hdr.key_0_5.isValid()){
            hdr.key_0_5.c=0;
        }

        if(!hdr.key_0_4.isValid()){
            hdr.key_0_4.c=0;
        }

        if(!hdr.key_0_3.isValid()){
            hdr.key_0_3.c=0;
        }

        if(!hdr.key_0_2.isValid()){
            hdr.key_0_2.c=0;
        }

        if(!hdr.key_0_1.isValid()){
            hdr.key_0_1.c=0;
        }

        if(!hdr.key_0_0.isValid()){
            hdr.key_0_0.c=0;
        }


        
        if(!hdr.val_0_l32.isValid()){
            hdr.val_0_l32.c=0;
        }

        if(!hdr.val_0_l16.isValid()){
            hdr.val_0_l16.c=0;
        }

        if(!hdr.val_0_l8.isValid()){
            hdr.val_0_l8.c=0;
        }



        if(!hdr.val_0_6.isValid()){
            hdr.val_0_6.c=0;
        }


        if(!hdr.val_0_5.isValid()){
            hdr.val_0_5.c=0;
        }


        if(!hdr.val_0_4.isValid()){
            hdr.val_0_4.c=0;
        }


        if(!hdr.val_0_3.isValid()){
            hdr.val_0_3.c=0;
        }


        if(!hdr.val_0_2.isValid()){
            hdr.val_0_2.c=0;
        }


        if(!hdr.val_0_1.isValid()){
            hdr.val_0_1.c=0;
        }


        if(!hdr.val_0_0.isValid()){
            hdr.val_0_0.c=0;
        }


        if(!hdr.key_1_l32.isValid()){
            hdr.key_1_l32.c=0;
        }

        if(!hdr.key_1_l16.isValid()){
            hdr.key_1_l16.c=0;
        }

        if(!hdr.key_1_l8.isValid()){
            hdr.key_1_l8.c=0;
        }


        if(!hdr.key_1_6.isValid()){
            hdr.key_1_6.c=0;
        }

        if(!hdr.key_1_5.isValid()){
            hdr.key_1_5.c=0;
        }

        if(!hdr.key_1_4.isValid()){
            hdr.key_1_4.c=0;
        }

        if(!hdr.key_1_3.isValid()){
            hdr.key_1_3.c=0;
        }

        if(!hdr.key_1_2.isValid()){
            hdr.key_1_2.c=0;
        }

        if(!hdr.key_1_1.isValid()){
            hdr.key_1_1.c=0;
        }

        if(!hdr.key_1_0.isValid()){
            hdr.key_1_0.c=0;
        }


        
        if(!hdr.val_1_l32.isValid()){
            hdr.val_1_l32.c=0;
        }

        if(!hdr.val_1_l16.isValid()){
            hdr.val_1_l16.c=0;
        }

        if(!hdr.val_1_l8.isValid()){
            hdr.val_1_l8.c=0;
        }



        if(!hdr.val_1_6.isValid()){
            hdr.val_1_6.c=0;
        }


        if(!hdr.val_1_5.isValid()){
            hdr.val_1_5.c=0;
        }


        if(!hdr.val_1_4.isValid()){
            hdr.val_1_4.c=0;
        }


        if(!hdr.val_1_3.isValid()){
            hdr.val_1_3.c=0;
        }


        if(!hdr.val_1_2.isValid()){
            hdr.val_1_2.c=0;
        }


        if(!hdr.val_1_1.isValid()){
            hdr.val_1_1.c=0;
        }


        if(!hdr.val_1_0.isValid()){
            hdr.val_1_0.c=0;
        }
        t_fixed_parse.apply();
        t_filter_0_0.apply();
        t_filter_0_1.apply();
        t_filter_1_0.apply();
        t_filter_1_1.apply();
        // if( ig_md.fixed_parse_found==1 && ig_md.filter0_found==1 && ig_md.filter1_found==1 ) {
        //     c_tot_cnt.count(0);
        // }

        if( ig_md.filter0_found==1 && ig_md.filter1_found==1 ) {
            c_tot_cnt.count(0);
        }

        
        check0.write(0,hdr.key_0_0.c);

        check01.write(0,hdr.key_0_1.c);
        check02.write(0,hdr.key_0_l16.c);
        check03.write(0,hdr.key_0_l8.c);
        check1.write(0,hdr.key_1_0.c);
        check2.write(0,hdr.fixed_parse.c32);


        if (hdr.ipv4.isValid()){
            t_forward.apply();
        }
        // }

    }
}

Pipeline(IngressParser(),
         IngressControl(),
         IngressDeparser(),
         EgressParser(),
         EgressControl(),
         EgressDeparser()) pipe;

Switch(pipe) main;
