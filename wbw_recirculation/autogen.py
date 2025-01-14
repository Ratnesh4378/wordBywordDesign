import argparse

def generate_p4_code(num_keys, num_stages, key_size, output_file):
    """
    Generates P4 code based on the provided table name, number of keys, number of stages, and key size.
    :param table_name: Name of the table to generate.
    :param num_keys: Number of key fields for the table.
    :param num_stages: Number of stages in the pipeline.
    :param key_size: Size of each key in bits.
    :param output_file: File path to save the generated P4 code.
    """
    stages=key_size//4
    p4_code ="""
// Autogenerated P4 Code
#include <core.p4>
#include <tna.p4>

const bit<16> ETHER_HEADER_LENGTH = 14;
const bit<16> IPV4_HEADER_LENGTH = 20;
const bit<16> ICMP_HEADER_LENGTH = 8;
const bit<16> TCP_HEADER_LENGTH = 20;
const bit<16> UDP_HEADER_LENGTH = 8;

#define ETH_TYPE_IPV4   0x800
#define ETH_TYPE_ARP    0x0806

#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_ID_RCLT       111

#define PACKET_TYPE_NORMAL      1
#define PACKET_TYPE_MIRROR      2
#define PACKET_ETH_TYPE_RCLT    3
#define IFACE_DUMMY 100  // Any dummy port

// Didn't include some changes

#define CHAR_COMMA      0x2c


typedef bit<48> macAddr_t;
typedef bit<9>  egressSpec_t;
typedef bit<16> state_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> found_t;
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
    // #1: k1, k2 etc (keys)
"""
    for i in range(num_keys):
        p4_code+="    found_t k"+str(i)+";\n"
    p4_code+="""
    bit<8> packet_type;
    bit<8> cur_value_code;
    // #2: Entries for all possible values
    // #3: Space inside the rclt header to store direct match headers stuff
}

header dummy_t {
    bit<8> c;
}

header dummy4B_t {
    bit<32> c;
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


struct ingress_metadata_t {
    bit<1> mark_to_rec;
    // bit<32> arpTargetIPv4_temp;
    pkt_type_t pkt_type;
    MirrorId_t ing_mir_ses;     // 10 bit
    bit<8> op_failed;
    
    // #3: cur_val_combined entries

    bit<8> packet_id;

    bit<32> arpTargetIPv4_temp;
    bit<1> id;
"""
    for i in range(num_keys):
        for j in range(stages-1):
            p4_code+="    bit<32> filterKey_"+str(i)+"_"+str(j)+";\n"
        p4_code+="    bit<32> filterKey_"+str(i)+"_l32;\n"
        p4_code+="    bit<16> filterKey_"+str(i)+"_l16;\n"
        p4_code+="    bit<8> filterKey_"+str(i)+"_l8;\n"

        for j in range(stages-1):
            p4_code+="    bit<32> filterVal_"+str(i)+"_"+str(j)+";\n"
        p4_code+="    bit<32> filterVal_"+str(i)+"_l32;\n"
        p4_code+="    bit<16> filterVal_"+str(i)+"_l16;\n"
        p4_code+="    bit<8> filterVal_"+str(i)+"_l8;\n"
    p4_code+="""
}

struct ingress_header_t {
    mirror_bridged_metadata_h bridged_meta;
    ethernet_t              ethernet;
    arp_t                   arp;
    ipv4_t                  ipv4;
    rclt_t                  rclt;           
    tcp_t                   tcp;
    tcp_opt_t               tcp_op;
"""
    for i in range(num_stages):
        for j in range(stages-1):
            p4_code+="    b32_t key_"+str(i)+"_"+str(j)+";\n"
        p4_code+="    b32_t key_"+str(i)+"_l32;\n"
        p4_code+="    b16_t key_"+str(i)+"_l16;\n"
        p4_code+="    b8_t key_"+str(i)+"_l8;\n"

        for j in range(stages-1):
            p4_code+="    b32_t val_"+str(i)+"_"+str(j)+";\n"
        p4_code+="    b32_t val_"+str(i)+"_l32;\n"
        p4_code+="    b16_t val_"+str(i)+"_l16;\n"
        p4_code+="    b8_t val_"+str(i)+"_l8;\n"
    p4_code+="""
}

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
        }
}

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

control EgressDeparser(
        packet_out packet,
        inout egress_header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {

    apply {
        // Selectively emmiting ethernet only
        // packet.emit(hdr);
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
            // default: parse_tcp_norclt;
            default : parse_tcp;
        }
    }
    
    
    state parse_rclt {
        packet.extract(hdr.rclt);
        // transition tcp_parse_rclt;
        transition parse_tcp;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_op);
        ig_md.id = 0;
        transition parse_key_0_0;
    }
"""
    for i in range(num_stages):
        for j in range(stages):
            p4_code+="    state parse_key_"+str(i)+"_"+str(j)+" {\n"
            if(j!=0):
                p4_code+="        packet.extract(hdr.key_"+str(i)+"_"+str(j-1)+");\n"
            p4_code+="        bit<32> temp;\n        temp = packet.lookahead<bit<32>>();\n\n"
            p4_code+="        transition select (temp){\n"
            p4_code+="            0x3a000000 &&& 0xff000000:  parse_key_"+str(i)+"_l8;\n"
            p4_code+="            0x003a0000 &&& 0x00ff0000:  parse_key_"+str(i)+"_l16;\n"
            p4_code+="            0x00003a00 &&& 0x0000ff00:  parse_key_"+str(i)+"_l24;\n"
            p4_code+="            0x0000003a &&& 0x000000ff:  parse_key_"+str(i)+"_l32;\n"
            if j!=stages-1:
                p4_code+="            default: parse_key_"+str(i)+"_"+str(j+1)+";\n"
            else:
                p4_code+="            default: accept;\n"
            p4_code+="        }\n    }\n"
        
        p4_code+="    state parse_key_"+str(i)+"_l8 {\n"
        p4_code+="        packet.extract(hdr.key_"+str(i)+"_l8);\n"
        p4_code+="        transition parse_val_"+str(i)+"_0;\n"
        p4_code+="    }\n"

        p4_code+="    state parse_key_"+str(i)+"_l16 {\n"
        p4_code+="        packet.extract(hdr.key_"+str(i)+"_l16);\n"
        p4_code+="        transition parse_val_"+str(i)+"_0;\n"
        p4_code+="    }\n"

        
        p4_code+="    state parse_key_"+str(i)+"_l24 {\n"
        p4_code+="        packet.extract(hdr.key_"+str(i)+"_l8);\n"
        p4_code+="        packet.extract(hdr.key_"+str(i)+"_l16);\n"
        p4_code+="        transition parse_val_"+str(i)+"_0;\n"
        p4_code+="    }\n"

        p4_code+="    state parse_key_"+str(i)+"_l32 {\n"
        p4_code+="        packet.extract(hdr.key_"+str(i)+"_l32);\n"
        p4_code+="        transition parse_val_"+str(i)+"_0;\n"
        p4_code+="    }\n"

        for j in range(stages):
            p4_code+="    state parse_val_"+str(i)+"_"+str(j)+" {\n"
            if(j!=0):
                p4_code+="        packet.extract(hdr.val_"+str(i)+"_"+str(j-1)+");\n\n"
            p4_code+="        bit<32> temp;\n        temp = packet.lookahead<bit<32>>();\n"
            p4_code+="        transition select (temp){\n"
            p4_code+="            0x2c000000 &&& 0xff000000:  parse_val_"+str(i)+"_l8;\n"
            p4_code+="            0x002c0000 &&& 0x00ff0000:  parse_val_"+str(i)+"_l16;\n"
            p4_code+="            0x00002c00 &&& 0x0000ff00:  parse_val_"+str(i)+"_l24;\n"
            p4_code+="            0x0000002c &&& 0x000000ff:  parse_val_"+str(i)+"_l32;\n"
            if j!=stages-1:
                p4_code+="            default: parse_val_"+str(i)+"_"+str(j+1)+";\n"
            else:
                p4_code+="            default: accept;\n"
            p4_code+="        }\n    }\n"

                
        p4_code+="    state parse_val_"+str(i)+"_l8 {\n"
        p4_code+="        packet.extract(hdr.val_"+str(i)+"_l8);\n"
        p4_code+="        transition parse_key_"+str(i+1)+"_0;\n"
        p4_code+="    }\n"

        p4_code+="    state parse_val_"+str(i)+"_l16 {\n"
        p4_code+="        packet.extract(hdr.val_"+str(i)+"_l16);\n"
        p4_code+="        transition parse_key_"+str(i+1)+"_0;\n"
        p4_code+="    }\n"

        
        p4_code+="    state parse_val_"+str(i)+"_l24 {\n"
        p4_code+="        packet.extract(hdr.val_"+str(i)+"_l8);\n"
        p4_code+="        packet.extract(hdr.val_"+str(i)+"_l16);\n"
        p4_code+="        transition parse_key_"+str(i+1)+"_0;\n"
        p4_code+="    }\n"

        p4_code+="    state parse_val_"+str(i)+"_l32 {\n"
        p4_code+="        packet.extract(hdr.val_"+str(i)+"_l32);\n"
        p4_code+="        transition parse_key_"+str(i+1)+"_0;\n"
        p4_code+="    }\n"
    
    p4_code+="    state parse_key_"+str(num_stages)+"_0 {\n"
    p4_code+="        transition accept;\n    }\n}\n"


    p4_code+="""

control EgressControl(
        inout egress_header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {
        hdr.bridged_meta.setInvalid();
    }
}"""
    p4_code+="""

control IngressControl(
        inout ingress_header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    bit<8> max_rclt;
    Counter<bit<32>, bit<16>>(65536, CounterType_t.PACKETS_AND_BYTES)c_tot_cnt;
    Counter<bit<32>, bit<16>>(65536, CounterType_t.PACKETS_AND_BYTES)rclt_tot_cnt;

    action a_nop() {}  

    
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
        hdr.bridged_meta.setValid();
        hdr.bridged_meta.pkt_type = PACKET_TYPE_NORMAL;
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

    
    action a_setup_mirror_rclt(PortId_t egressPort, PortId_t iface_rclt) {
        // cnt2.count(0); //debug
        bit<32> x=hdr.ethernet.dstAddr[31:0];
        // regA.write(0,x);
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
"""
    for i in range(num_keys):
        p4_code+="        hdr.rclt.k"+str(i)+"=0;\n"
    p4_code+="""
        hdr.rclt.rclt_count = 0;
        ig_md.mark_to_rec = 0;
        // Note: None of the above change will go to the mirrored packet which
        // will reach to the destination

        // c_setup_mirror_rclt.count(); // Debug

        // #2: Clearing the buckets by making them 0

        // #3: Saving the extracted values for direct match in rclt header

    } 

    action a_retrive_state(){
        // Egress parser and deparser always remove this field. So need to
        // enable this
        hdr.bridged_meta.setValid();
        hdr.bridged_meta.pkt_type = PACKET_ETH_TYPE_RCLT;   // Any dummy value is ok
        // hdr.rclt.state = hdr.rclt.state;
        // This parameter should be reset after each recirculation;
        hdr.rclt.discardBytes = 0;
        ig_md.mark_to_rec = 0;
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
"""
    for i in range(num_keys):
        for j in range(num_stages):
            p4_code+="    action a_filter_"+str(i)+"_"+str(j)+"() {\n"
            for k in range(stages-1):
                p4_code+="        ig_md.filterKey_"+str(i)+"_"+str(k)+" = hdr.key_"+str(j)+"_"+str(k)+".c ;\n"
            p4_code+="        ig_md.filterKey_"+str(i)+"_l32 = hdr.key_"+str(j)+"_l32.c ;\n"
            p4_code+="        ig_md.filterKey_"+str(i)+"_l16 = hdr.key_"+str(j)+"_l16.c ;\n"
            p4_code+="        ig_md.filterKey_"+str(i)+"_l8 = hdr.key_"+str(j)+"_l8.c ;\n"
            for k in range(stages-1):
                p4_code+="        ig_md.filterVal_"+str(i)+"_"+str(k)+" = hdr.val_"+str(j)+"_"+str(k)+".c ;\n"
            p4_code+="        ig_md.filterVal_"+str(i)+"_l32 = hdr.val_"+str(j)+"_l32.c ;\n"
            p4_code+="        ig_md.filterVal_"+str(i)+"_l16 = hdr.val_"+str(j)+"_l16.c ;\n"
            p4_code+="        ig_md.filterVal_"+str(i)+"_l8 = hdr.val_"+str(j)+"_l8.c ;\n"

            p4_code+="        hdr.rclt.k"+str(i)+" = 1 ;\n    }\n"

        # for j in range(num_stages):
            p4_code+="    table t_filter_"+str(i)+"_"+str(j)+" {\n        key = {\n"
            for k in range(stages-1):
                p4_code+="            hdr.key_"+str(j)+"_"+str(k)+".c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l32.c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l16.c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l8.c: exact;\n"

            for k in range(stages-1):
                p4_code+="            hdr.val_"+str(j)+"_"+str(k)+".c: exact;\n"
            p4_code+="            hdr.val_"+str(j)+"_l32.c: exact;\n"
            p4_code+="            hdr.val_"+str(j)+"_l16.c: exact;\n"
            p4_code+="            hdr.val_"+str(j)+"_l8.c: exact;\n"

            p4_code+="        }\n        actions={\n            a_filter_"+str(i)+"_"+str(j)+";\n        }\n"
            p4_code+="        size = 512;\n    }\n"

    p4_code+="""
    action a_increase_counter(){
        c_tot_cnt.count(0);
        hdr.rclt.rclt_count = max_rclt;
    }

    """

    p4_code+="table t_check {\n        key = {\n"

    for i in range(num_keys):
        p4_code+="            hdr.rclt.k"+str(i)+": exact;\n"
    p4_code+="        }\n        actions = {\n            a_increase_counter;\n        }\n        size = 1024;\n    }\n"


    p4_code+="""
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

        
    table t_save_state_and_recirculate {
        key = {
            ig_intr_md.ingress_mac_tstamp : ternary;
        }
        actions = {
             a_save_state_and_recirculate;
        }
        size = 16;
    }

        
    action a_send_to_dummy_port(){
        ig_tm_md.ucast_egress_port = IFACE_DUMMY;
        ig_dprsr_md.drop_ctl = 1;
    }

    
    apply {
        if (hdr.arp.isValid()){
            t_arp.apply();
        }
        if(hdr.rclt.isValid()){
            a_retrive_state();
        }else{
            t_setup_mirror_rclt.apply();
        }
"""
    for i in range(num_stages):
        p4_code+="        if(!hdr.key_"+str(i)+"_l32.isValid()){\n            hdr.key_"+str(i)+"_l32.c=0;\n        }\n"
        p4_code+="        if(!hdr.key_"+str(i)+"_l16.isValid()){\n            hdr.key_"+str(i)+"_l16.c=0;\n        }\n"
        p4_code+="        if(!hdr.key_"+str(i)+"_l8.isValid()){\n            hdr.key_"+str(i)+"_l8.c=0;\n        }\n"

        for j in range(stages-1):
            p4_code+="        if(!hdr.key_"+str(i)+"_"+str(j)+".isValid()){\n            hdr.key_"+str(i)+"_"+str(j)+".c=0;\n        }\n"

        p4_code+="        if(!hdr.val_"+str(i)+"_l32.isValid()){\n            hdr.val_"+str(i)+"_l32.c=0;\n        }\n"
        p4_code+="        if(!hdr.val_"+str(i)+"_l16.isValid()){\n            hdr.val_"+str(i)+"_l16.c=0;\n        }\n"
        p4_code+="        if(!hdr.val_"+str(i)+"_l8.isValid()){\n            hdr.val_"+str(i)+"_l8.c=0;\n        }\n"

        
        for j in range(stages-1):
            p4_code+="        if(!hdr.val_"+str(i)+"_"+str(j)+".isValid()){\n            hdr.val_"+str(i)+"_"+str(j)+".c=0;\n        }\n"

    for i in range(num_keys):
        for j in range(num_stages):
            p4_code+="        t_filter_"+str(i)+"_"+str(j)+".apply();\n"
    
    
    p4_code+="        max_rclt = 10;\n"
    p4_code+="        rclt_tot_cnt.count(0);\n"
    p4_code+="        t_check.apply();\n"
    p4_code+="""
        if (hdr.rclt.rclt_count == max_rclt){
                a_send_to_dummy_port();
        }
        else{
            t_save_state_and_recirculate.apply();
        }
"""
    p4_code+="    }\n}\n"

    p4_code+="""

Pipeline(IngressParser(),
         IngressControl(),
         IngressDeparser(),
         EgressParser(),
         EgressControl(),
         EgressDeparser()) pipe;

Switch(pipe) main;
"""
    output_file+=".p4"
    with open(output_file, "w") as file:
        file.write(p4_code)

def main():
    parser = argparse.ArgumentParser(description="Generate P4 code with customizable parameters.")
    # parser.add_argument("--table_name", type=str, required=True, help="Name of the table.")
    parser.add_argument("--num_keys", type=int, required=True, help="Number of key fields for the table.")
    parser.add_argument("--num_stages", type=int, required=True, help="Number of stages in the pipeline.")
    parser.add_argument("--key_size", type=int, required=True, help="Size of each key in bits.")
    parser.add_argument("--output_file", type=str, required=True, help="File path to save the generated P4 code.")

    args = parser.parse_args()

    generate_p4_code(
        num_keys=args.num_keys,
        num_stages=args.num_stages,
        key_size=args.key_size,
        output_file=args.output_file
    )

if __name__ == "__main__":
    main()





