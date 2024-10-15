import sys
def generate_p4_code(k,no_of_bytes,fixed_parse,no_of_filters=0, count=0,no_of_extracts=0,isSum=0,map_index_key="",map_update_val=""):
    stages=no_of_bytes//4
    # P4 code header definitions
    fixed_parse_powers=[]
    powers=[256,128,64,32,16,8,2,1]
    fixed_parse_bits=fixed_parse*8
    for power in powers:
        if fixed_parse_bits >= power:
            fixed_parse_powers.append(power)
            fixed_parse_bits -= power
    p4_code = """
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

"""
    if fixed_parse!=0:
        p4_code+="header fixed_parse_t {\n"
        for power in fixed_parse_powers:
            p4_code+="    bit<"+str(power)+"> c"+str(power)+";\n"
        p4_code+="}\n"
        pass

    p4_code+="""
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
"""
    if(fixed_parse!=0):
        p4_code+="    bit<1> fixed_parse_found;\n"
    for i in range(no_of_extracts):
        p4_code+="    bit<1> extract"+str(i)+"_found;\n"
    for i in range(no_of_extracts):
        for j in range(stages-1):
            p4_code+="    bit<32> extractKey_"+str(i)+"_"+str(j)+";\n"
        p4_code+="    bit<32> extractKey_"+str(i)+"_l32;\n"
        p4_code+="    bit<16> extractKey_"+str(i)+"_l16;\n"
        p4_code+="    bit<8> extractKey_"+str(i)+"_l8;\n"
        for j in range(stages-1):
            p4_code+="    bit<32> extractVal_"+str(i)+"_"+str(j)+";\n"
        p4_code+="    bit<32> extractVal_"+str(i)+"_l32;\n"
        p4_code+="    bit<16> extractVal_"+str(i)+"_l16;\n"
        p4_code+="    bit<8> extractVal_"+str(i)+"_l8;\n"
    for i in range(no_of_filters):
        p4_code+="    bit<1> filter"+str(i)+"_found;\n"
    for i in range(no_of_filters):
        for j in range(stages-1):
            p4_code+="    bit<32> filterKey_"+str(i)+"_"+str(j)+";\n"
        p4_code+="""    bit<32> filterKey_"""+str(i)+"""_l32;
    bit<16> filterKey_"""+str(i)+"""_l16;
    bit<8> filterKey_"""+str(i)+"""_l8;\n"""
        for j in range(stages-1):
            p4_code+="    bit<32> filterVal_"+str(i)+"_"+str(j)+";\n"
        p4_code+="""    bit<32> filterVal_"""+str(i)+"""_l32;
    bit<16> filterVal_"""+str(i)+"""_l16;
    bit<8> filterVal_"""+str(i)+"""_l8;
"""
    p4_code+="""}

struct ingress_header_t {
    ethernet_t              ethernet;
    arp_t                   arp;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    tcp_opt_t               tcp_op;

"""
    if fixed_parse!=0:
        p4_code+="    fixed_parse_t           fixed_parse;\n"


    #adding 32 bit key variables for each key:value pair
    for i in range(k):
        for j in range(stages-1):
            p4_code+=f"     b32_t               key_{i}_{j};\n"
        p4_code+="\n"
    

    #adding 32 bit "value" variables for each key:value pair 
    for i in range(k):
        for j in range(stages-1):
            p4_code+=f"     b32_t               val_{i}_{j};\n"
        p4_code+="\n"

    # adding the lower bits for keys
    for i in range(k):
        p4_code+=f"     b32_t               key_{i}_l32;\n      b16_t               key_{i}_l16;\n      b8_t                key_{i}_l8;\n\n"

    # adding the lower bits for values
    for i in range(k):
        p4_code+=f"     b32_t               val_{i}_l32;\n      b16_t               val_{i}_l16;\n      b8_t                val_{i}_l8;\n\n"
    
    p4_code+="}"

    p4_code+="""
control IngressDeparser(
        packet_out packet,
        inout ingress_header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        packet.emit(hdr);
    }
}
"""
    p4_code+="""
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

    state parse_tcp {\n"""
    for i in range(no_of_filters):
        p4_code+="        ig_md.filter"+str(i)+"_found=0;\n"
    for i in range(no_of_extracts):
        p4_code+="        ig_md.extract"+str(i)+"_found=0;\n"
    if(fixed_parse!=0):
        p4_code+="        ig_md.fixed_parse_found=0;\n"
    p4_code+="""        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_op);
        ig_md.id = 0;
        """
    if fixed_parse==0:
        p4_code+="""
        transition parse_key_0_0;
    }

"""
    else:
        p4_code+="""
        transition parse_fixed;
    }
    state parse_fixed {
        packet.extract(hdr.fixed_parse);
        transition parse_key_0_0;
    }
"""
    for i in range(k):
        for j in range(stages):
            next_state = "accept" if j == stages-1 else f"parse_key_{i}_{j + 1}"
            extract= "" if j==0 else f"packet.extract(hdr.key_{i}_{j-1});\n"
            p4_code+="""
    state parse_key_"""+str(i)+"""_"""+str(j)+""" {
        """+extract+"""
        bit<32> temp;
        temp = packet.lookahead<bit<32>>();
        transition select (temp){
            0x3a000000 &&& 0xff000000:  parse_key_"""+str(i)+"""_l8;
            0x003a0000 &&& 0x00ff0000:  parse_key_"""+str(i)+"""_l16;
            0x00003a00 &&& 0x0000ff00:  parse_key_"""+str(i)+"""_l24;
            0x0000003a &&& 0x000000ff:  parse_key_"""+str(i)+"""_l32;
            default: """+next_state+""";
        }
    }
    
"""
        p4_code+="""
    state parse_key_"""+str(i)+"""_l8 {
        packet.extract(hdr.key_"""+str(i)+"""_l8);
        transition parse_val_"""+str(i)+"""_0;
    }

    state parse_key_"""+str(i)+"""_l16 {
        packet.extract(hdr.key_"""+str(i)+"""_l16);
        transition parse_val_"""+str(i)+"""_0;
    }

    state parse_key_"""+str(i)+"""_l24 {
        packet.extract(hdr.key_"""+str(i)+"""_l8);
        packet.extract(hdr.key_"""+str(i)+"""_l16);
        transition parse_val_"""+str(i)+"""_0;
    }

    state parse_key_"""+str(i)+"""_l32 {
        packet.extract(hdr.key_"""+str(i)+"""_l32);
        transition parse_val_"""+str(i)+"""_0;
    }
 
"""
        for j in range(stages):
            next_state = "accept" if j == stages-1 else f"parse_val_{i}_{j + 1}"
            extract= "" if j==0 else f"packet.extract(hdr.val_{i}_{j-1});\n"
            p4_code+="""

    state parse_val_"""+str(i)+"""_"""+str(j)+""" {
        """+extract+"""
        bit<32> temp;
        temp= packet.lookahead<bit<32>>();
        transition select (temp){
            0x2c000000 &&& 0xff000000:  parse_val_"""+str(i)+"""_l8;
            0x002c0000 &&& 0x00ff0000:  parse_val_"""+str(i)+"""_l16;
            0x00002c00 &&& 0x0000ff00:  parse_val_"""+str(i)+"""_l24;
            0x0000002c &&& 0x000000ff:  parse_val_"""+str(i)+"""_l32;
            default: """+next_state+""";
        }
    }

 """
        next_state=str(i+1)
        p4_code+="""

    state parse_val_"""+str(i)+"""_l8 {
        packet.extract(hdr.val_"""+str(i)+"""_l8);
        transition parse_key_"""+next_state+"""_0;
    }

    state parse_val_"""+str(i)+"""_l16 {
        packet.extract(hdr.val_"""+str(i)+"""_l16);
        transition parse_key_"""+next_state+"""_0;
    }

    state parse_val_"""+str(i)+"""_l24 {
        packet.extract(hdr.val_"""+str(i)+"""_l8);
        packet.extract(hdr.val_"""+str(i)+"""_l16);
        transition parse_key_"""+next_state+"""_0;
    }

    state parse_val_"""+str(i)+"""_l32 {
        packet.extract(hdr.val_"""+str(i)+"""_l32);
        transition parse_key_"""+next_state+"""_0;
    }

"""
    p4_code+="""

    state parse_key_"""+str(k)+"""_0 {
        transition accept;
    }

}
"""
    p4_code+="""

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

"""

    for i in range(k):
        pass
    #     for j in range(stages-1):
    #         p4_code+="    bit<32>    store_key_"+str(i)+"_"+str(j)+";\n"
    #     p4_code+="""
    # bit<32>    store_key_"""+str(i)+"""_l32;
    # bit<16>    store_key_"""+str(i)+"""_l16;
    # bit<8>    store_key_"""+str(i)+"""_l8;
    #     \n"""
    #     for j in range(stages-1):
    #         p4_code+="    bit<32>    store_val_"+str(i)+"_"+str(j)+";\n"
        
    #     p4_code+="""
    # bit<32>    store_val_"""+str(i)+"""_l32;
    # bit<16>    store_val_"""+str(i)+"""_l16;
    # bit<8>    store_val_"""+str(i)+"""_l8;
    # \n"""

    #     for j in range(stages-1):
    #         p4_code+="    Register<bit<32>, bit<16>>(65536)    r_val_"+str(i)+"_"+str(j)+";\n"
    #     p4_code+="""
    # Register<bit<32>, bit<16>>(65536)    r_val_"""+str(i)+"""_l32;
    # Register<bit<16>, bit<16>>(65536)    r_val_"""+str(i)+"""_l16;
    # Register<bit<8>, bit<16>>(65536)    r_val_"""+str(i)+"""_l8;
    # \n"""
        

    if map_index_key!="":
        for i in range(stages-1):
            p4_code+="    Register<bit<32>, bit<16>>(65536)    r_"+map_index_key+"_"+str(i)+";\n"
        p4_code+="    Register<bit<32>, bit<16>>(65536)    r_"+map_index_key+"_l32;\n"
        p4_code+="    Register<bit<16>, bit<16>>(65536)    r_"+map_index_key+"_l16;\n"
        p4_code+="    Register<bit<8>, bit<16>>(65536)    r_"+map_index_key+"_l8;\n"
        
    
    for i in range(isSum):
        p4_code+="    Register<bit<32>, bit<16>>(65536) tot_sum"+str(i)+";\n"
    
    # for i in range(isSum):
    #     p4_code+="""    RegisterAction <bit<32>, bit<8>, bit<32>>(tot_sum"""+str(i)+""")ra_total_sum"""+str(i)+"""={
    #     void apply(inout bit<32> regval){
    #         regval = regval + hdr.rclt.var_5_0;
    #     }
    # };\n"""
    if(count!=0):
        p4_code+="    Counter<bit<32>, bit<16>>(65536, CounterType_t.PACKETS_AND_BYTES)c_tot_cnt;\n"
    p4_code+="""

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
    }\n"""
    if fixed_parse!=0:
        p4_code+="    action a_fixed_parse () {\n        ig_md.fixed_parse_found=1;\n    }\n"
        p4_code+="    table t_fixed_parse {\n        key = {\n"
        for power in fixed_parse_powers:
            p4_code+="            hdr.fixed_parse.c"+str(power)+": exact;\n"
        p4_code+="        }\n        actions = {\n            a_fixed_parse;\n        }\n        size = 256;\n    }\n"
    
    for i in range(no_of_extracts):
        for j in range(k):
            p4_code+="    action a_extract_"+str(i)+"_"+str(j)+"(){\n        ig_md.extract"+str(i)+"_found = 1;\n"
            for stage in range(stages-1):
                p4_code+="        ig_md.extractKey_"+str(i)+"_"+str(stage)+" = hdr.key_"+str(j)+"_"+str(stage)+".c;\n"
            p4_code+="        ig_md.extractKey_"+str(i)+"_l32 = hdr.key_"+str(j)+"_l32.c;\n"
            p4_code+="        ig_md.extractKey_"+str(i)+"_l16 = hdr.key_"+str(j)+"_l16.c;\n" 
            p4_code+="        ig_md.extractKey_"+str(i)+"_l8 = hdr.key_"+str(j)+"_l8.c;\n"
            for stage in range(stages-1):
                p4_code+="        ig_md.extractVal_"+str(i)+"_"+str(stage)+" = hdr.val_"+str(j)+"_"+str(stage)+".c;\n"
            p4_code+="        ig_md.extractVal_"+str(i)+"_l32 = hdr.val_"+str(j)+"_l32.c;\n"
            p4_code+="        ig_md.extractVal_"+str(i)+"_l16 = hdr.val_"+str(j)+"_l16.c;\n" 
            p4_code+="        ig_md.extractVal_"+str(i)+"_l8 = hdr.val_"+str(j)+"_l8.c;\n"
            p4_code+="    }\n"

            p4_code+="   table t_extract_"+str(i)+"_"+str(j)+"{\n        key = {\n"
            for stage in range(stages-1):
                p4_code+="            hdr.key_"+str(j)+"_"+str(stage)+".c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l32.c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l16.c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l8.c: exact;\n"

            p4_code+="        }\n        actions={\n            a_extract_"+str(i)+"_"+str(j)+";\n        }\n        size = 512;\n    }\n"
    for i in range(no_of_filters):
        for j in range(k):
            p4_code+="    action a_filter_"+str(i)+"_"+str(j)+"(){\n        ig_md.filter"+str(i)+"_found = 1;\n"
            for stage in range(stages-1):
                p4_code+="        ig_md.filterKey_"+str(i)+"_"+str(stage)+" = hdr.key_"+str(j)+"_"+str(stage)+".c;\n"
            p4_code+="        ig_md.filterKey_"+str(i)+"_l32 = hdr.key_"+str(j)+"_l32.c;\n"
            p4_code+="        ig_md.filterKey_"+str(i)+"_l16 = hdr.key_"+str(j)+"_l16.c;\n"
            p4_code+="        ig_md.filterKey_"+str(i)+"_l8 = hdr.key_"+str(j)+"_l8.c;\n"
            for stage in range(stages-1):
                p4_code+="        ig_md.filterVal_"+str(i)+"_"+str(stage)+" = hdr.val_"+str(j)+"_"+str(stage)+".c;\n"
            p4_code+="        ig_md.filterVal_"+str(i)+"_l32 = hdr.val_"+str(j)+"_l32.c;\n"
            p4_code+="        ig_md.filterVal_"+str(i)+"_l16 = hdr.val_"+str(j)+"_l16.c;\n"
            p4_code+="        ig_md.filterVal_"+str(i)+"_l8 = hdr.val_"+str(j)+"_l8.c;\n"
            p4_code+="    }\n"

            p4_code+="   table t_filter_"+str(i)+"_"+str(j)+"{\n        key = {\n"
            for stage in range(stages-1):
                p4_code+="            hdr.key_"+str(j)+"_"+str(stage)+".c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l32.c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l16.c: exact;\n"
            p4_code+="            hdr.key_"+str(j)+"_l8.c: exact;\n"
            for stage in range(stages-1):
                p4_code+="            hdr.val_"+str(j)+"_"+str(stage)+".c: exact;\n"
            p4_code+="            hdr.val_"+str(j)+"_l32.c: exact;\n"
            p4_code+="            hdr.val_"+str(j)+"_l16.c: exact;\n"
            p4_code+="            hdr.val_"+str(j)+"_l8.c: exact;\n"

            p4_code+="        }\n        actions={\n            a_filter_"+str(i)+"_"+str(j)+";\n        }\n        size = 512;\n    }\n"

            
    p4_code+="""
    apply {
        if (hdr.arp.isValid()){
            t_arp.apply();
        }
"""
#     for i in range(k):
#         p4_code+="""
#         store_key_"""+str(i)+"""_l32=0;
#         store_key_"""+str(i)+"""_l16=0;
#         store_key_"""+str(i)+"""_l8=0;
#         store_val_"""+str(i)+"""_l32=0;
#         store_val_"""+str(i)+"""_l16=0;
#         store_val_"""+str(i)+"""_l8=0;

# """
    for i in range(k):
        p4_code+="""

        if(!hdr.key_"""+str(i)+"""_l32.isValid()){
            hdr.key_"""+str(i)+"""_l32.c=0;
        }

        if(!hdr.key_"""+str(i)+"""_l16.isValid()){
            hdr.key_"""+str(i)+"""_l16.c=0;
        }

        if(!hdr.key_"""+str(i)+"""_l8.isValid()){
            hdr.key_"""+str(i)+"""_l8.c=0;
        }

"""
        for j in range(stages-1):
            idx=stages-1-j-1
            i_idx=f"{i}_{idx}"
            p4_code+="""
        if(!hdr.key_"""+i_idx+""".isValid()){
            hdr.key_"""+i_idx+""".c=0;
        }
"""
        p4_code+="""

        
        if(!hdr.val_"""+str(i)+"""_l32.isValid()){
            hdr.val_"""+str(i)+"""_l32.c=0;
        }

        if(!hdr.val_"""+str(i)+"""_l16.isValid()){
            hdr.val_"""+str(i)+"""_l16.c=0;
        }

        if(!hdr.val_"""+str(i)+"""_l8.isValid()){
            hdr.val_"""+str(i)+"""_l8.c=0;
        }

"""
        for j in range(stages-1):
            idx=str(stages-1-j-1)
            p4_code+="""

        if(!hdr.val_"""+str(i)+"_"+idx+""".isValid()){
            hdr.val_"""+str(i)+"_"+idx+""".c=0;
        }
"""
        # if i==0:
            # p4_code+="        index=Hash_0.get({"
            # for j in range(stages-1):
            #     p4_code+="hdr.val_"+str(i)+"_"+str(j)+".c,"
            # p4_code+="hdr.val_"+str(i)+"_l32.c,hdr.val_"+str(i)+"_l16.c,hdr.val_"+str(i)+"_l8.c });\n"
        
        # for j in range(stages-1):
        #     p4_code+="        r_val_"+str(i)+"_"+str(j)+".write(index,hdr.val_"+str(i)+"_"+str(j)+".c );\n"
        # p4_code+="""
        # r_val_"""+str(i)+"""_l32.write(index,hdr.val_"""+str(i)+"""_l32.c);
        # r_val_"""+str(i)+"""_l16.write(index,hdr.val_"""+str(i)+"""_l16.c);
        # r_val_"""+str(i)+"""_l8.write(index,hdr.val_"""+str(i)+"""_l8.c);\n"""
    if fixed_parse!=0:
        p4_code+="        t_fixed_parse.apply();\n"
    for i in range(no_of_extracts):
        for j in range(k):
            p4_code+="        t_extract_"+str(i)+"_"+str(j)+".apply();\n"
    for i in range(no_of_filters):
        for j in range(k):
            p4_code+="        t_filter_"+str(i)+"_"+str(j)+".apply();\n"
    if count!=0:
        p4_code+="        if( "
        if fixed_parse!=0:
            p4_code+="ig_md.fixed_parse_found==1 "
        for i in range(no_of_filters):
            if(i==0 and fixed_parse==0):
                p4_code+="ig_md.filter"+str(i)+"_found==1 "
            else:
                p4_code+="&& ig_md.filter"+str(i)+"_found==1 " 
        p4_code+=") {\n            c_tot_cnt.count(0);\n        }\n"
    
    # if isSum!=0:
    #     p4_code+="        if( "
    #     if(fixed_parse!=0):
    #         p4_code+="ig_md.fixed_parse_found==1 "
    #     for i in range(no_of_filters)

    if map_index_key!="":
        p4_code+="        index=Hash_0.get({"
        for i in range(stages-1):
            p4_code+="ig_md."+map_index_key+"_"+str(i)+","
        p4_code+="ig_md."+map_index_key+"_l32,ig_md."+map_index_key+"_l16,ig_md."+map_index_key+"_l8 });\n"

                
        for i in range(stages-1):
            p4_code+="        r_"+map_index_key+"_"+str(i)+".write(index,ig_md."+map_update_val+"_"+str(i)+" );\n"
        p4_code+="""
        r_"""+map_index_key+"""_l32.write(index,ig_md."""+map_update_val+"""_l32);
        r_"""+map_index_key+"""_l16.write(index,ig_md."""+map_update_val+"""_l16);
        r_"""+map_index_key+"""_l8.write(index,ig_md."""+map_update_val+"""_l8);\n"""
        


    p4_code+="""

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
"""

    return p4_code

def save_p4_code_to_file(filename, p4_code):
    with open(filename, 'w') as file:
        file.write(p4_code)
    print(f"P4 code saved to {filename}")

if(len(sys.argv)<3 or len(sys.argv)>11):
    print(f"Incorrect command: python3 {sys.argv[0]} <no_of_key:value pair> <no_of_bytes_for_each_key:value_pair> <fixed_parse_bytes> <no_of_filters> <count_op> <no_of_extracts> <sum> <map_index_key> <map_update_val> <json_filename>\n")
    exit(1)
k = int(sys.argv[1])
no_of_bytes=int(sys.argv[2])
fixed_parse_bytes=0
no_of_filters=0
count=0
no_of_extracts=0
isSum=0
filename=[]
map_index_key=""
map_update_val=""
if(len(sys.argv)>=4):
    fixed_parse_bytes=int(sys.argv[3])
if(len(sys.argv)>=5):
    no_of_filters=int(sys.argv[4])

if(len(sys.argv)>=6):
    count=int(sys.argv[5])
if(len(sys.argv)>=7):
    no_of_extracts=int(sys.argv[6])
if(len(sys.argv)>=8):
    isSum=int(sys.argv[7])
if(len(sys.argv)>=9):
    map_index_key=sys.argv[8]
if(len(sys.argv)>=10):
    map_update_val=sys.argv[9]
if(len(sys.argv)>=11):
    filename=sys.argv[10].split(".")
json_filename=filename[0]
generated_p4_code = generate_p4_code(k,no_of_bytes,fixed_parse_bytes,no_of_filters,count,no_of_extracts,isSum,map_index_key,map_update_val)

save_p4_code_to_file(f"{json_filename}.p4", generated_p4_code)
