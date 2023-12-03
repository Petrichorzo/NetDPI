/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// #include "set_type_of_switch.p4"
// #include "defines.p4"


const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TABLE_NUM = 1;

const bit<16> ETHER_HEADER_LENGTH = 14;
const bit<16> IPV4_HEADER_LENGTH = 20;
const bit<16> IPV4_OPTION_HEADER_LENGTH = 8;
const bit<16> ICMP_HEADER_LENGTH = 8;
const bit<16> TCP_HEADER_LENGTH = 20;
const bit<16> UDP_HEADER_LENGTH = 8;
#define BLOOM_FILTER_ENTRIES 65536
#define START_POS_ENTRIES 65536
#define BLOOM_FILTER_BIT_WIDTH 1
#define LONG_START_POS_BIT_WIDTH 4
#define SHORT_START_POS_BIT_WIDTH 2
#define SLIDE_DISTANCE 2

#define MAX_HOPS 496
#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<32> stateNumber_t;
typedef bit<8> matchLen_t;
typedef bit<16> ruleNumber_t;

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

header ipv4_option_t {
    bit<8> hdr;
    bit<9> position1;
    bit<9> position2;
    bit<9> position3;
    bit<9> position4;
    bit<9> position5;
    bit<9> position6;
    bit<9> position7;
    bit<9> position8;
    bit<16> rule1;
    bit<16> rule2;
    bit<16> rule3;

}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> icmpHdrChecksum;
    bit<16> id;
    bit<16> seq;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header patrn_t {
    bit<8> pattern;
}



struct metadata { 
    /*state_t state;*/
    bit<8> pattern_num;
    bit<16> payload_length;
    bit<16> non_payload_length;   
    bit<1> non_first_pass;
    bit<16> start_pos;
    bit<16> current_pos; 
    bit<1> end_flag;//1 pattern match finished
    bit<1> packet_end_flag;//reach end of the packet
    bit<32> src_state;
    bit<8> next_len;
    //match position
    bit<16> p1;
    bit<16> p2;
    bit<16> p3;
    bit<8> max_match_times;
    // bit<1> switch_type; //0 prefilter 1 verification
}

struct headers {
    @name("ethernet")
    ethernet_t              ethernet;
    @name("ipv4")
    ipv4_t                  ipv4;
    @name("ipv4_option")
    ipv4_option_t           ipv4_option;
    @name("udp")
    udp_t                   udp;
    patrn_t[MAX_HOPS]       patrns;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet); 
        // meta.non_first_pass = 1;
        meta.non_payload_length = ETHER_HEADER_LENGTH;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.non_payload_length = meta.non_payload_length + IPV4_HEADER_LENGTH;//34
        transition parse_ipv4_option;
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        meta.non_payload_length = meta.non_payload_length + IPV4_OPTION_HEADER_LENGTH;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.non_payload_length = meta.non_payload_length + UDP_HEADER_LENGTH;
        meta.pattern_num = 0;
        meta.payload_length = hdr.ipv4.totalLen + 14 - meta.non_payload_length;
        transition prepare_parse_pattern;
    }

    state prepare_parse_pattern {
        transition select(meta.payload_length) {
            0: accept;         
            default: parse_pattern;
        }
    }

    state parse_pattern{
        packet.extract(hdr.patrns.next);
        meta.pattern_num = meta.pattern_num + 1;
        meta.payload_length = meta.payload_length - 1;
        transition select(meta.payload_length) {
            0: accept;         
            default: parse_pattern;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control pattern_verificaiton(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

     
    action init_meta(){
        meta.src_state=0;
        meta.next_len=1;
        meta.current_pos=0;
        //supose every pattern need at most 8 times match
        meta.max_match_times=15;
        meta.end_flag=0;
        meta.packet_end_flag=0;
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    action set_rule(ruleNumber_t ruleNumber){
        if(hdr.ipv4_option.rule1 == ruleNumber || hdr.ipv4_option.rule2 == ruleNumber||hdr.ipv4_option.rule3 == ruleNumber){}
        else{
            if (hdr.ipv4_option.rule1 == 0) {
                hdr.ipv4_option.rule1 = ruleNumber;
            } else if (hdr.ipv4_option.rule2 == 0) {
                hdr.ipv4_option.rule2 = ruleNumber;
            } else if (hdr.ipv4_option.rule3 == 0) {
                hdr.ipv4_option.rule3 = ruleNumber;
            } 
        }
    }

    action is_packet_end(bit<16> pos1,bit<16> pos2,bit<16> pos3){
        if(pos1>=MAX_HOPS || pos2>=MAX_HOPS || pos3>=MAX_HOPS){
            meta.packet_end_flag=1;
        }
    }
    // action goto(stateNumber_t dstState,matchLen_t nextLen,ruleNumber_t ruleNumber){
    //     meta.src_state=dstState;
    //     meta.next_len=nextLen;
    //     if(ruleNumber!=0){
    //         set_rule(ruleNumber);
    //     }
    //     if(nextLen==0){
    //         meta.end_flag=1;
    //     }
    //     else if(nextLen==1){
    //         meta.p1=meta.current_pos;
    //     }else if(nextLen==2){
    //         meta.p1=meta.current_pos;
    //         meta.p2=meta.current_pos+1;
    //     }else if(nextLen==3){
    //         meta.p1=meta.current_pos;
    //         meta.p2=meta.current_pos+1;
    //         meta.p3=meta.current_pos+2;
    //     }
    //     is_packet_end(meta.p1, meta.p2, meta.p3);
    //     if(meta.packet_end_flag==1){
    //         meta.end_flag=1;
    //     }
    // }
    action goto(stateNumber_t dstState,matchLen_t nextLen,ruleNumber_t ruleNumber){
        meta.src_state=dstState;
        
        if(ruleNumber!=0){
            set_rule(ruleNumber);
        }
        if(nextLen==0){
            meta.end_flag=1;
        }
        else if(nextLen==1){
            meta.p1=meta.current_pos+(bit<16>)meta.next_len;
            meta.p2=0;
            meta.p3=0;
        }else if(nextLen==2){
            meta.p1=meta.current_pos+(bit<16>)meta.next_len;
            meta.p2=meta.current_pos+(bit<16>)meta.next_len+1;
            meta.p3=0;
        }else if(nextLen==3){
            meta.p1=meta.current_pos+(bit<16>)meta.next_len;
            meta.p2=meta.current_pos+(bit<16>)meta.next_len+1;
            meta.p3=meta.current_pos+(bit<16>)meta.next_len+2;
        }
        meta.current_pos = meta.current_pos + (bit<16>)meta.next_len;
        meta.next_len=nextLen;
        is_packet_end(meta.p1, meta.p2, meta.p3);
        if(meta.packet_end_flag==1){
            meta.end_flag=1;
        }
    }
    action fail(){
        // meta.end_flag=1;
    }
    table CAC_match1_1 {
        key = {
            meta.src_state: ternary @name("key1_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match1_2 {
        key = {
            meta.src_state: ternary @name("key1_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match1_3 {
        key = {
            meta.src_state: ternary @name("key1_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match1_4 {
        key = {
            meta.src_state: ternary @name("key1_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match1_5 {
        key = {
            meta.src_state: ternary @name("key1_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match1_6 {
        key = {
            meta.src_state: ternary @name("key1_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match1_7 {
        key = {
            meta.src_state: ternary @name("key1_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key1_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key1_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key1_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_1 {
        key = {
            meta.src_state: ternary @name("key2_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_2 {
        key = {
            meta.src_state: ternary @name("key2_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_3 {
        key = {
            meta.src_state: ternary @name("key2_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_4 {
        key = {
            meta.src_state: ternary @name("key2_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_5 {
        key = {
            meta.src_state: ternary @name("key2_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_6 {
        key = {
            meta.src_state: ternary @name("key2_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match2_7 {
        key = {
            meta.src_state: ternary @name("key2_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key2_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key2_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key2_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_1 {
        key = {
            meta.src_state: ternary @name("key3_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_2 {
        key = {
            meta.src_state: ternary @name("key3_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_3 {
        key = {
            meta.src_state: ternary @name("key3_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_4 {
        key = {
            meta.src_state: ternary @name("key3_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_5 {
        key = {
            meta.src_state: ternary @name("key3_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_6 {
        key = {
            meta.src_state: ternary @name("key3_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match3_7 {
        key = {
            meta.src_state: ternary @name("key3_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key3_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key3_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key3_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_1 {
        key = {
            meta.src_state: ternary @name("key4_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_2 {
        key = {
            meta.src_state: ternary @name("key4_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_3 {
        key = {
            meta.src_state: ternary @name("key4_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_4 {
        key = {
            meta.src_state: ternary @name("key4_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_5 {
        key = {
            meta.src_state: ternary @name("key4_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_6 {
        key = {
            meta.src_state: ternary @name("key4_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match4_7 {
        key = {
            meta.src_state: ternary @name("key4_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key4_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key4_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key4_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_1 {
        key = {
            meta.src_state: ternary @name("key5_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_2 {
        key = {
            meta.src_state: ternary @name("key5_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_3 {
        key = {
            meta.src_state: ternary @name("key5_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_4 {
        key = {
            meta.src_state: ternary @name("key5_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_5 {
        key = {
            meta.src_state: ternary @name("key5_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_6 {
        key = {
            meta.src_state: ternary @name("key5_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match5_7 {
        key = {
            meta.src_state: ternary @name("key5_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key5_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key5_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key5_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_1 {
        key = {
            meta.src_state: ternary @name("key6_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_2 {
        key = {
            meta.src_state: ternary @name("key6_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_3 {
        key = {
            meta.src_state: ternary @name("key6_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_4 {
        key = {
            meta.src_state: ternary @name("key6_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_5 {
        key = {
            meta.src_state: ternary @name("key6_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_6 {
        key = {
            meta.src_state: ternary @name("key6_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match6_7 {
        key = {
            meta.src_state: ternary @name("key6_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key6_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key6_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key6_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_1 {
        key = {
            meta.src_state: ternary @name("key7_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_2 {
        key = {
            meta.src_state: ternary @name("key7_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_3 {
        key = {
            meta.src_state: ternary @name("key7_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_4 {
        key = {
            meta.src_state: ternary @name("key7_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_5 {
        key = {
            meta.src_state: ternary @name("key7_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_6 {
        key = {
            meta.src_state: ternary @name("key7_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match7_7 {
        key = {
            meta.src_state: ternary @name("key7_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key7_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key7_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key7_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_1 {
        key = {
            meta.src_state: ternary @name("key8_1_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_1_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_1_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_1_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_2 {
        key = {
            meta.src_state: ternary @name("key8_2_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_2_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_2_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_2_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_3 {
        key = {
            meta.src_state: ternary @name("key8_3_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_3_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_3_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_3_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_4 {
        key = {
            meta.src_state: ternary @name("key8_4_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_4_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_4_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_4_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_5 {
        key = {
            meta.src_state: ternary @name("key8_5_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_5_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_5_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_5_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_6 {
        key = {
            meta.src_state: ternary @name("key8_6_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_6_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_6_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_6_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }
    table CAC_match8_7 {
        key = {
            meta.src_state: ternary @name("key8_7_state");
            hdr.patrns[(bit<9>)meta.p1].pattern: ternary @name("key8_7_c1");
            hdr.patrns[(bit<9>)meta.p2].pattern: ternary @name("key8_7_c2");
            hdr.patrns[(bit<9>)meta.p3].pattern: ternary @name("key8_7_c3");
        }
        actions = {
            goto;
            fail;
        }
        default_action = fail();
        size = 81920;
    }





    /****** main process ******/
    apply {
        //get candidate postion 
        if(hdr.ipv4_option.position1 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position1);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position1 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position1 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position1);
            //2.match -> action
            CAC_match1_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match1_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match1_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match1_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match1_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match1_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match1_7.apply();
            }
        }
        if(hdr.ipv4_option.position2 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position2);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position2 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position2 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position2);
            //2.match -> action
            CAC_match2_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match2_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match2_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match2_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match2_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match2_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match2_7.apply();
            }
        }
        if(hdr.ipv4_option.position3 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position3);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position3 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position3 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position3);
            //2.match -> action
            CAC_match3_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match3_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match3_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match3_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match3_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match3_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match3_7.apply();
            }
        }
        if(hdr.ipv4_option.position4 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position4);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position4 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position4 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position4);
            //2.match -> action
            CAC_match4_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match4_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match4_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match4_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match4_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match4_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match4_7.apply();
            }
        }
        if(hdr.ipv4_option.position5 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position5);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position5 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position5 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position5);
            //2.match -> action
            CAC_match5_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match5_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match5_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match5_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match5_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match5_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match5_7.apply();
            }
        }
        if(hdr.ipv4_option.position6 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position6);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position6 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position6 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position6);
            //2.match -> action
            CAC_match6_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match6_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match6_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match6_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match6_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match6_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match6_7.apply();
            }
        }
        if(hdr.ipv4_option.position7 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position7);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position7 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position7 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position7);
            //2.match -> action
            CAC_match7_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match7_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match7_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match7_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match7_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match7_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match7_7.apply();
            }
        }
        if(hdr.ipv4_option.position8 != 511){
            init_meta();
            //1.get start position
            meta.p1 = (bit<16>)(hdr.ipv4_option.position8);
            meta.p2 = (bit<16>)(hdr.ipv4_option.position8 + 1);
            meta.p3 = (bit<16>)(hdr.ipv4_option.position8 + 2);
            meta.current_pos = (bit<16>)(hdr.ipv4_option.position8);
            //2.match -> action
            CAC_match8_1.apply();
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match8_2.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match8_3.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match8_4.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match8_5.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match8_6.apply();
            }
            meta.max_match_times = meta.max_match_times - 1;
            if(meta.max_match_times != 0 && meta.end_flag != 1){
                CAC_match8_7.apply();
            }
        }






        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {  
        if (hdr.ipv4.isValid())
        {
            // if (meta.flags == MARK_RECIR )
            // {
            //     recirculate(meta);
            // }       
        }     
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control computeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
    update_checksum(
        hdr.ipv4.isValid(),
        { 
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr 
        },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(ParserImpl(), verifyChecksum(), pattern_verificaiton(), MyEgress(), computeChecksum(), DeparserImpl()) main;
