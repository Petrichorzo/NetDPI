/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in pkt,
                out my_ingress_headers_for_filter_t hdr,
                inout my_ingress_metadata_for_filter_t meta,
                inout standard_metadata_t standard_metadata)

{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        // pkt.extract(ig_intr_md);
        // pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        // meta.non_payload_length = 14;
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        // meta.non_payload_length = meta.non_payload_length + 20;//34
        transition parse_ipv4_option;
    }

    state parse_ipv4_option {
        // meta.non_payload_length = meta.non_payload_length + 8;
        pkt.extract(hdr.ipv4_option);
        transition parse_udp;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        // meta.non_payload_length = meta.non_payload_length + 8;
        // meta.pattern_num = 0;
        meta.payload_length = 120;
        meta.st_mask1_low1=0x00000000;
        meta.st_mask1_high1=0x00000000;
        meta.st_mask2_low1=0x00000000;
        meta.st_mask2_high1=0x00000000;
        meta.st_mask3_low1=0x00000000;
        meta.st_mask3_high1=0x00000000;
        meta.st_mask4_low1=0x00000000;
        meta.st_mask4_high1=0x00000000;
        meta.st_mask5_low1=0x00000000;
        meta.st_mask5_high1=0x00000000;
        meta.st_mask6_low1=0x00000000;
        meta.st_mask6_high1=0x00000000;
        meta.st_mask7_low1=0x00000000;
        meta.st_mask7_high1=0x00000000;
        meta.st_mask8_low1=0x00000000;
        meta.st_mask8_high1=0x00000000;
        meta.st_mask9_low1=0x00000000;
        meta.st_mask9_high1=0x00000000;
        meta.st_mask10_low1=0x00000000;
        meta.st_mask10_high1=0x00000000;
        meta.st_mask11_low1=0x00000000;
        meta.st_mask11_high1=0x00000000;
        meta.st_mask12_low1=0x00000000;
        meta.st_mask12_high1=0x00000000;
        meta.st_mask13_low1=0x00000000;
        meta.st_mask13_high1=0x00000000;
        meta.st_mask14_low1=0x00000000;
        meta.st_mask14_high1=0x00000000;
        meta.st_mask15_low1=0x00000000;
        transition parse_pattern;
    }

    // state prepare_parse_pattern {
    //     transition select(meta.payload_length) {
    //         0: accept;         
    //         default: parse_pattern;
    //     }
    // }

    state parse_pattern{
        pkt.extract(hdr.patrns.next);
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

control verifyChecksum(inout my_ingress_headers_for_filter_t hdr, inout my_ingress_metadata_for_filter_t meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control pattern_prefilter(inout my_ingress_headers_for_filter_t hdr,
                  inout my_ingress_metadata_for_filter_t meta,
                  inout standard_metadata_t standard_metadata) {



    register<bit<64>>(1) first_filter_ingress_time_reg;
    register<bit<64>>(1) last_filter_ingress_time_reg;

    /**************************************************/
    /******************** stage 0 *********************/
    /**************************************************/

    action or1_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1;
        meta.st_mask1_low1 = mask_low1;
    }
    table filter_win1_1 {
        key = {
            hdr.patrns[0].pattern: exact;
        }
        actions = {
            or1_1;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1;
        meta.st_mask2_low1 = mask_low1;
    }
    table filter_win2_1 {
        key = {
            hdr.patrns[8].pattern: exact;
        }
        actions = {
            or2_1;
        }
        size = 256;
    }

    action or3_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1;
        meta.st_mask3_low1 = mask_low1;
    }
    table filter_win3_1 {
        key = {
            hdr.patrns[16].pattern: exact;
        }
        actions = {
            or3_1;
        }
        size = 256;
    }

    action or4_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1;
        meta.st_mask4_low1 = mask_low1;
    }
    table filter_win4_1 {
        key = {
            hdr.patrns[24].pattern: exact;
        }
        actions = {
            or4_1;
        }
        size = 256;
    }

    action or5_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1;
        meta.st_mask5_low1 = mask_low1;
    }
    table filter_win5_1 {
        key = {
            hdr.patrns[32].pattern: exact;
        }
        actions = {
            or5_1;
        }
        size = 256;
    }

    action or6_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1;
        meta.st_mask6_low1 = mask_low1;
    }
    table filter_win6_1 {
        key = {
            hdr.patrns[40].pattern: exact;
        }
        actions = {
            or6_1;
        }
        size = 256;
    }

    action or7_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1;
        meta.st_mask7_low1 = mask_low1;
    }
    table filter_win7_1 {
        key = {
            hdr.patrns[48].pattern: exact;
        }
        actions = {
            or7_1;
        }
        size = 256;
    }

    action or8_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1;
        meta.st_mask8_low1 = mask_low1;
    }
    table filter_win8_1 {
        key = {
            hdr.patrns[56].pattern: exact;
        }
        actions = {
            or8_1;
        }
        size = 256;
    }

    action or9_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1;
        meta.st_mask9_low1 = mask_low1;
    }
    table filter_win9_1 {
        key = {
            hdr.patrns[64].pattern: exact;
        }
        actions = {
            or9_1;
        }
        size = 256;
    }

    action or10_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1;
        meta.st_mask10_low1 = mask_low1;
    }
    table filter_win10_1 {
        key = {
            hdr.patrns[72].pattern: exact;
        }
        actions = {
            or10_1;
        }
        size = 256;
    }

    action or11_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1;
        meta.st_mask11_low1 = mask_low1;
    }
    table filter_win11_1 {
        key = {
            hdr.patrns[80].pattern: exact;
        }
        actions = {
            or11_1;
        }
        size = 256;
    }

    action or12_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1;
        meta.st_mask12_low1 = mask_low1;
    }
    table filter_win12_1 {
        key = {
            hdr.patrns[88].pattern: exact;
        }
        actions = {
            or12_1;
        }
        size = 256;
    }

    action or13_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1;
        meta.st_mask13_low1 = mask_low1;
    }
    table filter_win13_1 {
        key = {
            hdr.patrns[96].pattern: exact;
        }
        actions = {
            or13_1;
        }
        size = 256;
    }

    action or14_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1;
        meta.st_mask14_low1 = mask_low1;
    }
    table filter_win14_1 {
        key = {
            hdr.patrns[104].pattern: exact;
        }
        actions = {
            or14_1;
        }
        size = 256;
    }

    action or15_1(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1;
    }
    table filter_win15_1 {
        key = {
            hdr.patrns[112].pattern: exact;
        }
        actions = {
            or15_1;
        }
        size = 256;
    }

    action or1_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_2 {
        key = {
            hdr.patrns[1].pattern: exact;
        }
        actions = {
            or1_2;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_2 {
        key = {
            hdr.patrns[9].pattern: exact;
        }
        actions = {
            or2_2;
        }
        size = 256;
    }

    action or3_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_2 {
        key = {
            hdr.patrns[17].pattern: exact;
        }
        actions = {
            or3_2;
        }
        size = 256;
    }

    action or4_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_2 {
        key = {
            hdr.patrns[25].pattern: exact;
        }
        actions = {
            or4_2;
        }
        size = 256;
    }

    action or5_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_2 {
        key = {
            hdr.patrns[33].pattern: exact;
        }
        actions = {
            or5_2;
        }
        size = 256;
    }

    action or6_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_2 {
        key = {
            hdr.patrns[41].pattern: exact;
        }
        actions = {
            or6_2;
        }
        size = 256;
    }

    action or7_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_2 {
        key = {
            hdr.patrns[49].pattern: exact;
        }
        actions = {
            or7_2;
        }
        size = 256;
    }

    action or8_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_2 {
        key = {
            hdr.patrns[57].pattern: exact;
        }
        actions = {
            or8_2;
        }
        size = 256;
    }

    action or9_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_2 {
        key = {
            hdr.patrns[65].pattern: exact;
        }
        actions = {
            or9_2;
        }
        size = 256;
    }

    action or10_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_2 {
        key = {
            hdr.patrns[73].pattern: exact;
        }
        actions = {
            or10_2;
        }
        size = 256;
    }

    action or11_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_2 {
        key = {
            hdr.patrns[81].pattern: exact;
        }
        actions = {
            or11_2;
        }
        size = 256;
    }

    action or12_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_2 {
        key = {
            hdr.patrns[89].pattern: exact;
        }
        actions = {
            or12_2;
        }
        size = 256;
    }

    action or13_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_2 {
        key = {
            hdr.patrns[97].pattern: exact;
        }
        actions = {
            or13_2;
        }
        size = 256;
    }

    action or14_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_2 {
        key = {
            hdr.patrns[105].pattern: exact;
        }
        actions = {
            or14_2;
        }
        size = 256;
    }

    action or15_2(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_2 {
        key = {
            hdr.patrns[113].pattern: exact;
        }
        actions = {
            or15_2;
        }
        size = 256;
    }

    action or1_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_3 {
        key = {
            hdr.patrns[2].pattern: exact;
        }
        actions = {
            or1_3;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_3 {
        key = {
            hdr.patrns[10].pattern: exact;
        }
        actions = {
            or2_3;
        }
        size = 256;
    }

    action or3_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_3 {
        key = {
            hdr.patrns[18].pattern: exact;
        }
        actions = {
            or3_3;
        }
        size = 256;
    }

    action or4_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_3 {
        key = {
            hdr.patrns[26].pattern: exact;
        }
        actions = {
            or4_3;
        }
        size = 256;
    }

    action or5_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_3 {
        key = {
            hdr.patrns[34].pattern: exact;
        }
        actions = {
            or5_3;
        }
        size = 256;
    }

    action or6_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_3 {
        key = {
            hdr.patrns[42].pattern: exact;
        }
        actions = {
            or6_3;
        }
        size = 256;
    }

    action or7_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_3 {
        key = {
            hdr.patrns[50].pattern: exact;
        }
        actions = {
            or7_3;
        }
        size = 256;
    }

    action or8_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_3 {
        key = {
            hdr.patrns[58].pattern: exact;
        }
        actions = {
            or8_3;
        }
        size = 256;
    }

    action or9_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_3 {
        key = {
            hdr.patrns[66].pattern: exact;
        }
        actions = {
            or9_3;
        }
        size = 256;
    }

    action or10_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_3 {
        key = {
            hdr.patrns[74].pattern: exact;
        }
        actions = {
            or10_3;
        }
        size = 256;
    }

    action or11_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_3 {
        key = {
            hdr.patrns[82].pattern: exact;
        }
        actions = {
            or11_3;
        }
        size = 256;
    }

    action or12_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_3 {
        key = {
            hdr.patrns[90].pattern: exact;
        }
        actions = {
            or12_3;
        }
        size = 256;
    }

    action or13_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_3 {
        key = {
            hdr.patrns[98].pattern: exact;
        }
        actions = {
            or13_3;
        }
        size = 256;
    }

    action or14_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_3 {
        key = {
            hdr.patrns[106].pattern: exact;
        }
        actions = {
            or14_3;
        }
        size = 256;
    }

    action or15_3(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_3 {
        key = {
            hdr.patrns[114].pattern: exact;
        }
        actions = {
            or15_3;
        }
        size = 256;
    }

    action or1_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_4 {
        key = {
            hdr.patrns[3].pattern: exact;
        }
        actions = {
            or1_4;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_4 {
        key = {
            hdr.patrns[11].pattern: exact;
        }
        actions = {
            or2_4;
        }
        size = 256;
    }

    action or3_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_4 {
        key = {
            hdr.patrns[19].pattern: exact;
        }
        actions = {
            or3_4;
        }
        size = 256;
    }

    action or4_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_4 {
        key = {
            hdr.patrns[27].pattern: exact;
        }
        actions = {
            or4_4;
        }
        size = 256;
    }

    action or5_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_4 {
        key = {
            hdr.patrns[35].pattern: exact;
        }
        actions = {
            or5_4;
        }
        size = 256;
    }

    action or6_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_4 {
        key = {
            hdr.patrns[43].pattern: exact;
        }
        actions = {
            or6_4;
        }
        size = 256;
    }

    action or7_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_4 {
        key = {
            hdr.patrns[51].pattern: exact;
        }
        actions = {
            or7_4;
        }
        size = 256;
    }

    action or8_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_4 {
        key = {
            hdr.patrns[59].pattern: exact;
        }
        actions = {
            or8_4;
        }
        size = 256;
    }

    action or9_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_4 {
        key = {
            hdr.patrns[67].pattern: exact;
        }
        actions = {
            or9_4;
        }
        size = 256;
    }

    action or10_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_4 {
        key = {
            hdr.patrns[75].pattern: exact;
        }
        actions = {
            or10_4;
        }
        size = 256;
    }

    action or11_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_4 {
        key = {
            hdr.patrns[83].pattern: exact;
        }
        actions = {
            or11_4;
        }
        size = 256;
    }

    action or12_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_4 {
        key = {
            hdr.patrns[91].pattern: exact;
        }
        actions = {
            or12_4;
        }
        size = 256;
    }

    action or13_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_4 {
        key = {
            hdr.patrns[99].pattern: exact;
        }
        actions = {
            or13_4;
        }
        size = 256;
    }

    action or14_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_4 {
        key = {
            hdr.patrns[107].pattern: exact;
        }
        actions = {
            or14_4;
        }
        size = 256;
    }

    action or15_4(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_4 {
        key = {
            hdr.patrns[115].pattern: exact;
        }
        actions = {
            or15_4;
        }
        size = 256;
    }

    action or1_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_5 {
        key = {
            hdr.patrns[4].pattern: exact;
        }
        actions = {
            or1_5;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_5 {
        key = {
            hdr.patrns[12].pattern: exact;
        }
        actions = {
            or2_5;
        }
        size = 256;
    }

    action or3_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_5 {
        key = {
            hdr.patrns[20].pattern: exact;
        }
        actions = {
            or3_5;
        }
        size = 256;
    }

    action or4_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_5 {
        key = {
            hdr.patrns[28].pattern: exact;
        }
        actions = {
            or4_5;
        }
        size = 256;
    }

    action or5_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_5 {
        key = {
            hdr.patrns[36].pattern: exact;
        }
        actions = {
            or5_5;
        }
        size = 256;
    }

    action or6_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_5 {
        key = {
            hdr.patrns[44].pattern: exact;
        }
        actions = {
            or6_5;
        }
        size = 256;
    }

    action or7_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_5 {
        key = {
            hdr.patrns[52].pattern: exact;
        }
        actions = {
            or7_5;
        }
        size = 256;
    }

    action or8_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_5 {
        key = {
            hdr.patrns[60].pattern: exact;
        }
        actions = {
            or8_5;
        }
        size = 256;
    }

    action or9_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_5 {
        key = {
            hdr.patrns[68].pattern: exact;
        }
        actions = {
            or9_5;
        }
        size = 256;
    }

    action or10_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_5 {
        key = {
            hdr.patrns[76].pattern: exact;
        }
        actions = {
            or10_5;
        }
        size = 256;
    }

    action or11_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_5 {
        key = {
            hdr.patrns[84].pattern: exact;
        }
        actions = {
            or11_5;
        }
        size = 256;
    }

    action or12_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_5 {
        key = {
            hdr.patrns[92].pattern: exact;
        }
        actions = {
            or12_5;
        }
        size = 256;
    }

    action or13_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_5 {
        key = {
            hdr.patrns[100].pattern: exact;
        }
        actions = {
            or13_5;
        }
        size = 256;
    }

    action or14_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_5 {
        key = {
            hdr.patrns[108].pattern: exact;
        }
        actions = {
            or14_5;
        }
        size = 256;
    }

    action or15_5(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_5 {
        key = {
            hdr.patrns[116].pattern: exact;
        }
        actions = {
            or15_5;
        }
        size = 256;
    }

    action or1_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_6 {
        key = {
            hdr.patrns[5].pattern: exact;
        }
        actions = {
            or1_6;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_6 {
        key = {
            hdr.patrns[13].pattern: exact;
        }
        actions = {
            or2_6;
        }
        size = 256;
    }

    action or3_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_6 {
        key = {
            hdr.patrns[21].pattern: exact;
        }
        actions = {
            or3_6;
        }
        size = 256;
    }

    action or4_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_6 {
        key = {
            hdr.patrns[29].pattern: exact;
        }
        actions = {
            or4_6;
        }
        size = 256;
    }

    action or5_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_6 {
        key = {
            hdr.patrns[37].pattern: exact;
        }
        actions = {
            or5_6;
        }
        size = 256;
    }

    action or6_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_6 {
        key = {
            hdr.patrns[45].pattern: exact;
        }
        actions = {
            or6_6;
        }
        size = 256;
    }

    action or7_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_6 {
        key = {
            hdr.patrns[53].pattern: exact;
        }
        actions = {
            or7_6;
        }
        size = 256;
    }

    action or8_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_6 {
        key = {
            hdr.patrns[61].pattern: exact;
        }
        actions = {
            or8_6;
        }
        size = 256;
    }

    action or9_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_6 {
        key = {
            hdr.patrns[69].pattern: exact;
        }
        actions = {
            or9_6;
        }
        size = 256;
    }

    action or10_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_6 {
        key = {
            hdr.patrns[77].pattern: exact;
        }
        actions = {
            or10_6;
        }
        size = 256;
    }

    action or11_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_6 {
        key = {
            hdr.patrns[85].pattern: exact;
        }
        actions = {
            or11_6;
        }
        size = 256;
    }

    action or12_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_6 {
        key = {
            hdr.patrns[93].pattern: exact;
        }
        actions = {
            or12_6;
        }
        size = 256;
    }

    action or13_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_6 {
        key = {
            hdr.patrns[101].pattern: exact;
        }
        actions = {
            or13_6;
        }
        size = 256;
    }

    action or14_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_6 {
        key = {
            hdr.patrns[109].pattern: exact;
        }
        actions = {
            or14_6;
        }
        size = 256;
    }

    action or15_6(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_6 {
        key = {
            hdr.patrns[117].pattern: exact;
        }
        actions = {
            or15_6;
        }
        size = 256;
    }

    action or1_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_7 {
        key = {
            hdr.patrns[6].pattern: exact;
        }
        actions = {
            or1_7;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_7 {
        key = {
            hdr.patrns[14].pattern: exact;
        }
        actions = {
            or2_7;
        }
        size = 256;
    }

    action or3_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_7 {
        key = {
            hdr.patrns[22].pattern: exact;
        }
        actions = {
            or3_7;
        }
        size = 256;
    }

    action or4_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_7 {
        key = {
            hdr.patrns[30].pattern: exact;
        }
        actions = {
            or4_7;
        }
        size = 256;
    }

    action or5_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_7 {
        key = {
            hdr.patrns[38].pattern: exact;
        }
        actions = {
            or5_7;
        }
        size = 256;
    }

    action or6_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_7 {
        key = {
            hdr.patrns[46].pattern: exact;
        }
        actions = {
            or6_7;
        }
        size = 256;
    }

    action or7_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_7 {
        key = {
            hdr.patrns[54].pattern: exact;
        }
        actions = {
            or7_7;
        }
        size = 256;
    }

    action or8_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_7 {
        key = {
            hdr.patrns[62].pattern: exact;
        }
        actions = {
            or8_7;
        }
        size = 256;
    }

    action or9_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_7 {
        key = {
            hdr.patrns[70].pattern: exact;
        }
        actions = {
            or9_7;
        }
        size = 256;
    }

    action or10_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_7 {
        key = {
            hdr.patrns[78].pattern: exact;
        }
        actions = {
            or10_7;
        }
        size = 256;
    }

    action or11_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_7 {
        key = {
            hdr.patrns[86].pattern: exact;
        }
        actions = {
            or11_7;
        }
        size = 256;
    }

    action or12_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_7 {
        key = {
            hdr.patrns[94].pattern: exact;
        }
        actions = {
            or12_7;
        }
        size = 256;
    }

    action or13_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_7 {
        key = {
            hdr.patrns[102].pattern: exact;
        }
        actions = {
            or13_7;
        }
        size = 256;
    }

    action or14_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_7 {
        key = {
            hdr.patrns[110].pattern: exact;
        }
        actions = {
            or14_7;
        }
        size = 256;
    }

    action or15_7(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_7 {
        key = {
            hdr.patrns[118].pattern: exact;
        }
        actions = {
            or15_7;
        }
        size = 256;
    }

    action or1_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1 = mask_high1 | meta.st_mask1_high1;
        meta.st_mask1_low1 = mask_low1 | meta.st_mask1_low1;
    }
    table filter_win1_8 {
        key = {
            hdr.patrns[7].pattern: exact;
        }
        actions = {
            or1_8;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1 = mask_high1 | meta.st_mask2_high1;
        meta.st_mask2_low1 = mask_low1 | meta.st_mask2_low1;
    }
    table filter_win2_8 {
        key = {
            hdr.patrns[15].pattern: exact;
        }
        actions = {
            or2_8;
        }
        size = 256;
    }

    action or3_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1 = mask_high1 | meta.st_mask3_high1;
        meta.st_mask3_low1 = mask_low1 | meta.st_mask3_low1;
    }
    table filter_win3_8 {
        key = {
            hdr.patrns[23].pattern: exact;
        }
        actions = {
            or3_8;
        }
        size = 256;
    }

    action or4_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1 = mask_high1 | meta.st_mask4_high1;
        meta.st_mask4_low1 = mask_low1 | meta.st_mask4_low1;
    }
    table filter_win4_8 {
        key = {
            hdr.patrns[31].pattern: exact;
        }
        actions = {
            or4_8;
        }
        size = 256;
    }

    action or5_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1 = mask_high1 | meta.st_mask5_high1;
        meta.st_mask5_low1 = mask_low1 | meta.st_mask5_low1;
    }
    table filter_win5_8 {
        key = {
            hdr.patrns[39].pattern: exact;
        }
        actions = {
            or5_8;
        }
        size = 256;
    }

    action or6_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1 = mask_high1 | meta.st_mask6_high1;
        meta.st_mask6_low1 = mask_low1 | meta.st_mask6_low1;
    }
    table filter_win6_8 {
        key = {
            hdr.patrns[47].pattern: exact;
        }
        actions = {
            or6_8;
        }
        size = 256;
    }

    action or7_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1 = mask_high1 | meta.st_mask7_high1;
        meta.st_mask7_low1 = mask_low1 | meta.st_mask7_low1;
    }
    table filter_win7_8 {
        key = {
            hdr.patrns[55].pattern: exact;
        }
        actions = {
            or7_8;
        }
        size = 256;
    }

    action or8_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1 = mask_high1 | meta.st_mask8_high1;
        meta.st_mask8_low1 = mask_low1 | meta.st_mask8_low1;
    }
    table filter_win8_8 {
        key = {
            hdr.patrns[63].pattern: exact;
        }
        actions = {
            or8_8;
        }
        size = 256;
    }

    action or9_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1 = mask_high1 | meta.st_mask9_high1;
        meta.st_mask9_low1 = mask_low1 | meta.st_mask9_low1;
    }
    table filter_win9_8 {
        key = {
            hdr.patrns[71].pattern: exact;
        }
        actions = {
            or9_8;
        }
        size = 256;
    }

    action or10_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1 = mask_high1 | meta.st_mask10_high1;
        meta.st_mask10_low1 = mask_low1 | meta.st_mask10_low1;
    }
    table filter_win10_8 {
        key = {
            hdr.patrns[79].pattern: exact;
        }
        actions = {
            or10_8;
        }
        size = 256;
    }

    action or11_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1 = mask_high1 | meta.st_mask11_high1;
        meta.st_mask11_low1 = mask_low1 | meta.st_mask11_low1;
    }
    table filter_win11_8 {
        key = {
            hdr.patrns[87].pattern: exact;
        }
        actions = {
            or11_8;
        }
        size = 256;
    }

    action or12_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1 = mask_high1 | meta.st_mask12_high1;
        meta.st_mask12_low1 = mask_low1 | meta.st_mask12_low1;
    }
    table filter_win12_8 {
        key = {
            hdr.patrns[95].pattern: exact;
        }
        actions = {
            or12_8;
        }
        size = 256;
    }

    action or13_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1 = mask_high1 | meta.st_mask13_high1;
        meta.st_mask13_low1 = mask_low1 | meta.st_mask13_low1;
    }
    table filter_win13_8 {
        key = {
            hdr.patrns[103].pattern: exact;
        }
        actions = {
            or13_8;
        }
        size = 256;
    }

    action or14_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1 = mask_high1 | meta.st_mask14_high1;
        meta.st_mask14_low1 = mask_low1 | meta.st_mask14_low1;
    }
    table filter_win14_8 {
        key = {
            hdr.patrns[111].pattern: exact;
        }
        actions = {
            or14_8;
        }
        size = 256;
    }

    action or15_8(bit<32> mask_low1){
        meta.st_mask15_low1 = mask_low1 | meta.st_mask15_low1;
    }
    table filter_win15_8 {
        key = {
            hdr.patrns[119].pattern: exact;
        }
        actions = {
            or15_8;
        }
        size = 256;
    }


    /**************************************************/
    /******************** stage 8 *********************/
    /**************************************************/
    @pragma stage 8
    action set_st_mask1(){
        meta.st_mask2_low1=meta.st_mask2_low1|meta.st_mask1_high1;
        // meta.st_mask2_low2=meta.st_mask2_low2|meta.st_mask1_high2;
        // meta.st_mask2_low3=meta.st_mask2_low3|meta.st_mask1_high3;
        // meta.st_mask2_low4=meta.st_mask2_low4|meta.st_mask1_high4;

        meta.st_mask3_low1=meta.st_mask3_low1|meta.st_mask2_high1;
        // meta.st_mask3_low2=meta.st_mask3_low2|meta.st_mask2_high2;
        // meta.st_mask3_low3=meta.st_mask3_low3|meta.st_mask2_high3;
        // meta.st_mask3_low4=meta.st_mask3_low4|meta.st_mask2_high4;

        meta.st_mask4_low1=meta.st_mask4_low1|meta.st_mask3_high1;
        // meta.st_mask4_low2=meta.st_mask4_low2|meta.st_mask3_high2;
        // meta.st_mask4_low3=meta.st_mask4_low3|meta.st_mask3_high3;
        // meta.st_mask4_low4=meta.st_mask4_low4|meta.st_mask3_high4;
        // meta.temp_for_st_mask5_low1=meta.st_mask4_high1[15:0];
        // meta.temp_for_st_mask5_low2=meta.st_mask4_high1[31:16];
        meta.st_mask5_low1=meta.st_mask5_low1|meta.st_mask4_high1;
        // meta.st_mask5_low2=meta.st_mask5_low2|meta.st_mask4_high2;
        // meta.st_mask5_low3=meta.st_mask5_low3|meta.st_mask4_high3;
        // meta.st_mask5_low4=meta.st_mask5_low4|meta.st_mask4_high4;

        meta.st_mask6_low1=meta.st_mask6_low1|meta.st_mask5_high1;
        // meta.st_mask6_low2=meta.st_mask6_low2|meta.st_mask5_high2;
        // meta.st_mask6_low3=meta.st_mask6_low3|meta.st_mask5_high3;
        // meta.st_mask6_low4=meta.st_mask6_low4|meta.st_mask5_high4;

        meta.st_mask7_low1=meta.st_mask7_low1|meta.st_mask6_high1;
        // meta.st_mask7_low2=meta.st_mask7_low2|meta.st_mask6_high2;
        // meta.st_mask7_low3=meta.st_mask7_low3|meta.st_mask6_high3;
        // meta.st_mask7_low4=meta.st_mask7_low4|meta.st_mask6_high4;

        meta.st_mask8_low1=meta.st_mask8_low1|meta.st_mask7_high1;
        // meta.st_mask8_low2=meta.st_mask8_low2|meta.st_mask7_high2;

        meta.st_mask9_low1=meta.st_mask9_low1|meta.st_mask8_high1;
        // meta.st_mask9_low2=meta.st_mask9_low2|meta.st_mask8_high2;

        meta.st_mask10_low1=meta.st_mask10_low1|meta.st_mask9_high1;
        // meta.st_mask10_low2=meta.st_mask10_low2|meta.st_mask9_high2;

        meta.st_mask11_low1=meta.st_mask11_low1|meta.st_mask10_high1;
        // meta.st_mask11_low2=meta.st_mask11_low2|meta.st_mask10_high2;

        meta.st_mask12_low1=meta.st_mask12_low1|meta.st_mask11_high1;
        // meta.st_mask12_low2=meta.st_mask12_low2|meta.st_mask11_high2;

        meta.st_mask13_low1=meta.st_mask13_low1|meta.st_mask12_high1;
        //meta.st_mask13_low2=meta.st_mask13_low2|meta.st_mask12_high2;

        meta.st_mask14_low1=meta.st_mask14_low1|meta.st_mask13_high1;

        meta.st_mask15_low1=meta.st_mask15_low1|meta.st_mask14_high1;

        // meta.st_mask16_low1=meta.st_mask16_low1|meta.st_mask15_high1;
        // meta.st_mask16_low2=meta.st_mask16_low2|meta.st_mask15_high2;
        // meta.st_mask16_low3=meta.st_mask16_low3|meta.st_mask15_high3;
        // meta.st_mask16_low4=meta.st_mask16_low4|meta.st_mask15_high4;

    }
    // @pragma stage 9
    // action set_st_mask2(){
    //     meta.st_mask5_low1=meta.st_mask5_low1|meta.temp_for_st_mask5_low1;
    //     meta.st_mask5_low2=meta.st_mask5_low2|meta.temp_for_st_mask5_low2;
    // }
    /**************************************************/
    /******************** stage 9 *********************/
    /**************************************************/
    action set_b1(bit<8> b){
        hdr.ipv4_option.b1 = b;
    }
    table set_map1{
        key = {
            meta.st_mask1_low1: ternary;
        }
        actions = {
            set_b1;
        }
        size=256;
    }

    action set_b2(bit<8> b){
        hdr.ipv4_option.b2 = b;
    }
    table set_map2{
        key = {
            meta.st_mask2_low1: ternary;
        }
        actions = {
            set_b2;
        }
        size=256;
    }

    action set_b3(bit<8> b){
        hdr.ipv4_option.b3 = b;
    }
    table set_map3{
        key = {
            meta.st_mask3_low1: ternary;
        }
        actions = {
            set_b3;
        }
        size=256;
    }

    action set_b4(bit<8> b){
        hdr.ipv4_option.b4 = b;
    }
    table set_map4{
        key = {
            meta.st_mask4_low1: ternary;
        }
        actions = {
            set_b4;
        }
        size=256;
    }

    action set_b5(bit<8> b){
        hdr.ipv4_option.b5 = b;
    }
    table set_map5{
        key = {
            meta.st_mask5_low1: ternary;
        }
        actions = {
            set_b5;
        }
        size=256;
    }

    action set_b6(bit<8> b){
        hdr.ipv4_option.b6 = b;
    }
    table set_map6{
        key = {
            meta.st_mask6_low1: ternary;
        }
        actions = {
            set_b6;
        }
        size=256;
    }

    action set_b7(bit<8> b){
        hdr.ipv4_option.b7 = b;
    }
    table set_map7{
        key = {
            meta.st_mask7_low1: ternary;
        }
        actions = {
            set_b7;
        }
        size=256;
    }

    action set_b8(bit<8> b){
        hdr.ipv4_option.b8 = b;
    }
    table set_map8{
        key = {
            meta.st_mask8_low1: ternary;
        }
        actions = {
            set_b8;
        }
        size=256;
    }

    action set_b9(bit<8> b){
        hdr.ipv4_option.b9 = b;
    }
    table set_map9{
        key = {
            meta.st_mask9_low1: ternary;
        }
        actions = {
            set_b9;
        }
        size=256;
    }

    action set_b10(bit<8> b){
        hdr.ipv4_option.b10 = b;
    }
    table set_map10{
        key = {
            meta.st_mask10_low1: ternary;
        }
        actions = {
            set_b10;
        }
        size=256;
    }

    action set_b11(bit<8> b){
        hdr.ipv4_option.b11 = b;
    }
    table set_map11{
        key = {
            meta.st_mask11_low1: ternary;
        }
        actions = {
            set_b11;
        }
        size=256;
    }

    action set_b12(bit<8> b){
        hdr.ipv4_option.b12 = b;
    }
    table set_map12{
        key = {
            meta.st_mask12_low1: ternary;
        }
        actions = {
            set_b12;
        }
        size=256;
    }

    action set_b13(bit<8> b){
        hdr.ipv4_option.b13 = b;
    }
    table set_map13{
        key = {
            meta.st_mask13_low1: ternary;
        }
        actions = {
            set_b13;
        }
        size=256;
    }

    action set_b14(bit<8> b){
        hdr.ipv4_option.b14 = b;
    }
    table set_map14{
        key = {
            meta.st_mask14_low1: ternary;
        }
        actions = {
            set_b14;
        }
        size=256;
    }

    action set_b15(bit<8> b){
        hdr.ipv4_option.b15 = b;
    }
    table set_map15{
        key = {
            meta.st_mask15_low1: ternary;
        }
        actions = {
            set_b15;
        }
        size=256;
    }



    action recirculate(bit<9> recircle_port) {
        standard_metadata.egress_spec = recircle_port;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4_option.recircle_time=0;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    @pragma stage 11
    table need_recircle{
        key={
            hdr.ipv4_option.b1: ternary;
            hdr.ipv4_option.b2: ternary;
            hdr.ipv4_option.b3: ternary;
            hdr.ipv4_option.b4: ternary;
            hdr.ipv4_option.b5: ternary;
            hdr.ipv4_option.b6: ternary;
            hdr.ipv4_option.b7: ternary;
            hdr.ipv4_option.b8: ternary;
            hdr.ipv4_option.b9: ternary;
            hdr.ipv4_option.b10: ternary;
            hdr.ipv4_option.b11: ternary;
            hdr.ipv4_option.b12: ternary;
            hdr.ipv4_option.b13: ternary;
            hdr.ipv4_option.b14: ternary;
            hdr.ipv4_option.b15: ternary;
            standard_metadata.ingress_port: ternary;
        }
        actions={
            recirculate;
            send;

        }
        const entries={
            // all 0 means no candidata position,thus no neeed to recirculate
            (0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,1&&&0b111111111):send(3);
            // (0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,48&&&0b111111111):send(32);
        }
        size=3;
        // const default_action=recirculate(0);
        // const default_action=send(3);
    }




    apply {
        // send(64);
        if(hdr.ipv4_option.padding == 1){
            first_filter_ingress_time_reg.write(0,1);
        }
        // else if(hdr.ipv4_option.padding == 2){
        else if(hdr.ipv4.totalLen == 168){
            last_filter_ingress_time_reg.write(0,2);
        }
        //stage 0
        filter_win1_1.apply();
        filter_win2_1.apply();
        filter_win3_1.apply();
        filter_win4_1.apply();
        filter_win5_1.apply();
        filter_win6_1.apply();
        filter_win7_1.apply();
        filter_win8_1.apply();
        filter_win9_1.apply();
        filter_win10_1.apply();
        filter_win11_1.apply();
        filter_win12_1.apply();
        filter_win13_1.apply();
        filter_win14_1.apply();
        filter_win15_1.apply();
        // filter_win16_1.apply();

        //stage 1
        filter_win1_2.apply();
        filter_win2_2.apply();
        filter_win3_2.apply();
        filter_win4_2.apply();
        filter_win5_2.apply();
        filter_win6_2.apply();
        filter_win7_2.apply();
        filter_win8_2.apply();
        filter_win9_2.apply();
        filter_win10_2.apply();
        filter_win11_2.apply();
        filter_win12_2.apply();
        filter_win13_2.apply();
        filter_win14_2.apply();
        filter_win15_2.apply();
        // filter_win16_2.apply();

        //stage 2
        filter_win1_3.apply();
        filter_win2_3.apply();
        filter_win3_3.apply();
        filter_win4_3.apply();
        filter_win5_3.apply();
        filter_win6_3.apply();
        filter_win7_3.apply();
        filter_win8_3.apply();
        filter_win9_3.apply();
        filter_win10_3.apply();
        filter_win11_3.apply();
        filter_win12_3.apply();
        filter_win13_3.apply();
        filter_win14_3.apply();
        filter_win15_3.apply();
        // filter_win16_3.apply();

        //stage 3
        filter_win1_4.apply();
        filter_win2_4.apply();
        filter_win3_4.apply();
        filter_win4_4.apply();
        filter_win5_4.apply();
        filter_win6_4.apply();
        filter_win7_4.apply();
        filter_win8_4.apply();
        filter_win9_4.apply();
        filter_win10_4.apply();
        filter_win11_4.apply();
        filter_win12_4.apply();
        filter_win13_4.apply();
        filter_win14_4.apply();
        filter_win15_4.apply();
        // filter_win16_4.apply();

        //stage 4
        filter_win1_5.apply();
        filter_win2_5.apply();
        filter_win3_5.apply();
        filter_win4_5.apply();
        filter_win5_5.apply();
        filter_win6_5.apply();
        filter_win7_5.apply();
        filter_win8_5.apply();
        filter_win9_5.apply();
        filter_win10_5.apply();
        filter_win11_5.apply();
        filter_win12_5.apply();
        filter_win13_5.apply();
        filter_win14_5.apply();
        filter_win15_5.apply();
        // filter_win16_5.apply();

        //stage 5
        filter_win1_6.apply();
        filter_win2_6.apply();
        filter_win3_6.apply();
        filter_win4_6.apply();
        filter_win5_6.apply();
        filter_win6_6.apply();
        filter_win7_6.apply();
        filter_win8_6.apply();
        filter_win9_6.apply();
        filter_win10_6.apply();
        filter_win11_6.apply();
        filter_win12_6.apply();
        filter_win13_6.apply();
        filter_win14_6.apply();
        filter_win15_6.apply();
        // filter_win16_6.apply();

        //stage 6
        filter_win1_7.apply();
        filter_win2_7.apply();
        filter_win3_7.apply();
        filter_win4_7.apply();
        filter_win5_7.apply();
        filter_win6_7.apply();
        filter_win7_7.apply();
        filter_win8_7.apply();
        filter_win9_7.apply();
        filter_win10_7.apply();
        filter_win11_7.apply();
        filter_win12_7.apply();
        filter_win13_7.apply();
        filter_win14_7.apply();
        filter_win15_7.apply();
        // filter_win16_7.apply();

        //stage 7
        filter_win1_8.apply();
        filter_win2_8.apply();
        filter_win3_8.apply();
        filter_win4_8.apply();
        filter_win5_8.apply();
        filter_win6_8.apply();
        filter_win7_8.apply();
        filter_win8_8.apply();
        filter_win9_8.apply();
        filter_win10_8.apply();
        filter_win11_8.apply();
        filter_win12_8.apply();
        filter_win13_8.apply();
        filter_win14_8.apply();
        filter_win15_8.apply();
        // filter_win16_8.apply();

        //stage 8
        set_st_mask1();
        set_map1.apply();
        // set_b1(0x55);

        //stage 9
        set_map2.apply();
        // set_b2(0x55);
        set_map3.apply();
        // set_b3(0x55);
        set_map4.apply();
        // set_b4(0x55);
        set_map5.apply();
        // set_b5(0x55);
        set_map6.apply();
        // set_b6(0x55);
        set_map7.apply();
        // set_b7(0x55);
        set_map8.apply();
        // set_b8(0x55);
        set_map9.apply();
        // set_b9(0x55);
        //stage 10
        set_map10.apply();
        // set_b10(0x55);
        set_map11.apply();
        // set_b11(0x55);
        set_map12.apply();
        // set_b12(0x55);
        set_map13.apply();
        // set_b13(0x55);
        set_map14.apply();
        // set_b14(0x55);
        set_map15.apply();
        // set_b15(0x55);
        //stage 11
        if(hdr.ipv4.isValid()){
            need_recircle.apply();
        }
        // if (hdr.ipv4.isValid()) {
        //     ipv4_lpm.apply();
        // }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout my_ingress_headers_for_filter_t hdr,
                 inout my_ingress_metadata_for_filter_t meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if (hdr.ipv4.isValid())
        {
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(inout my_ingress_headers_for_filter_t  hdr, inout my_ingress_metadata_for_filter_t meta) {
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

control DeparserImpl(packet_out packet, in my_ingress_headers_for_filter_t hdr) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(ParserImpl(), verifyChecksum(), pattern_prefilter(), MyEgress(), computeChecksum(), DeparserImpl()) main;