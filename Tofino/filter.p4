/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "headers.p4"



    /***********************  P A R S E R  **************************/
parser IngressParser_filter(packet_in          pkt,
    /* User */
    out my_ingress_headers_for_filter_t        hdr,
    out my_ingress_metadata_for_filter_t       meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t           ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_ipv4_option;
    }

    state parse_ipv4_option {
        pkt.extract(hdr.ipv4_option);
        transition parse_udp;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_pattern;
    }

    state parse_pattern{
        pkt.extract(hdr.patrns);
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

        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress_filter(
    /* User */
    inout my_ingress_headers_for_filter_t            hdr,
    inout my_ingress_metadata_for_filter_t           meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    Register<bit<64>,bit<1>>(1) first_filter_ingress_time_reg;

    RegisterAction<bit<64>, bit<1>, bit<64>>(first_filter_ingress_time_reg) first_filter_ingress_time_reg_write = {
        void apply(inout bit<64> value){
            value  = (bit<64>)ig_prsr_md.global_tstamp;
        }
    };


    Register<bit<64>,bit<1>>(1) last_filter_ingress_time_reg;

    RegisterAction<bit<64>, bit<1>, bit<64>>(last_filter_ingress_time_reg) last_filter_ingress_time_reg_write = {
        void apply(inout bit<64> value){
            value  = (bit<64>)ig_prsr_md.global_tstamp;
        }
    };
    /**************************************************/
    /******************** stage 0 *********************/
    /**************************************************/

    //since the shortest pattern is 1B,so the initial st_mask=0x0000000000000000
    //thus we simplify the caculation process as st_mask=sh_mask
    action or1_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=mask_high1;
        meta.st_mask1_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win1_1 {
        key = {
            hdr.patrns.p1: exact;
        }
        actions = {
            or1_1;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();

    }

    action or2_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=mask_high1;
        meta.st_mask2_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win2_1 {
        key = {
            hdr.patrns.p9: exact;
        }
        actions = {
            or2_1;
        }
        size = 256;

    }

    action or3_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=mask_high1;

        meta.st_mask3_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win3_1 {
        key = {
            hdr.patrns.p17: exact;
        }
        actions = {
            or3_1;
        }
        size = 256;

    }

    action or4_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=mask_high1;

        meta.st_mask4_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win4_1 {
        key = {
            hdr.patrns.p25: exact;
        }
        actions = {
            or4_1;
        }
        size = 256;

    }

    action or5_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=mask_high1;

        meta.st_mask5_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win5_1 {
        key = {
            hdr.patrns.p33: exact;
        }
        actions = {
            or5_1;
        }
        size = 256;

    }

    action or6_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=mask_high1;

        meta.st_mask6_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win6_1 {
        key = {
            hdr.patrns.p41: exact;
        }
        actions = {
            or6_1;
        }
        size = 256;

    }

    action or7_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=mask_high1;
        meta.st_mask7_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win7_1 {
        key = {
            hdr.patrns.p49: exact;
        }
        actions = {
            or7_1;
        }
        size = 256;


    }

    action or8_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=mask_high1;

        meta.st_mask8_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win8_1 {
        key = {
            hdr.patrns.p57: exact;
        }
        actions = {
            or8_1;
        }
        size = 256;

    }

    action or9_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=mask_high1;
        meta.st_mask9_low1=mask_low1;
    }
    @pragma stage 0
    table filter_win9_1 {
        key = {
            hdr.patrns.p65: exact;
        }
        actions = {
            or9_1;
        }
        size = 256;
    }

    action or10_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=mask_high1;
        meta.st_mask10_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win10_1 {
        key = {
            hdr.patrns.p73: exact;
        }
        actions = {
            or10_1;
        }
        size = 256;
    }

    action or11_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=mask_high1;
        meta.st_mask11_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win11_1 {
        key = {
            hdr.patrns.p81: exact;
        }
        actions = {
            or11_1;
        }
        size = 256;
    }

    action or12_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=mask_high1;
        meta.st_mask12_low1=mask_low1;
    }
    @pragma stage 0
    table filter_win12_1 {
        key = {
            hdr.patrns.p89: exact;
        }
        actions = {
            or12_1;
        }
        size = 256;
    }

    action or13_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=mask_high1;
        meta.st_mask13_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win13_1 {
        key = {
            hdr.patrns.p97: exact;
        }
        actions = {
            or13_1;
        }
        size = 256;

    }

    action or14_1(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=mask_high1;
        meta.st_mask14_low1=mask_low1;

    }
    @pragma stage 0
    table filter_win14_1 {
        key = {
            hdr.patrns.p105: exact;
        }
        actions = {
            or14_1;
        }
        size = 256;
    }

    action or15_1(bit<32> mask_low1){
        meta.st_mask15_low1=mask_low1;
    }
    @pragma stage 0
    table filter_win15_1 {
        key = {
            hdr.patrns.p113: exact;
        }
        actions = {
            or15_1;
        }
        size = 256;
    }



    /**************************************************/
    /******************** stage 1 *********************/
    /**************************************************/
    action or1_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;

        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win1_2 {
        key = {
            hdr.patrns.p2: exact;
        }
        actions = {
            or1_2;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;
        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win2_2 {
        key = {
            hdr.patrns.p10: exact;
        }
        actions = {
            or2_2;
        }
        size = 256;

    }

    action or3_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;
        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win3_2 {
        key = {
            hdr.patrns.p18: exact;
        }
        actions = {
            or3_2;
        }
        size = 256;

    }

    action or4_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;

        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win4_2 {
        key = {
            hdr.patrns.p26: exact;
        }
        actions = {
            or4_2;
        }
        size = 256;

    }

    action or5_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;

        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win5_2 {
        key = {
            hdr.patrns.p34: exact;
        }
        actions = {
            or5_2;
        }
        size = 256;

    }

    action or6_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;

        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win6_2 {
        key = {
            hdr.patrns.p42: exact;
        }
        actions = {
            or6_2;
        }
        size = 256;

    }

    action or7_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;
        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win7_2 {
        key = {
            hdr.patrns.p50: exact;
        }
        actions = {
            or7_2;
        }
        size = 256;

    }

    action or8_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win8_2 {
        key = {
            hdr.patrns.p58: exact;
        }
        actions = {
            or8_2;
        }
        size = 256;

    }

    action or9_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;
        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win9_2 {
        key = {
            hdr.patrns.p66: exact;
        }
        actions = {
            or9_2;
        }
        size = 256;

    }

    action or10_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win10_2 {
        key = {
            hdr.patrns.p74: exact;
        }
        actions = {
            or10_2;
        }
        size = 256;
    }

    action or11_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win11_2 {
        key = {
            hdr.patrns.p82: exact;
        }
        actions = {
            or11_2;
        }
        size = 256;

    }

    action or12_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;

    }
    @pragma stage 1
    table filter_win12_2 {
        key = {
            hdr.patrns.p90: exact;
        }
        actions = {
            or12_2;
        }
        size = 256;

    }

    action or13_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win13_2 {
        key = {
            hdr.patrns.p98: exact;
        }
        actions = {
            or13_2;
        }
        size = 256;

    }

    action or14_2(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win14_2 {
        key = {
            hdr.patrns.p106: exact;
        }
        actions = {
            or14_2;
        }
        size = 256;

    }

    action or15_2(bit<32> mask_low1){

        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 1
    table filter_win15_2 {
        key = {
            hdr.patrns.p114: exact;
        }
        actions = {
            or15_2;
        }
        size = 256;

    }


    /**************************************************/
    /******************** stage 2 *********************/
    /**************************************************/
    action or1_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;

        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win1_3 {
        key = {
            hdr.patrns.p3: exact;
        }
        actions = {
            or1_3;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;
        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win2_3 {
        key = {
            hdr.patrns.p11: exact;
        }
        actions = {
            or2_3;
        }
        size = 256;

    }

    action or3_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;

        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win3_3 {
        key = {
            hdr.patrns.p19: exact;
        }
        actions = {
            or3_3;
        }
        size = 256;

    }

    action or4_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;

        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win4_3 {
        key = {
            hdr.patrns.p27: exact;
        }
        actions = {
            or4_3;
        }
        size = 256;

    }

    action or5_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;

        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win5_3 {
        key = {
            hdr.patrns.p35: exact;
        }
        actions = {
            or5_3;
        }
        size = 256;

    }

    action or6_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;

        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win6_3 {
        key = {
            hdr.patrns.p43: exact;
        }
        actions = {
            or6_3;
        }
        size = 256;

    }

    action or7_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;
        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win7_3 {
        key = {
            hdr.patrns.p51: exact;
        }
        actions = {
            or7_3;
        }
        size = 256;

    }

    action or8_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
    }
    @pragma stage 2
    table filter_win8_3 {
        key = {
            hdr.patrns.p59: exact;
        }
        actions = {
            or8_3;
        }
        size = 256;

    }

    action or9_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;
        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;
    }
    @pragma stage 2
    table filter_win9_3 {
        key = {
            hdr.patrns.p67: exact;
        }
        actions = {
            or9_3;
        }
        size = 256;
    }

    action or10_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;
    }
    @pragma stage 2
    table filter_win10_3 {
        key = {
            hdr.patrns.p75: exact;
        }
        actions = {
            or10_3;
        }
        size = 256;

    }

    action or11_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;
    }
    @pragma stage 2
    table filter_win11_3 {
        key = {
            hdr.patrns.p83: exact;
        }
        actions = {
            or11_3;
        }
        size = 256;

    }

    action or12_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;

    }
    @pragma stage 2
    table filter_win12_3 {
        key = {
            hdr.patrns.p91: exact;
        }
        actions = {
            or12_3;
        }
        size = 256;

    }

    action or13_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;
        //meta.st_mask13_low2=meta.st_mask13_low2|mask_low2;
    }
    @pragma stage 2
    table filter_win13_3 {
        key = {
            hdr.patrns.p99: exact;
        }
        actions = {
            or13_3;
        }
        size = 256;

    }

    action or14_3(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 2
    table filter_win14_3 {
        key = {
            hdr.patrns.p107: exact;
        }
        actions = {
            or14_3;
        }
        size = 256;

    }

    action or15_3(bit<32> mask_low1){

        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 2
    table filter_win15_3 {
        key = {
            hdr.patrns.p115: exact;
        }
        actions = {
            or15_3;
        }
        size = 256;

    }


    /**************************************************/
    /******************** stage 3 *********************/
    /**************************************************/
    action or1_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;

        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win1_4 {
        key = {
            hdr.patrns.p4: exact;
        }
        actions = {
            or1_4;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();

    }
    action or2_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;

        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win2_4 {
        key = {
            hdr.patrns.p12: exact;
        }
        actions = {
            or2_4;
        }
        size = 256;

    }

    action or3_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;

        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win3_4 {
        key = {
            hdr.patrns.p20: exact;
        }
        actions = {
            or3_4;
        }
        size = 256;

    }

    action or4_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;

        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win4_4 {
        key = {
            hdr.patrns.p28: exact;
        }
        actions = {
            or4_4;
        }
        size = 256;

    }

    action or5_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;

        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win5_4 {
        key = {
            hdr.patrns.p36: exact;
        }
        actions = {
            or5_4;
        }
        size = 256;

    }

    action or6_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;

        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win6_4 {
        key = {
            hdr.patrns.p44: exact;
        }
        actions = {
            or6_4;
        }
        size = 256;

    }

    action or7_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;

        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win7_4 {
        key = {
            hdr.patrns.p52: exact;
        }
        actions = {
            or7_4;
        }
        size = 256;

    }

    action or8_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        // meta.st_mask8_high2=meta.st_mask8_high2|mask_high2;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
        // meta.st_mask8_low2=meta.st_mask8_low2|mask_low2;
    }
    @pragma stage 3
    table filter_win8_4 {
        key = {
            hdr.patrns.p60: exact;
        }
        actions = {
            or8_4;
        }
        size = 256;

    }

    action or9_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;

        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win9_4 {
        key = {
            hdr.patrns.p68: exact;
        }
        actions = {
            or9_4;
        }
        size = 256;
    }

    action or10_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win10_4 {
        key = {
            hdr.patrns.p76: exact;
        }
        actions = {
            or10_4;
        }
        size = 256;

    }

    action or11_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win11_4 {
        key = {
            hdr.patrns.p84: exact;
        }
        actions = {
            or11_4;
        }
        size = 256;
    }

    action or12_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win12_4 {
        key = {
            hdr.patrns.p92: exact;
        }
        actions = {
            or12_4;
        }
        size = 256;

    }

    action or13_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;

    }
    @pragma stage 3
    table filter_win13_4 {
        key = {
            hdr.patrns.p100: exact;
        }
        actions = {
            or13_4;
        }
        size = 256;

    }

    action or14_4(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 3
    table filter_win14_4 {
        key = {
            hdr.patrns.p108: exact;
        }
        actions = {
            or14_4;
        }
        size = 256;

    }

    action or15_4(bit<32> mask_low1){

        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 3
    table filter_win15_4 {
        key = {
            hdr.patrns.p116: exact;
        }
        actions = {
            or15_4;
        }
        size = 256;

    }


    /**************************************************/
    /******************** stage 4 *********************/
    /**************************************************/
    action or1_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;

        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;

    }
    @pragma stage 4
    table filter_win1_5 {
        key = {
            hdr.patrns.p5: exact;
        }
        actions = {
            or1_5;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }

    action or2_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;

        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;

    }
    @pragma stage 4
    table filter_win2_5 {
        key = {
            hdr.patrns.p13: exact;
        }
        actions = {
            or2_5;
        }
        size = 256;

    }

    action or3_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;

        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;

    }
    @pragma stage 4
    table filter_win3_5 {
        key = {
            hdr.patrns.p21: exact;
        }
        actions = {
            or3_5;
        }
        size = 256;

    }

    action or4_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;

        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;

    }
    @pragma stage 4
    table filter_win4_5 {
        key = {
            hdr.patrns.p29: exact;
        }
        actions = {
            or4_5;
        }
        size = 256;

    }

     action or5_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;
        // meta.st_mask5_high2=meta.st_mask5_high2|mask_high2;
        // meta.st_mask5_high3=meta.st_mask5_high3|mask_high3;
        // meta.st_mask5_high4=meta.st_mask5_high4|mask_high4;
        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;
        // meta.st_mask5_low2=meta.st_mask5_low2|mask_low2;
        // meta.st_mask5_low3=meta.st_mask5_low3|mask_low3;
        // meta.st_mask5_low4=meta.st_mask5_low4|mask_low4;
    }
    @pragma stage 4
    table filter_win5_5 {
        key = {
            hdr.patrns.p37: exact;
        }
        actions = {
            or5_5;
        }
        size = 256;

    }

    action or6_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;
        // meta.st_mask6_high2=meta.st_mask6_high2|mask_high2;
        // meta.st_mask6_high3=meta.st_mask6_high3|mask_high3;
        // meta.st_mask6_high4=meta.st_mask6_high4|mask_high4;
        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;
        // meta.st_mask6_low2=meta.st_mask6_low2|mask_low2;
        // meta.st_mask6_low3=meta.st_mask6_low3|mask_low3;
        // meta.st_mask6_low4=meta.st_mask6_low4|mask_low4;
    }
    @pragma stage 4
    table filter_win6_5 {
        key = {
            hdr.patrns.p45: exact;
        }
        actions = {
            or6_5;
        }
        size = 256;

    }

    action or7_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;
        // meta.st_mask7_high2=meta.st_mask7_high2|mask_high2;
        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;
        // meta.st_mask7_low2=meta.st_mask7_low2|mask_low2;
        // meta.st_mask7_low3=meta.st_mask7_low3|mask_low3;
        // meta.st_mask7_low4=meta.st_mask7_low4|mask_low4;
    }
    @pragma stage 4
    table filter_win7_5 {
        key = {
            hdr.patrns.p53: exact;
        }
        actions = {
            or7_5;
        }
        size = 256;

    }

    action or8_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        // meta.st_mask8_high2=meta.st_mask8_high2|mask_high2;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
        // meta.st_mask8_low2=meta.st_mask8_low2|mask_low2;
    }
    @pragma stage 4
    table filter_win8_5 {
        key = {
            hdr.patrns.p61: exact;
        }
        actions = {
            or8_5;
        }
        size = 256;

    }

    action or9_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;
        // meta.st_mask9_high2=meta.st_mask9_high2|mask_high2;
        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;
        // meta.st_mask9_low2=meta.st_mask9_low2|mask_low2;
    }
    @pragma stage 4
    table filter_win9_5 {
        key = {
            hdr.patrns.p69: exact;
        }
        actions = {
            or9_5;
        }
        size = 256;

    }

    action or10_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        // meta.st_mask10_high2=meta.st_mask10_high2|mask_high2;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;
        // meta.st_mask10_low2=meta.st_mask10_low2|mask_low2;
    }
    @pragma stage 4
    table filter_win10_5 {
        key = {
            hdr.patrns.p77: exact;
        }
        actions = {
            or10_5;
        }
        size = 256;

    }

    action or11_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        // meta.st_mask11_high2=meta.st_mask11_high2|mask_high2;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;
        // meta.st_mask11_low2=meta.st_mask11_low2|mask_low2;
    }
    @pragma stage 4
    table filter_win11_5 {
        key = {
            hdr.patrns.p85: exact;
        }
        actions = {
            or11_5;
        }
        size = 256;

    }

    action or12_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        //meta.st_mask12_high2=meta.st_mask12_high2|mask_high2;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;
        // meta.st_mask12_low2=meta.st_mask12_low2|mask_low2;
    }
    @pragma stage 4
    table filter_win12_5 {
        key = {
            hdr.patrns.p93: exact;
        }
        actions = {
            or12_5;
        }
        size = 256;

    }

    action or13_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;
        //meta.st_mask13_low2=meta.st_mask13_low2|mask_low2;
    }
    @pragma stage 4
    table filter_win13_5 {
        key = {
            hdr.patrns.p101: exact;
        }
        actions = {
            or13_5;
        }
        size = 256;

    }

    action or14_5(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 4
    table filter_win14_5 {
        key = {
            hdr.patrns.p109: exact;
        }
        actions = {
            or14_5;
        }
        size = 256;

    }

    action or15_5(bit<32> mask_low1){
        // meta.st_mask15_high1=meta.st_mask15_high1|mask_high1;
        // meta.st_mask15_high2=meta.st_mask15_high2|mask_high2;
        // meta.st_mask15_high3=meta.st_mask15_high3|mask_high3;
        // meta.st_mask15_high4=meta.st_mask15_high4|mask_high4;
        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 4
    table filter_win15_5 {
        key = {
            hdr.patrns.p117: exact;
        }
        actions = {
            or15_5;
        }
        size = 256;

    }

    // action or16_5(bit<8> mask_low1,bit<8> mask_low2,bit<8> mask_low3,bit<8> mask_low4){
    //     // meta.st_mask16_low1=meta.st_mask16_low1|mask_low1;
    //     // meta.st_mask16_low2=meta.st_mask16_low2|mask_low2;
    //     // meta.st_mask16_low3=meta.st_mask16_low3|mask_low3;
    //     // meta.st_mask16_low4=meta.st_mask16_low4|mask_low4;
    // }
    // @pragma stage 4
    // table filter_win16_5 {
    //     key = {
    //         hdr.patrns.p125: exact;
    //     }
    //     actions = {
    //         or16_5;
    //     }
    //     size = 256;

    // }
    /**************************************************/
    /******************** stage 5 *********************/
    /**************************************************/
    action or1_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;
        // meta.st_mask1_high2=meta.st_mask1_high2|mask_high2;
        // meta.st_mask1_high3=meta.st_mask1_high3|mask_high3;
        // meta.st_mask1_high4=meta.st_mask1_high4|mask_high4;
        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;
        // meta.st_mask1_low2=meta.st_mask1_low2|mask_low2;
        // meta.st_mask1_low3=meta.st_mask1_low3|mask_low4;
        // meta.st_mask1_low4=meta.st_mask1_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win1_6 {
        key = {
            hdr.patrns.p6: exact;
        }
        actions = {
            or1_6;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();

    }

    action or2_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;
        // meta.st_mask2_high2=meta.st_mask2_high2|mask_high2;
        // meta.st_mask2_high3=meta.st_mask2_high3|mask_high3;
        // meta.st_mask2_high4=meta.st_mask2_high4|mask_high4;
        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;
        // meta.st_mask2_low2=meta.st_mask2_low2|mask_low2;
        // meta.st_mask2_low3=meta.st_mask2_low3|mask_low3;
        // meta.st_mask2_low4=meta.st_mask2_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win2_6 {
        key = {
            hdr.patrns.p14: exact;
        }
        actions = {
            or2_6;
        }
        size = 256;

    }

    action or3_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;
        // meta.st_mask3_high2=meta.st_mask3_high2|mask_high2;
        // meta.st_mask3_high3=meta.st_mask3_high3|mask_high3;
        // meta.st_mask3_high4=meta.st_mask3_high4|mask_high4;
        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;
        // meta.st_mask3_low2=meta.st_mask3_low2|mask_low2;
        // meta.st_mask3_low3=meta.st_mask3_low3|mask_low3;
        // meta.st_mask3_low4=meta.st_mask3_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win3_6 {
        key = {
            hdr.patrns.p22: exact;
        }
        actions = {
            or3_6;
        }
        size = 256;

    }

    action or4_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;
        // meta.st_mask4_high2=meta.st_mask4_high2|mask_high2;
        // meta.st_mask4_high3=meta.st_mask4_high3|mask_high3;
        // meta.st_mask4_high4=meta.st_mask4_high4|mask_high4;
        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;
        // meta.st_mask4_low2=meta.st_mask4_low2|mask_low2;
        // meta.st_mask4_low3=meta.st_mask4_low3|mask_low3;
        // meta.st_mask4_low4=meta.st_mask4_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win4_6 {
        key = {
            hdr.patrns.p30: exact;
        }
        actions = {
            or4_6;
        }
        size = 256;

    }

    action or5_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;
        // meta.st_mask5_high2=meta.st_mask5_high2|mask_high2;
        // meta.st_mask5_high3=meta.st_mask5_high3|mask_high3;
        // meta.st_mask5_high4=meta.st_mask5_high4|mask_high4;
        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;
        // meta.st_mask5_low2=meta.st_mask5_low2|mask_low2;
        // meta.st_mask5_low3=meta.st_mask5_low3|mask_low3;
        // meta.st_mask5_low4=meta.st_mask5_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win5_6 {
        key = {
            hdr.patrns.p38: exact;
        }
        actions = {
            or5_6;
        }
        size = 256;

    }

    action or6_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;
        // meta.st_mask6_high2=meta.st_mask6_high2|mask_high2;
        // meta.st_mask6_high3=meta.st_mask6_high3|mask_high3;
        // meta.st_mask6_high4=meta.st_mask6_high4|mask_high4;
        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;
        // meta.st_mask6_low2=meta.st_mask6_low2|mask_low2;
        // meta.st_mask6_low3=meta.st_mask6_low3|mask_low3;
        // meta.st_mask6_low4=meta.st_mask6_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win6_6 {
        key = {
            hdr.patrns.p46: exact;
        }
        actions = {
            or6_6;
        }
        size = 256;

    }

    action or7_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;
        // meta.st_mask7_high2=meta.st_mask7_high2|mask_high2;
        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;
        // meta.st_mask7_low2=meta.st_mask7_low2|mask_low2;
        // meta.st_mask7_low3=meta.st_mask7_low3|mask_low3;
        // meta.st_mask7_low4=meta.st_mask7_low4|mask_low4;
    }
    @pragma stage 5
    table filter_win7_6 {
        key = {
            hdr.patrns.p54: exact;
        }
        actions = {
            or7_6;
        }
        size = 256;

    }

    action or8_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        // meta.st_mask8_high2=meta.st_mask8_high2|mask_high2;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
        // meta.st_mask8_low2=meta.st_mask8_low2|mask_low2;
    }
    @pragma stage 5
    table filter_win8_6 {
        key = {
            hdr.patrns.p62: exact;
        }
        actions = {
            or8_6;
        }
        size = 256;

    }

    action or9_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;
        // meta.st_mask9_high2=meta.st_mask9_high2|mask_high2;
        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;
        // meta.st_mask9_low2=meta.st_mask9_low2|mask_low2;
    }
    @pragma stage 5
    table filter_win9_6 {
        key = {
            hdr.patrns.p70: exact;
        }
        actions = {
            or9_6;
        }
        size = 256;

    }

    action or10_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        // meta.st_mask10_high2=meta.st_mask10_high2|mask_high2;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;
        // meta.st_mask10_low2=meta.st_mask10_low2|mask_low2;
    }
    @pragma stage 5
    table filter_win10_6 {
        key = {
            hdr.patrns.p78: exact;
        }
        actions = {
            or10_6;
        }
        size = 256;

    }

    action or11_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        // meta.st_mask11_high2=meta.st_mask11_high2|mask_high2;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;
        // meta.st_mask11_low2=meta.st_mask11_low2|mask_low2;
    }
    @pragma stage 5
    table filter_win11_6 {
        key = {
            hdr.patrns.p86: exact;
        }
        actions = {
            or11_6;
        }
        size = 256;

    }

    action or12_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        //meta.st_mask12_high2=meta.st_mask12_high2|mask_high2;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;
        // meta.st_mask12_low2=meta.st_mask12_low2|mask_low2;
    }
    @pragma stage 5
    table filter_win12_6 {
        key = {
            hdr.patrns.p94: exact;
        }
        actions = {
            or12_6;
        }
        size = 256;

    }

    action or13_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;
        //meta.st_mask13_low2=meta.st_mask13_low2|mask_low2;
    }
    @pragma stage 5
    table filter_win13_6 {
        key = {
            hdr.patrns.p102: exact;
        }
        actions = {
            or13_6;
        }
        size = 256;

    }

    action or14_6(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 5
    table filter_win14_6 {
        key = {
            hdr.patrns.p110: exact;
        }
        actions = {
            or14_6;
        }
        size = 256;

    }

    action or15_6(bit<32> mask_low1){
        // meta.st_mask15_high1=meta.st_mask15_high1|mask_high1;
        // meta.st_mask15_high2=meta.st_mask15_high2|mask_high2;
        // meta.st_mask15_high3=meta.st_mask15_high3|mask_high3;
        // meta.st_mask15_high4=meta.st_mask15_high4|mask_high4;
        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 5
    table filter_win15_6 {
        key = {
            hdr.patrns.p118: exact;
        }
        actions = {
            or15_6;
        }
        size = 256;
    }
    // action or16_6(bit<8> mask_low1,bit<8> mask_low2,bit<8> mask_low3,bit<8> mask_low4){
    //     // meta.st_mask16_low1=meta.st_mask16_low1|mask_low1;
    //     // meta.st_mask16_low2=meta.st_mask16_low2|mask_low2;
    //     // meta.st_mask16_low3=meta.st_mask16_low3|mask_low3;
    //     // meta.st_mask16_low4=meta.st_mask16_low4|mask_low4;
    // }
    // @pragma stage 5
    // table filter_win16_6 {
    //     key = {
    //         hdr.patrns.p126: exact;
    //     }
    //     actions = {
    //         or16_6;
    //     }
    //     size = 256;

    // }
    /**************************************************/
    /******************** stage 6 *********************/
    /**************************************************/
    action or1_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;
        // meta.st_mask1_high2=meta.st_mask1_high2|mask_high2;
        // meta.st_mask1_high3=meta.st_mask1_high3|mask_high3;
        // meta.st_mask1_high4=meta.st_mask1_high4|mask_high4;
        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;
        // meta.st_mask1_low2=meta.st_mask1_low2|mask_low2;
        // meta.st_mask1_low3=meta.st_mask1_low3|mask_low4;
        // meta.st_mask1_low4=meta.st_mask1_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win1_7 {
        key = {
            hdr.patrns.p7: exact;
        }
        actions = {
            or1_7;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();

    }
    action or2_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;
        // meta.st_mask2_high2=meta.st_mask2_high2|mask_high2;
        // meta.st_mask2_high3=meta.st_mask2_high3|mask_high3;
        // meta.st_mask2_high4=meta.st_mask2_high4|mask_high4;
        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;
        // meta.st_mask2_low2=meta.st_mask2_low2|mask_low2;
        // meta.st_mask2_low3=meta.st_mask2_low3|mask_low3;
        // meta.st_mask2_low4=meta.st_mask2_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win2_7 {
        key = {
            hdr.patrns.p15: exact;
        }
        actions = {
            or2_7;
        }
        size = 256;

    }

    action or3_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;
        // meta.st_mask3_high2=meta.st_mask3_high2|mask_high2;
        // meta.st_mask3_high3=meta.st_mask3_high3|mask_high3;
        // meta.st_mask3_high4=meta.st_mask3_high4|mask_high4;
        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;
        // meta.st_mask3_low2=meta.st_mask3_low2|mask_low2;
        // meta.st_mask3_low3=meta.st_mask3_low3|mask_low3;
        // meta.st_mask3_low4=meta.st_mask3_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win3_7 {
        key = {
            hdr.patrns.p23: exact;
        }
        actions = {
            or3_7;
        }
        size = 256;

    }

    action or4_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;
        // meta.st_mask4_high2=meta.st_mask4_high2|mask_high2;
        // meta.st_mask4_high3=meta.st_mask4_high3|mask_high3;
        // meta.st_mask4_high4=meta.st_mask4_high4|mask_high4;
        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;
        // meta.st_mask4_low2=meta.st_mask4_low2|mask_low2;
        // meta.st_mask4_low3=meta.st_mask4_low3|mask_low3;
        // meta.st_mask4_low4=meta.st_mask4_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win4_7 {
        key = {
            hdr.patrns.p31: exact;
        }
        actions = {
            or4_7;
        }
        size = 256;

    }

    action or5_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;
        // meta.st_mask5_high2=meta.st_mask5_high2|mask_high2;
        // meta.st_mask5_high3=meta.st_mask5_high3|mask_high3;
        // meta.st_mask5_high4=meta.st_mask5_high4|mask_high4;
        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;
        // meta.st_mask5_low2=meta.st_mask5_low2|mask_low2;
        // meta.st_mask5_low3=meta.st_mask5_low3|mask_low3;
        // meta.st_mask5_low4=meta.st_mask5_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win5_7 {
        key = {
            hdr.patrns.p39: exact;
        }
        actions = {
            or5_7;
        }
        size = 256;

    }

    action or6_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;
        // meta.st_mask6_high2=meta.st_mask6_high2|mask_high2;
        // meta.st_mask6_high3=meta.st_mask6_high3|mask_high3;
        // meta.st_mask6_high4=meta.st_mask6_high4|mask_high4;
        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;
        // meta.st_mask6_low2=meta.st_mask6_low2|mask_low2;
        // meta.st_mask6_low3=meta.st_mask6_low3|mask_low3;
        // meta.st_mask6_low4=meta.st_mask6_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win6_7 {
        key = {
            hdr.patrns.p47: exact;
        }
        actions = {
            or6_7;
        }
        size = 256;

    }

    action or7_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;
        // meta.st_mask7_high2=meta.st_mask7_high2|mask_high2;
        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;
        // meta.st_mask7_low2=meta.st_mask7_low2|mask_low2;
        // meta.st_mask7_low3=meta.st_mask7_low3|mask_low3;
        // meta.st_mask7_low4=meta.st_mask7_low4|mask_low4;
    }
    @pragma stage 6
    table filter_win7_7 {
        key = {
            hdr.patrns.p55: exact;
        }
        actions = {
            or7_7;
        }
        size = 256;

    }

    action or8_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        // meta.st_mask8_high2=meta.st_mask8_high2|mask_high2;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
        // meta.st_mask8_low2=meta.st_mask8_low2|mask_low2;
    }
    @pragma stage 6
    table filter_win8_7 {
        key = {
            hdr.patrns.p63: exact;
        }
        actions = {
            or8_7;
        }
        size = 256;

    }

    action or9_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;
        // meta.st_mask9_high2=meta.st_mask9_high2|mask_high2;
        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;
        // meta.st_mask9_low2=meta.st_mask9_low2|mask_low2;
    }
    @pragma stage 6
    table filter_win9_7 {
        key = {
            hdr.patrns.p71: exact;
        }
        actions = {
            or9_7;
        }
        size = 256;

    }

    action or10_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        // meta.st_mask10_high2=meta.st_mask10_high2|mask_high2;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;
        // meta.st_mask10_low2=meta.st_mask10_low2|mask_low2;
    }
    @pragma stage 6
    table filter_win10_7 {
        key = {
            hdr.patrns.p79: exact;
        }
        actions = {
            or10_7;
        }
        size = 256;
    }

    action or11_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        // meta.st_mask11_high2=meta.st_mask11_high2|mask_high2;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;
        // meta.st_mask11_low2=meta.st_mask11_low2|mask_low2;
    }
    @pragma stage 6
    table filter_win11_7 {
        key = {
            hdr.patrns.p87: exact;
        }
        actions = {
            or11_7;
        }
        size = 256;
    }

    action or12_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        //meta.st_mask12_high2=meta.st_mask12_high2|mask_high2;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;
        // meta.st_mask12_low2=meta.st_mask12_low2|mask_low2;
    }
    @pragma stage 6
    table filter_win12_7 {
        key = {
            hdr.patrns.p95: exact;
        }
        actions = {
            or12_7;
        }
        size = 256;

    }

    action or13_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;
        //meta.st_mask13_low2=meta.st_mask13_low2|mask_low2;
    }
    @pragma stage 6
    table filter_win13_7 {
        key = {
            hdr.patrns.p103: exact;
        }
        actions = {
            or13_7;
        }
        size = 256;

    }

    action or14_7(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 6
    table filter_win14_7 {
        key = {
            hdr.patrns.p111: exact;
        }
        actions = {
            or14_7;
        }
        size = 256;

    }

    action or15_7(bit<32> mask_low1){
        // meta.st_mask15_high1=meta.st_mask15_high1|mask_high1;
        // meta.st_mask15_high2=meta.st_mask15_high2|mask_high2;
        // meta.st_mask15_high3=meta.st_mask15_high3|mask_high3;
        // meta.st_mask15_high4=meta.st_mask15_high4|mask_high4;
        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 6
    table filter_win15_7 {
        key = {
            hdr.patrns.p119: exact;
        }
        actions = {
            or15_7;
        }
        size = 256;

    }

    // action or16_7(bit<8> mask_low1,bit<8> mask_low2,bit<8> mask_low3,bit<8> mask_low4){
    //     // meta.st_mask16_low1=meta.st_mask16_low1|mask_low1;
    //     // meta.st_mask16_low2=meta.st_mask16_low2|mask_low2;
    //     // meta.st_mask16_low3=meta.st_mask16_low3|mask_low3;
    //     // meta.st_mask16_low4=meta.st_mask16_low4|mask_low4;
    // }
    // @pragma stage 6
    // table filter_win16_7 {
    //     key = {
    //         hdr.patrns.p127: exact;
    //     }
    //     actions = {
    //         or16_7;
    //     }
    //     size = 256;


    // }
    /**************************************************/
    /******************** stage 7 *********************/
    /**************************************************/
    action or1_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask1_high1=meta.st_mask1_high1|mask_high1;
        // meta.st_mask1_high2=meta.st_mask1_high2|mask_high2;
        // meta.st_mask1_high3=meta.st_mask1_high3|mask_high3;
        // meta.st_mask1_high4=meta.st_mask1_high4|mask_high4;
        meta.st_mask1_low1=meta.st_mask1_low1|mask_low1;
        // meta.st_mask1_low2=meta.st_mask1_low2|mask_low2;
        // meta.st_mask1_low3=meta.st_mask1_low3|mask_low4;
        // meta.st_mask1_low4=meta.st_mask1_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win1_8 {
        key = {
            hdr.patrns.p8: exact;
        }
        actions = {
            or1_8;
            @defaultonly NoAction;
        }
        size = 256;
        const default_action=NoAction();
    }
    action or2_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask2_high1=meta.st_mask2_high1|mask_high1;
        // meta.st_mask2_high2=meta.st_mask2_high2|mask_high2;
        // meta.st_mask2_high3=meta.st_mask2_high3|mask_high3;
        // meta.st_mask2_high4=meta.st_mask2_high4|mask_high4;
        meta.st_mask2_low1=meta.st_mask2_low1|mask_low1;
        // meta.st_mask2_low2=meta.st_mask2_low2|mask_low2;
        // meta.st_mask2_low3=meta.st_mask2_low3|mask_low3;
        // meta.st_mask2_low4=meta.st_mask2_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win2_8 {
        key = {
            hdr.patrns.p16: exact;
        }
        actions = {
            or2_8;
        }
        size = 256;

    }

    action or3_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask3_high1=meta.st_mask3_high1|mask_high1;
        // meta.st_mask3_high2=meta.st_mask3_high2|mask_high2;
        // meta.st_mask3_high3=meta.st_mask3_high3|mask_high3;
        // meta.st_mask3_high4=meta.st_mask3_high4|mask_high4;
        meta.st_mask3_low1=meta.st_mask3_low1|mask_low1;
        // meta.st_mask3_low2=meta.st_mask3_low2|mask_low2;
        // meta.st_mask3_low3=meta.st_mask3_low3|mask_low3;
        // meta.st_mask3_low4=meta.st_mask3_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win3_8 {
        key = {
            hdr.patrns.p24: exact;
        }
        actions = {
            or3_8;
        }
        size = 256;

    }

    action or4_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask4_high1=meta.st_mask4_high1|mask_high1;
        // meta.st_mask4_high2=meta.st_mask4_high2|mask_high2;
        // meta.st_mask4_high3=meta.st_mask4_high3|mask_high3;
        // meta.st_mask4_high4=meta.st_mask4_high4|mask_high4;
        meta.st_mask4_low1=meta.st_mask4_low1|mask_low1;
        // meta.st_mask4_low2=meta.st_mask4_low2|mask_low2;
        // meta.st_mask4_low3=meta.st_mask4_low3|mask_low3;
        // meta.st_mask4_low4=meta.st_mask4_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win4_8 {
        key = {
            hdr.patrns.p32: exact;
        }
        actions = {
            or4_8;
        }
        size = 256;

    }

    action or5_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask5_high1=meta.st_mask5_high1|mask_high1;
        // meta.st_mask5_high2=meta.st_mask5_high2|mask_high2;
        // meta.st_mask5_high3=meta.st_mask5_high3|mask_high3;
        // meta.st_mask5_high4=meta.st_mask5_high4|mask_high4;
        meta.st_mask5_low1=meta.st_mask5_low1|mask_low1;
        // meta.st_mask5_low2=meta.st_mask5_low2|mask_low2;
        // meta.st_mask5_low3=meta.st_mask5_low3|mask_low3;
        // meta.st_mask5_low4=meta.st_mask5_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win5_8 {
        key = {
            hdr.patrns.p40: exact;
        }
        actions = {
            or5_8;
        }
        size = 256;

    }

    action or6_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask6_high1=meta.st_mask6_high1|mask_high1;
        // meta.st_mask6_high2=meta.st_mask6_high2|mask_high2;
        // meta.st_mask6_high3=meta.st_mask6_high3|mask_high3;
        // meta.st_mask6_high4=meta.st_mask6_high4|mask_high4;
        meta.st_mask6_low1=meta.st_mask6_low1|mask_low1;
        // meta.st_mask6_low2=meta.st_mask6_low2|mask_low2;
        // meta.st_mask6_low3=meta.st_mask6_low3|mask_low3;
        // meta.st_mask6_low4=meta.st_mask6_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win6_8 {
        key = {
            hdr.patrns.p48: exact;
        }
        actions = {
            or6_8;
        }
        size = 256;

    }

    action or7_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask7_high1=meta.st_mask7_high1|mask_high1;
        // meta.st_mask7_high2=meta.st_mask7_high2|mask_high2;
        meta.st_mask7_low1=meta.st_mask7_low1|mask_low1;
        // meta.st_mask7_low2=meta.st_mask7_low2|mask_low2;
        // meta.st_mask7_low3=meta.st_mask7_low3|mask_low3;
        // meta.st_mask7_low4=meta.st_mask7_low4|mask_low4;
    }
    @pragma stage 7
    table filter_win7_8 {
        key = {
            hdr.patrns.p56: exact;
        }
        actions = {
            or7_8;
        }
        size = 256;

    }

    action or8_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask8_high1=meta.st_mask8_high1|mask_high1;
        // meta.st_mask8_high2=meta.st_mask8_high2|mask_high2;
        meta.st_mask8_low1=meta.st_mask8_low1|mask_low1;
        // meta.st_mask8_low2=meta.st_mask8_low2|mask_low2;
    }
    @pragma stage 7
    table filter_win8_8 {
        key = {
            hdr.patrns.p64: exact;
        }
        actions = {
            or8_8;
        }
        size = 256;

    }

    action or9_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask9_high1=meta.st_mask9_high1|mask_high1;
        // meta.st_mask9_high2=meta.st_mask9_high2|mask_high2;
        meta.st_mask9_low1=meta.st_mask9_low1|mask_low1;
        // meta.st_mask9_low2=meta.st_mask9_low2|mask_low2;
    }
    @pragma stage 7
    table filter_win9_8 {
        key = {
            hdr.patrns.p72: exact;
        }
        actions = {
            or9_8;
        }
        size = 256;

    }

    action or10_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask10_high1=meta.st_mask10_high1|mask_high1;
        // meta.st_mask10_high2=meta.st_mask10_high2|mask_high2;
        meta.st_mask10_low1=meta.st_mask10_low1|mask_low1;
        // meta.st_mask10_low2=meta.st_mask10_low2|mask_low2;
    }
    @pragma stage 7
    table filter_win10_8 {
        key = {
            hdr.patrns.p80: exact;
        }
        actions = {
            or10_8;
        }
        size = 256;

    }

    action or11_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask11_high1=meta.st_mask11_high1|mask_high1;
        // meta.st_mask11_high2=meta.st_mask11_high2|mask_high2;
        meta.st_mask11_low1=meta.st_mask11_low1|mask_low1;
        // meta.st_mask11_low2=meta.st_mask11_low2|mask_low2;
    }
    @pragma stage 7
    table filter_win11_8 {
        key = {
            hdr.patrns.p88: exact;
        }
        actions = {
            or11_8;
        }
        size = 256;
    }

    action or12_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask12_high1=meta.st_mask12_high1|mask_high1;
        //meta.st_mask12_high2=meta.st_mask12_high2|mask_high2;
        meta.st_mask12_low1=meta.st_mask12_low1|mask_low1;
        // meta.st_mask12_low2=meta.st_mask12_low2|mask_low2;
    }
    @pragma stage 7
    table filter_win12_8 {
        key = {
            hdr.patrns.p96: exact;
        }
        actions = {
            or12_8;
        }
        size = 256;

    }

    action or13_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask13_high1=meta.st_mask13_high1|mask_high1;
        meta.st_mask13_low1=meta.st_mask13_low1|mask_low1;
        //meta.st_mask13_low2=meta.st_mask13_low2|mask_low2;
    }
    @pragma stage 7
    table filter_win13_8 {
        key = {
            hdr.patrns.p104: exact;
        }
        actions = {
            or13_8;
        }
        size = 256;

    }

    action or14_8(bit<32> mask_high1,bit<32> mask_low1){
        meta.st_mask14_high1=meta.st_mask14_high1|mask_high1;
        meta.st_mask14_low1=meta.st_mask14_low1|mask_low1;
    }
    @pragma stage 7
    table filter_win14_8 {
        key = {
            hdr.patrns.p112: exact;
        }
        actions = {
            or14_8;
        }
        size = 256;

    }

    action or15_8(bit<32> mask_low1){
        // meta.st_mask15_high1=meta.st_mask15_high1|mask_high1;
        // meta.st_mask15_high2=meta.st_mask15_high2|mask_high2;
        // meta.st_mask15_high3=meta.st_mask15_high3|mask_high3;
        // meta.st_mask15_high4=meta.st_mask15_high4|mask_high4;
        meta.st_mask15_low1=meta.st_mask15_low1|mask_low1;
    }
    @pragma stage 7
    table filter_win15_8 {
        key = {
            hdr.patrns.p120: exact;
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
        // hdr.b1.setValid();
        hdr.ipv4_option.b1=b;
    }
    @pragma stage 8
    table set_map1{
        key={
            meta.st_mask1_low1: ternary;
            // meta.st_mask1_low2: ternary;
            // meta.st_mask1_low3: ternary;
            // meta.st_mask1_low4: ternary;
        }
        actions={
            set_b1;
        }
        size=256;


    }
    action set_b2(bit<8> b){
        // hdr.b2.setValid();
        hdr.ipv4_option.b2=b;
    }
    @pragma stage 9
    table set_map2{
        key={
            meta.st_mask2_low1: ternary;
        }
        actions={
            set_b2;
        }
        size=256;
    }

    action set_b3(bit<8> b){
        // hdr.b3.setValid();
        hdr.ipv4_option.b3=b;
    }
    @pragma stage 9
    table set_map3{
        key={
            meta.st_mask3_low1: ternary;
            // meta.st_mask3_low2: ternary;
            // meta.st_mask3_low3: ternary;
            // meta.st_mask3_low4: ternary;
        }
        actions={
            set_b3;
        }
        size=256;
    }
    action set_b4(bit<8> b){
        // hdr.b4.setValid();
        hdr.ipv4_option.b4=b;
    }
    @pragma stage 9
    table set_map4{
        key={
            meta.st_mask4_low1: ternary;
            // meta.st_mask4_low2: ternary;
            // meta.st_mask4_low3: ternary;
            // meta.st_mask4_low4: ternary;
        }
        actions={
            set_b4;
        }
        size=256;
    }

    action set_b5(bit<8> b){
        // hdr.b5.setValid();
        hdr.ipv4_option.b5=b;
    }
    @pragma stage 9
    table set_map5{
        key={
            meta.st_mask5_low1: ternary;
            // meta.st_mask5_low2: ternary;
            // meta.st_mask5_low3: ternary;
            // meta.st_mask5_low4: ternary;
        }
        actions={
            set_b5;
        }
        size=256;
    }

    action set_b6(bit<8> b){
        // hdr.b6.setValid();
        hdr.ipv4_option.b6=b;
    }
    @pragma stage 9
    table set_map6{
        key={
            meta.st_mask6_low1: ternary;
            // meta.st_mask6_low2: ternary;
            // meta.st_mask6_low3: ternary;
            // meta.st_mask6_low4: ternary;
        }
        actions={
            set_b6;
        }
        size=256;
    }

    action set_b7(bit<8> b){
        // hdr.b7.setValid();
        hdr.ipv4_option.b7=b;
    }
    @pragma stage 9
    table set_map7{
        key={
            meta.st_mask7_low1: ternary;
            // meta.st_mask7_low2: ternary;
            // meta.st_mask7_low3: ternary;
            // meta.st_mask7_low4: ternary;

        }
        actions={
            set_b7;
        }
        size=256;
    }

    action set_b8(bit<8> b){
        // hdr.b8.setValid();
        hdr.ipv4_option.b8=b;
    }
    @pragma stage 9
    table set_map8{
        key={
            meta.st_mask8_low1: ternary;
            // meta.st_mask8_low2: ternary;
        }
        actions={
            set_b8;
        }
        size=256;
    }
    action set_b9(bit<8> b){
        // hdr.b9.setValid();
        hdr.ipv4_option.b9=b;
    }
    @pragma stage 9
    table set_map9{
        key={
            meta.st_mask9_low1: ternary;
            // meta.st_mask9_low2: ternary;
        }
        actions={
            set_b9;
        }
        size=256;
    }

    action set_b10(bit<8> b){
        // hdr.b10.setValid();
        hdr.ipv4_option.b10=b;
    }
    @pragma stage 10
    table set_map10{
        key={
            meta.st_mask10_low1: ternary;
            // meta.st_mask10_low2: ternary;
        }
        actions={
            set_b10;
        }
        size=256;

    }

    action set_b11(bit<8> b){
        // hdr.b11.setValid();
        hdr.ipv4_option.b11=b;
    }
    @pragma stage 10
    table set_map11{
        key={
            meta.st_mask11_low1: ternary;
            // meta.st_mask11_low2: ternary;
        }
        actions={
            set_b11;
        }
        size=256;

    }
    action set_b12(bit<8> b){
        // hdr.b12.setValid();
        hdr.ipv4_option.b12=b;
    }
    @pragma stage 10
    table set_map12{
        key={
            meta.st_mask12_low1: ternary;
            // meta.st_mask12_low2:  ternary;
        }
        actions={
            set_b12;
        }
        size=256;
    }

    action set_b13(bit<8> b){
        // hdr.b13.setValid();
        hdr.ipv4_option.b13=b;
    }
    @pragma stage 10
    table set_map13{
        key={
            meta.st_mask13_low1: ternary;
            //meta.st_mask13_low2:  ternary;
        }
        actions={
            set_b13;
        }
        size=256;
    }
    action set_b14(bit<8> b){
        // hdr.b14.setValid();
        hdr.ipv4_option.b14=b;
    }
    @pragma stage 10
    table set_map14{
        key={
            meta.st_mask14_low1: ternary;
            //meta.st_mask14_low2:  ternary;
        }
        actions={
            set_b14;
        }
        size=256;
    }

    action set_b15(bit<8> b){
        // hdr.b15.setValid();
        hdr.ipv4_option.b15=b;
        // hdr.padding.setValid();
        // hdr.padding.b=0x00;
    }
    @pragma stage 10
    table set_map15{
        key={
            meta.st_mask15_low1: ternary;
            //meta.st_mask15_low2:  ternary;
        }
        actions={
            set_b15;
        }
        size=256;
    }
    action recirculate(bit<9> recircle_port) {
        ig_tm_md.ucast_egress_port= recircle_port;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4_option.recircle_time=0;
    }
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        // hdr.ipv4.st_mask_high=hdr.ipv4.total_len+16;
        // hdr.udp.length_=hdr.udp.length_+16;
        ig_tm_md.bypass_egress = 1w1;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
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
            ig_intr_md.ingress_port: ternary;
        }
        actions={
            recirculate;
            send;

        }
        const entries={
            // all 0 means no candidata position,thus no neeed to recirculate
            (0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,56&&&0b111111111):send(32);
            (0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,0x00&&&0xFF,48&&&0b111111111):send(32);
        }
        size=3;
        const default_action=recirculate(196);
        // const default_action=send(0);
    }


    apply {
        if(hdr.ipv4_option.padding == 1){
            first_filter_ingress_time_reg_write.execute(0);
        }
        // else if(hdr.ipv4_option.padding == 2){
        else if(hdr.ipv4.total_len == 168){
            last_filter_ingress_time_reg_write.execute(0);
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


        // hdr.ipv4_option.len = (bit<8>)ig_prsr_md.global_tstamp;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser_filter(packet_out pkt,
    /* User */
    inout my_ingress_headers_for_filter_t            hdr,
    in    my_ingress_metadata_for_filter_t           meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);

    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


    /***********************  P A R S E R  **************************/

parser EgressParser_filter(packet_in        pkt,
    /* User */
    out my_egress_headers_for_filter_t       hdr,
    out my_egress_metadata_for_filter_t      meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t          eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress_filter(
    /* User */
    inout my_egress_headers_for_filter_t               hdr,
    inout my_egress_metadata_for_filter_t              meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{

    apply {


    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser_filter(packet_out pkt,
    /* User */
    inout my_egress_headers_for_filter_t            hdr,
    in    my_egress_metadata_for_filter_t           meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {

    }
}


