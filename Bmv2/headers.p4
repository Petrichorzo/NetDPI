/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
#ifndef _HEADERS_
#define _HEADERS_
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
/* Table Sizes */
const int IPV4_HOST_SIZE = 65536;
typedef bit<32> ip4Addr_t;
typedef bit<32> stateNumber_t;
typedef bit<8> matchLen_t;
typedef bit<16> ruleNumber_t;

typedef bit<128> sh_mask_t;
const bit<32> alpha_num=50;
const bit<32> saturated=0xFE;
#ifdef USE_ALPM
const int IPV4_LPM_SIZE  = 400*1024;
#else
const int IPV4_LPM_SIZE  = 12288;
#endif
/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

// header ipv4_h {
//     bit<4>   version;
//     bit<4>   ihl;
//     bit<8>   diffserv;
//     bit<16>  total_len;
//     bit<16>  identification;
//     bit<3>   flags;
//     bit<13>  frag_offset;
//     bit<8>   ttl;
//     bit<8>   protocol;
//     bit<16>  hdr_checksum;
//     bit<32>  src_addr;
//     bit<32>  dst_addr;
// }
header ipv4_h {
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
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv4_option_hdr_h {
    bit<8>  hdr;
}
header ipv4_option_len_h{
    bit<8> len;
}

header ipv4_option_b1_h{
    bit<8>  b1;
}
header ipv4_option_b2_15_h{
    bit<8>  b2;
    bit<8>  b3;
    bit<8>  b4;
    bit<8>  b5;
    bit<8>  b6;
    bit<8>  b7;
    bit<8>  b8;
    bit<8>  b9;
    bit<8>  b10;
    bit<8>  b11;
    bit<8>  b12;
    bit<8>  b13;
    bit<8>  b14;
    bit<8>  b15;
}
header ipv4_option_recircle_time_h{
    bit<8> t;
}
header ipv4_option_padding_h{
    bit<16> padding;
}

header ipv4_option_h {
    bit<8>  hdr;
    bit<8>  len;
    bit<8>  recircle_time;
    bit<16> padding;
    bit<8>  b1;
    bit<8>  b2;
    bit<8>  b3;
    bit<8>  b4;
    bit<8>  b5;
    bit<8>  b6;
    bit<8>  b7;
    bit<8>  b8;
    bit<8>  b9;
    bit<8>  b10;
    bit<8>  b11;
    bit<8>  b12;
    bit<8>  b13;
    bit<8>  b14;
    bit<8>  b15;
}


/* 8 */
header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


header patrn_h {
    bit<8> pattern;
}

header patrn_recir_h {
    bit<8> p2;
    bit<8> p3;
    bit<8> p4;
    bit<8> p5;
    bit<8> p6;
    bit<8> p7;
    bit<8> p8;
    bit<8> p9;
    bit<8> p10;
    bit<8> p11;
    bit<8> p12;
    bit<8> p13;
    bit<8> p14;
    bit<8> p15;
    bit<8> p16;
    bit<8> p17;
    bit<8> p18;
    bit<8> p19;
    bit<8> p20;
    bit<8> p21;
    bit<8> p22;
    bit<8> p23;
    bit<8> p24;
    bit<8> p25;
    bit<8> p26;
    bit<8> p27;
    bit<8> p28;
    bit<8> p29;
    bit<8> p30;
    bit<8> p31;
    bit<8> p32;
    bit<8> p33;
    bit<8> p34;
    bit<8> p35;
    bit<8> p36;
    bit<8> p37;
    bit<8> p38;
    bit<8> p39;
    bit<8> p40;
    bit<8> p41;
    bit<8> p42;
    bit<8> p43;
    bit<8> p44;
    bit<8> p45;
    bit<8> p46;
    bit<8> p47;
    bit<8> p48;
    bit<8> p49;
    bit<8> p50;
    bit<8> p51;
    bit<8> p52;
    bit<8> p53;
    bit<8> p54;
    bit<8> p55;
    bit<8> p56;
    bit<8> p57;
    bit<8> p58;
    bit<8> p59;
    bit<8> p60;
    bit<8> p61;
    bit<8> p62;
    bit<8> p63;
    bit<8> p64;
    bit<8> p65;
    bit<8> p66;
    bit<8> p67;
    bit<8> p68;
    bit<8> p69;
    bit<8> p70;
    bit<8> p71;
    bit<8> p72;
    bit<8> p73;
    bit<8> p74;
    bit<8> p75;
    bit<8> p76;
    bit<8> p77;
    bit<8> p78;
    bit<8> p79;
    bit<8> p80;
    bit<8> p81;
    bit<8> p82;
    bit<8> p83;
    bit<8> p84;
    bit<8> p85;
    bit<8> p86;
    bit<8> p87;
    bit<8> p88;
    bit<8> p89;
    bit<8> p90;
    bit<8> p91;
    bit<8> p92;
    bit<8> p93;
    bit<8> p94;
    bit<8> p95;
    bit<8> p96;
    bit<8> p97;
    bit<8> p98;
    bit<8> p99;
    bit<8> p100;
    bit<8> p101;
    bit<8> p102;
    bit<8> p103;
    bit<8> p104;
    bit<8> p105;
    bit<8> p106;
    bit<8> p107;
    bit<8> p108;
    bit<8> p109;
    bit<8> p110;
    bit<8> p111;
    bit<8> p112;
    bit<8> p113;
    bit<8> p114;
    bit<8> p115;
    bit<8> p116;
    bit<8> p117;
    bit<8> p118;
    bit<8> p119;
    bit<8> p120;

}
header patrn_recover_high_h {
    bit<8> p9;
    bit<8> p10;
    bit<8> p11;
    bit<8> p12;
    bit<8> p13;
    bit<8> p14;
    bit<8> p15;
    bit<8> p16;
    bit<8> p17;
    bit<8> p18;
    bit<8> p19;
    bit<8> p20;
    bit<8> p21;
    bit<8> p22;
    bit<8> p23;
    bit<8> p24;
    bit<8> p25;
    bit<8> p26;
    bit<8> p27;
    bit<8> p28;
    bit<8> p29;
    bit<8> p30;
    bit<8> p31;
    bit<8> p32;
    bit<8> p33;
    bit<8> p34;
    bit<8> p35;
    bit<8> p36;
    bit<8> p37;
    bit<8> p38;
    bit<8> p39;
    bit<8> p40;
    bit<8> p41;
    bit<8> p42;
    bit<8> p43;
    bit<8> p44;
    bit<8> p45;
    bit<8> p46;
    bit<8> p47;
    bit<8> p48;
    bit<8> p49;
    bit<8> p50;
    bit<8> p51;
    bit<8> p52;
    bit<8> p53;
    bit<8> p54;
    bit<8> p55;
    bit<8> p56;
    bit<8> p57;
    bit<8> p58;
    bit<8> p59;
    bit<8> p60;
    bit<8> p61;
    bit<8> p62;
    bit<8> p63;
    bit<8> p64;
    bit<8> p65;
    bit<8> p66;
    bit<8> p67;
    bit<8> p68;
    bit<8> p69;
    bit<8> p70;
    bit<8> p71;
    bit<8> p72;
    bit<8> p73;
    bit<8> p74;
    bit<8> p75;
    bit<8> p76;
    bit<8> p77;
    bit<8> p78;
    bit<8> p79;
    bit<8> p80;
    bit<8> p81;
    bit<8> p82;
    bit<8> p83;
    bit<8> p84;
    bit<8> p85;
    bit<8> p86;
    bit<8> p87;
    bit<8> p88;
    bit<8> p89;
    bit<8> p90;
    bit<8> p91;
    bit<8> p92;
    bit<8> p93;
    bit<8> p94;
    bit<8> p95;
    bit<8> p96;
    bit<8> p97;
    bit<8> p98;
    bit<8> p99;
    bit<8> p100;
    bit<8> p101;
    bit<8> p102;
    bit<8> p103;
    bit<8> p104;
    bit<8> p105;
    bit<8> p106;
    bit<8> p107;
    bit<8> p108;
    bit<8> p109;
    bit<8> p110;
    bit<8> p111;
    bit<8> p112;
    bit<8> p113;
    bit<8> p114;
    bit<8> p115;
    bit<8> p116;
    bit<8> p117;
    bit<8> p118;
    bit<8> p119;
    bit<8> p120;

}
header patrn_recover_low_h {
    bit<8> p1;
    bit<8> p2;
    bit<8> p3;
    bit<8> p4;
    bit<8> p5;
    bit<8> p6;
    bit<8> p7;
    bit<8> p8;
}

header bitmap_t{
    bit<8> b;

}

/*************************************************************************
 **************************  F I L T E R *********************************
 *************************************************************************/
struct my_ingress_headers_for_filter_t {
    ethernet_h    ethernet;
    ipv4_h        ipv4;
    ipv4_option_h ipv4_option;
    udp_h         udp;
    patrn_h[120]   patrns;
}

/******  G L O B A L   M E T A D A T A  *********/

struct my_ingress_metadata_for_filter_t {
    bit<16> payload_length;
    // bit<16> non_payload_length;
    // bit<8> pattern_num;

    bit<32> st_mask1_high1;
    bit<32> st_mask1_low1;

    bit<32> st_mask2_high1;
    bit<32> st_mask2_low1;

    bit<32> st_mask3_high1;
    bit<32> st_mask3_low1;

    bit<32> st_mask4_high1;
    bit<32> st_mask4_low1;

    bit<32> st_mask5_high1;
    bit<32> st_mask5_low1;

    bit<32> st_mask6_high1;
    bit<32> st_mask6_low1;

    bit<32> st_mask7_high1;
    bit<32> st_mask7_low1;

    bit<32> st_mask8_low1;
    bit<32> st_mask8_high1;

    bit<32> st_mask9_high1;
    bit<32> st_mask9_low1;

    bit<32> st_mask10_high1;
    bit<32> st_mask10_low1;

    bit<32> st_mask11_high1;
    bit<32> st_mask11_low1;

    bit<32> st_mask12_high1;
    bit<32> st_mask12_low1;

    bit<32> st_mask13_high1;
    bit<32> st_mask13_low1;

    bit<32> st_mask14_high1;
    bit<32> st_mask14_low1;

    bit<32> st_mask15_low1;

}

struct my_egress_headers_for_filter_t {


}
struct my_egress_metadata_for_filter_t {

}

/*************************************************************************
 *************************  V E R I F I E R  *****************************
 *************************************************************************/
struct my_ingress_headers_for_verifier_t {
    ethernet_h                  ethernet;
    ipv4_h                      ipv4;
    ipv4_option_hdr_h           ipv4_option_hdr;
    ipv4_option_len_h           ipv4_option_len;
    ipv4_option_recircle_time_h ipv4_option_recircle_time;
    ipv4_option_padding_h       ipv4_option_padding;
    ipv4_option_b1_h            ipv4_option_b1;
    ipv4_option_b2_15_h         ipv4_option_b2_15;
    udp_h                       udp;
    patrn_recover_high_h        patrns_high;
    patrn_recover_low_h         patrns_low;

}
struct my_ingress_metadata_for_verifier_t {


}
header p_h {
    bit<8> p;
}
struct my_egress_headers_for_verifier_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    ipv4_option_h       ipv4_option;
    udp_h               udp;
    p_h                 p1;
    patrn_recir_h       patrns;


}
struct my_egress_metadata_for_verifier_t {

    bit<16> state1;
    bit<16> state2;
    bit<16> state3;
    bit<16> state4;
    bit<16> state5;
    bit<16> state6;
    bit<16> state7;
    bit<16> state8;
    bit<16> state9;
    bit<16> state10;
    bit<16> state11;
    bit<16> state12;
    bit<16> state13;
    bit<16> state14;
    bit<16> state15;

    bit<1> high1_1;
    bit<1> high1_2;
    bit<1> high1_3;
    bit<1> high1_4;
    bit<1> high1_5;
    bit<1> high1_6;
    bit<1> high1_7;
    bit<1> high1_8;
    bit<1> high1_9;
    bit<1> high1_10;
    bit<1> high1_11;
    bit<1> high1_12;
    bit<1> high1_13;
    bit<1> high1_14;
    bit<1> high1_15;
}
#endif /* _HEADERS_ */