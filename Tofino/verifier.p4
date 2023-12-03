/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "headers.p4"



    /***********************  P A R S E R  **************************/
parser IngressParser_verifier(packet_in       pkt,
    /* User */
    out my_ingress_headers_for_verifier_t     hdr,
    out my_ingress_metadata_for_verifier_t    meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t          ig_intr_md)
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
        pkt.extract(hdr.ipv4_option_hdr);
        pkt.extract(hdr.ipv4_option_len);
        pkt.extract(hdr.ipv4_option_recircle_time);
        pkt.extract(hdr.ipv4_option_padding);
        transition parse_bitmap_pattern;
    }

    state parse_bitmap_pattern{
        transition select(hdr.ipv4_option_recircle_time.t){
            7:parse_recover;
            default:parse_normal;
        }
    }

    state parse_normal{
        pkt.extract(hdr.ipv4_option_b1);
        pkt.extract(hdr.ipv4_option_b2_15);
        pkt.extract(hdr.udp);
        pkt.extract(hdr.patrns_low);
        pkt.extract(hdr.patrns_high);
        transition accept;
    }
    state parse_recover{
        pkt.extract(hdr.ipv4_option_b2_15);
        pkt.extract(hdr.ipv4_option_b1);
        pkt.extract(hdr.udp);
        pkt.extract(hdr.patrns_high);
        pkt.extract(hdr.patrns_low);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress_verifier(
    /* User */
    inout my_ingress_headers_for_verifier_t          hdr,
    inout my_ingress_metadata_for_verifier_t         meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Register<bit<64>,bit<1>>(1) first_verify_ingress_time_reg;

    RegisterAction<bit<64>, bit<1>, bit<64>>(first_verify_ingress_time_reg) first_verify_ingress_time_reg_write = {
        void apply(inout bit<64> value){
            value = (bit<64>)ig_prsr_md.global_tstamp;
        }
    };

    Register<bit<64>,bit<1>>(1) last_verify_ingress_time_reg;

    RegisterAction<bit<64>, bit<1>, bit<64>>(last_verify_ingress_time_reg) last_verify_ingress_time_reg_write = {
        void apply(inout bit<64> value){
            value = (bit<64>)ig_prsr_md.global_tstamp;
        }
    };

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        //ignore egress
        //ig_tm_md.bypass_egress = 1w1;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action recirculate(bit<9> recirc_port){
        ig_tm_md.ucast_egress_port=recirc_port;
    }

    table ipv4_host {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            send; drop;
        }
        const default_action=send(180);
        // size=2;
    }


    apply {
        if(hdr.ipv4_option_recircle_time.t<15){
            hdr.ipv4_option_recircle_time.t=hdr.ipv4_option_recircle_time.t+1;
            recirculate(196);

        }
        else if (hdr.ipv4.isValid()) {
            hdr.ipv4_option_recircle_time.t=hdr.ipv4_option_recircle_time.t+1;
            ipv4_host.apply();

        }
        if(hdr.ipv4_option_padding.padding == 1){
            first_verify_ingress_time_reg_write.execute(0);
        }
        else if(hdr.ipv4.total_len==168){
            last_verify_ingress_time_reg_write.execute(0);
        }

    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser_verifier(packet_out pkt,
    /* User */
    inout my_ingress_headers_for_verifier_t          hdr,
    in    my_ingress_metadata_for_verifier_t         meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_option_hdr);
        pkt.emit(hdr.ipv4_option_len);
        pkt.emit(hdr.ipv4_option_recircle_time);
        pkt.emit(hdr.ipv4_option_padding);
        pkt.emit(hdr.ipv4_option_b1);
        pkt.emit(hdr.ipv4_option_b2_15);
        pkt.emit(hdr.udp);
        //last time will recover bitmap and patrns
        pkt.emit(hdr.patrns_low);
        pkt.emit(hdr.patrns_high);

    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


    /***********************  P A R S E R  **************************/

parser EgressParser_verifier(packet_in        pkt,
    /* User */
    out my_egress_headers_for_verifier_t      hdr,
    out my_egress_metadata_for_verifier_t     meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t           eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
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
        transition select(hdr.ipv4_option.recircle_time){
            8:parse_last_time;
            default:parse_for_recircle;
        }
    }

    state parse_for_recircle{
        pkt.extract(hdr.p1);
        pkt.extract(hdr.patrns);
        meta.high1_1=0;
        meta.high1_2=0;
        meta.high1_3=0;
        meta.high1_4=0;
        meta.high1_5=0;
        meta.high1_6=0;
        meta.high1_7=0;
        meta.high1_8=0;
        meta.high1_9=0;
        meta.high1_10=0;
        meta.high1_11=0;
        meta.high1_12=0;
        meta.high1_13=0;
        meta.high1_14=0;
        meta.high1_15=0;
        transition accept;
    }
    state parse_last_time{
        pkt.extract(hdr.patrns);
        pkt.extract(hdr.p1);

        meta.high1_1=0;
        meta.high1_2=0;
        meta.high1_3=0;
        meta.high1_4=0;
        meta.high1_5=0;
        meta.high1_6=0;
        meta.high1_7=0;
        meta.high1_8=0;
        meta.high1_9=0;
        meta.high1_10=0;
        meta.high1_11=0;
        meta.high1_12=0;
        meta.high1_13=0;
        meta.high1_14=0;
        meta.high1_15=0;
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress_verifier(
    /* User */
    inout my_egress_headers_for_verifier_t             hdr,
    inout my_egress_metadata_for_verifier_t            meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    Register<bit<64>,bit<1>>(1) first_verify_egress_time_reg;

    RegisterAction<bit<64>, bit<1>, bit<64>>(first_verify_egress_time_reg) first_verify_egress_time_reg_write = {
        void apply(inout bit<64> value){
            value = (bit<64>)eg_prsr_md.global_tstamp;
        }
    };

    Register<bit<64>,bit<1>>(1) last_verify_egress_time_reg;

    RegisterAction<bit<64>, bit<1>, bit<64>>(last_verify_egress_time_reg) last_verify_egress_time_reg_write = {
        void apply(inout bit<64> value){
            value = (bit<64>)eg_prsr_md.global_tstamp;
        }
    };
    /******************************/
    /********** stage 1  **********/
    /******************************/
    action match1_8(bit<16>   state){
        meta.state1=state;
    }
    action miss1_8(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_8{
        key={
            hdr.p1.p:exact;
            meta.state1:exact;
        }
        actions = {
            match1_8;
            miss1_8;
        }
        size = 10240;
    }

    action match1_1(bit<16> state){
        meta.state1=state;
    }
    action miss1_1(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_1{
        key={
            hdr.patrns.p8:exact;
            meta.state1:exact;
        }
        actions = {
            match1_1;
            miss1_1;
        }
        size = 10240;
    }

    action match2_1(bit<16> state){
        meta.state2=state;
    }
    action miss2_1(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_1{
        key={
            hdr.patrns.p16:exact;
            meta.state2:exact;
        }
        actions = {
            match2_1;
            miss2_1;
        }
        size = 10240;
    }

    action match3_1(bit<16> state){
        meta.state3=state;
    }
    action miss3_1(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_1{
        key={
            hdr.patrns.p24:exact;
            meta.state3:exact;
        }
        actions = {
            match3_1;
            miss3_1;
        }
        size = 10240;
    }

    action match4_1(bit<16> state){
        meta.state4=state;
    }
    action miss4_1(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_1{
        key={
            hdr.patrns.p32:exact;
            meta.state4:exact;
        }
        actions = {
            match4_1;
            miss4_1;
        }
        size = 10240;
    }

    action match5_1(bit<16> state){
        meta.state5=state;
    }
    action miss5_1(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_1{
        key={
            hdr.patrns.p40:exact;
            meta.state5:exact;
        }
        actions = {
            match5_1;
            miss5_1;
        }
        size = 10240;
    }

    action match6_1(bit<16> state){
        meta.state6=state;
    }
    action miss6_1(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_1{
        key={
            hdr.patrns.p48:exact;
            meta.state6:exact;
        }
        actions = {
            match6_1;
            miss6_1;
        }
        size = 10240;
    }

    action match7_1(bit<16> state){
        meta.state7=state;
    }
    action miss7_1(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_1{
        key={
            hdr.patrns.p56:exact;
            meta.state7:exact;
        }
        actions = {
            match7_1;
            miss7_1;
        }
        size = 10240;
    }

    action match8_1(bit<16> state){
        meta.state8=state;
    }
    action miss8_1(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_1{
        key={
            hdr.patrns.p64:exact;
            meta.state8:exact;
        }
        actions = {
            match8_1;
            miss8_1;
        }
        size = 10240;
    }

    action match1_2(bit<16> state){
        meta.state1=state;
    }
    action miss1_2(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_2{
        key={
            hdr.patrns.p7:exact;
            meta.state1:exact;
        }
        actions = {
            match1_2;
            miss1_2;
        }
        size = 10240;
    }

    action match2_2(bit<16> state){
        meta.state2=state;
    }
    action miss2_2(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_2{
        key={
            hdr.patrns.p15:exact;
            meta.state2:exact;
        }
        actions = {
            match2_2;
            miss2_2;
        }
        size = 10240;
    }

    action match3_2(bit<16> state){
        meta.state3=state;
    }
    action miss3_2(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_2{
        key={
            hdr.patrns.p23:exact;
            meta.state3:exact;
        }
        actions = {
            match3_2;
            miss3_2;
        }
        size = 10240;
    }

    action match4_2(bit<16> state){
        meta.state4=state;
    }
    action miss4_2(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_2{
        key={
            hdr.patrns.p31:exact;
            meta.state4:exact;
        }
        actions = {
            match4_2;
            miss4_2;
        }
        size = 10240;
    }

    action match5_2(bit<16> state){
        meta.state5=state;
    }
    action miss5_2(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_2{
        key={
            hdr.patrns.p39:exact;
            meta.state5:exact;
        }
        actions = {
            match5_2;
            miss5_2;
        }
        size = 10240;
    }

    action match6_2(bit<16> state){
        meta.state6=state;
    }
    action miss6_2(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_2{
        key={
            hdr.patrns.p47:exact;
            meta.state6:exact;
        }
        actions = {
            match6_2;
            miss6_2;
        }
        size = 10240;
    }

    action match7_2(bit<16> state){
        meta.state7=state;
    }
    action miss7_2(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_2{
        key={
            hdr.patrns.p55:exact;
            meta.state7:exact;
        }
        actions = {
            match7_2;
            miss7_2;
        }
        size = 10240;
    }

    action match8_2(bit<16> state){
        meta.state8=state;
    }
    action miss8_2(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_2{
        key={
            hdr.patrns.p63:exact;
            meta.state8:exact;
        }
        actions = {
            match8_2;
            miss8_2;
        }
        size = 10240;
    }

    action match1_3(bit<16> state){
        meta.state1=state;
    }
    action miss1_3(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_3{
        key={
            hdr.patrns.p6:exact;
            meta.state1:exact;
        }
        actions = {
            match1_3;
            miss1_3;
        }
        size = 10240;
    }

    action match2_3(bit<16> state){
        meta.state2=state;
    }
    action miss2_3(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_3{
        key={
            hdr.patrns.p14:exact;
            meta.state2:exact;
        }
        actions = {
            match2_3;
            miss2_3;
        }
        size = 10240;
    }

    action match3_3(bit<16> state){
        meta.state3=state;
    }
    action miss3_3(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_3{
        key={
            hdr.patrns.p22:exact;
            meta.state3:exact;
        }
        actions = {
            match3_3;
            miss3_3;
        }
        size = 10240;
    }

    action match4_3(bit<16> state){
        meta.state4=state;
    }
    action miss4_3(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_3{
        key={
            hdr.patrns.p30:exact;
            meta.state4:exact;
        }
        actions = {
            match4_3;
            miss4_3;
        }
        size = 10240;
    }

    action match5_3(bit<16> state){
        meta.state5=state;
    }
    action miss5_3(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_3{
        key={
            hdr.patrns.p38:exact;
            meta.state5:exact;
        }
        actions = {
            match5_3;
            miss5_3;
        }
        size = 10240;
    }

    action match6_3(bit<16> state){
        meta.state6=state;
    }
    action miss6_3(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_3{
        key={
            hdr.patrns.p46:exact;
            meta.state6:exact;
        }
        actions = {
            match6_3;
            miss6_3;
        }
        size = 10240;
    }

    action match7_3(bit<16> state){
        meta.state7=state;
    }
    action miss7_3(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_3{
        key={
            hdr.patrns.p54:exact;
            meta.state7:exact;
        }
        actions = {
            match7_3;
            miss7_3;
        }
        size = 10240;
    }

    action match8_3(bit<16> state){
        meta.state8=state;
    }
    action miss8_3(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_3{
        key={
            hdr.patrns.p62:exact;
            meta.state8:exact;
        }
        actions = {
            match8_3;
            miss8_3;
        }
        size = 10240;
    }

    action match1_4(bit<16> state){
        meta.state1=state;
    }
    action miss1_4(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_4{
        key={
            hdr.patrns.p5:exact;
            meta.state1:exact;
        }
        actions = {
            match1_4;
            miss1_4;
        }
        size = 10240;
    }

    action match2_4(bit<16> state){
        meta.state2=state;
    }
    action miss2_4(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_4{
        key={
            hdr.patrns.p13:exact;
            meta.state2:exact;
        }
        actions = {
            match2_4;
            miss2_4;
        }
        size = 10240;
    }

    action match3_4(bit<16> state){
        meta.state3=state;
    }
    action miss3_4(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_4{
        key={
            hdr.patrns.p21:exact;
            meta.state3:exact;
        }
        actions = {
            match3_4;
            miss3_4;
        }
        size = 10240;
    }

    action match4_4(bit<16> state){
        meta.state4=state;
    }
    action miss4_4(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_4{
        key={
            hdr.patrns.p29:exact;
            meta.state4:exact;
        }
        actions = {
            match4_4;
            miss4_4;
        }
        size = 10240;
    }

    action match5_4(bit<16> state){
        meta.state5=state;
    }
    action miss5_4(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_4{
        key={
            hdr.patrns.p37:exact;
            meta.state5:exact;
        }
        actions = {
            match5_4;
            miss5_4;
        }
        size = 10240;
    }

    action match6_4(bit<16> state){
        meta.state6=state;
    }
    action miss6_4(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_4{
        key={
            hdr.patrns.p45:exact;
            meta.state6:exact;
        }
        actions = {
            match6_4;
            miss6_4;
        }
        size = 10240;
    }

    action match7_4(bit<16> state){
        meta.state7=state;
    }
    action miss7_4(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_4{
        key={
            hdr.patrns.p53:exact;
            meta.state7:exact;
        }
        actions = {
            match7_4;
            miss7_4;
        }
        size = 10240;
    }

    action match8_4(bit<16> state){
        meta.state8=state;
    }
    action miss8_4(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_4{
        key={
            hdr.patrns.p61:exact;
            meta.state8:exact;
        }
        actions = {
            match8_4;
            miss8_4;
        }
        size = 10240;
    }

    action match1_5(bit<16> state){
        meta.state1=state;
    }
    action miss1_5(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_5{
        key={
            hdr.patrns.p4:exact;
            meta.state1:exact;
        }
        actions = {
            match1_5;
            miss1_5;
        }
        size = 10240;
    }

    action match2_5(bit<16> state){
        meta.state2=state;
    }
    action miss2_5(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_5{
        key={
            hdr.patrns.p12:exact;
            meta.state2:exact;
        }
        actions = {
            match2_5;
            miss2_5;
        }
        size = 10240;
    }

    action match3_5(bit<16> state){
        meta.state3=state;
    }
    action miss3_5(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_5{
        key={
            hdr.patrns.p20:exact;
            meta.state3:exact;
        }
        actions = {
            match3_5;
            miss3_5;
        }
        size = 10240;
    }

    action match4_5(bit<16> state){
        meta.state4=state;
    }
    action miss4_5(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_5{
        key={
            hdr.patrns.p28:exact;
            meta.state4:exact;
        }
        actions = {
            match4_5;
            miss4_5;
        }
        size = 10240;
    }

    action match5_5(bit<16> state){
        meta.state5=state;
    }
    action miss5_5(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_5{
        key={
            hdr.patrns.p36:exact;
            meta.state5:exact;
        }
        actions = {
            match5_5;
            miss5_5;
        }
        size = 10240;
    }

    action match6_5(bit<16> state){
        meta.state6=state;
    }
    action miss6_5(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_5{
        key={
            hdr.patrns.p44:exact;
            meta.state6:exact;
        }
        actions = {
            match6_5;
            miss6_5;
        }
        size = 10240;
    }

    action match7_5(bit<16> state){
        meta.state7=state;
    }
    action miss7_5(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_5{
        key={
            hdr.patrns.p52:exact;
            meta.state7:exact;
        }
        actions = {
            match7_5;
            miss7_5;
        }
        size = 10240;
    }

    action match8_5(bit<16> state){
        meta.state8=state;
    }
    action miss8_5(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_5{
        key={
            hdr.patrns.p60:exact;
            meta.state8:exact;
        }
        actions = {
            match8_5;
            miss8_5;
        }
        size = 10240;
    }

    action match1_6(bit<16> state){
        meta.state1=state;
    }
    action miss1_6(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_6{
        key={
            hdr.patrns.p3:exact;
            meta.state1:exact;
        }
        actions = {
            match1_6;
            miss1_6;
        }
        size = 10240;
    }

    action match2_6(bit<16> state){
        meta.state2=state;
    }
    action miss2_6(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_6{
        key={
            hdr.patrns.p11:exact;
            meta.state2:exact;
        }
        actions = {
            match2_6;
            miss2_6;
        }
        size = 10240;
    }

    action match3_6(bit<16> state){
        meta.state3=state;
    }
    action miss3_6(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_6{
        key={
            hdr.patrns.p19:exact;
            meta.state3:exact;
        }
        actions = {
            match3_6;
            miss3_6;
        }
        size = 10240;
    }

    action match4_6(bit<16> state){
        meta.state4=state;
    }
    action miss4_6(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_6{
        key={
            hdr.patrns.p27:exact;
            meta.state4:exact;
        }
        actions = {
            match4_6;
            miss4_6;
        }
        size = 10240;
    }

    action match5_6(bit<16> state){
        meta.state5=state;
    }
    action miss5_6(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_6{
        key={
            hdr.patrns.p35:exact;
            meta.state5:exact;
        }
        actions = {
            match5_6;
            miss5_6;
        }
        size = 10240;
    }

    action match6_6(bit<16> state){
        meta.state6=state;
    }
    action miss6_6(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_6{
        key={
            hdr.patrns.p43:exact;
            meta.state6:exact;
        }
        actions = {
            match6_6;
            miss6_6;
        }
        size = 10240;
    }

    action match7_6(bit<16> state){
        meta.state7=state;
    }
    action miss7_6(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_6{
        key={
            hdr.patrns.p51:exact;
            meta.state7:exact;
        }
        actions = {
            match7_6;
            miss7_6;
        }
        size = 10240;
    }

    action match8_6(bit<16> state){
        meta.state8=state;
    }
    action miss8_6(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_6{
        key={
            hdr.patrns.p59:exact;
            meta.state8:exact;
        }
        actions = {
            match8_6;
            miss8_6;
        }
        size = 10240;
    }

    action match1_7(bit<16> state){
        meta.state1=state;
    }
    action miss1_7(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1&0b11111110;
    }
    @pragma ways 2
    table win1_7{
        key={
            hdr.patrns.p2:exact;
            meta.state1:exact;
        }
        actions = {
            match1_7;
            miss1_7;
        }
        size = 10240;
    }

    action match2_7(bit<16> state){
        meta.state2=state;
    }
    action miss2_7(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_7{
        key={
            hdr.patrns.p10:exact;
            meta.state2:exact;
        }
        actions = {
            match2_7;
            miss2_7;
        }
        size = 10240;
    }

    action match3_7(bit<16> state){
        meta.state3=state;
    }
    action miss3_7(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_7{
        key={
            hdr.patrns.p18:exact;
            meta.state3:exact;
        }
        actions = {
            match3_7;
            miss3_7;
        }
        size = 10240;
    }

    action match4_7(bit<16> state){
        meta.state4=state;
    }
    action miss4_7(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_7{
        key={
            hdr.patrns.p26:exact;
            meta.state4:exact;
        }
        actions = {
            match4_7;
            miss4_7;
        }
        size = 10240;
    }

    action match5_7(bit<16> state){
        meta.state5=state;
    }
    action miss5_7(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_7{
        key={
            hdr.patrns.p34:exact;
            meta.state5:exact;
        }
        actions = {
            match5_7;
            miss5_7;
        }
        size = 10240;
    }

    action match6_7(bit<16> state){
        meta.state6=state;
    }
    action miss6_7(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_7{
        key={
            hdr.patrns.p42:exact;
            meta.state6:exact;
        }
        actions = {
            match6_7;
            miss6_7;
        }
        size = 10240;
    }

    action match7_7(bit<16> state){
        meta.state7=state;
    }
    action miss7_7(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_7{
        key={
            hdr.patrns.p50:exact;
            meta.state7:exact;
        }
        actions = {
            match7_7;
            miss7_7;
        }
        size = 10240;
    }

    action match8_7(bit<16> state){
        meta.state8=state;
    }
    action miss8_7(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_7{
        key={
            hdr.patrns.p58:exact;
            meta.state8:exact;
        }
        actions = {
            match8_7;
            miss8_7;
        }
        size = 10240;
    }

    action match2_8(bit<16> state){
        meta.state2=state;
    }
    action miss2_8(){
        hdr.ipv4_option.b2=hdr.ipv4_option.b2&0b11111110;
    }
    @pragma ways 2
    table win2_8{
        key={
            hdr.patrns.p9:exact;
            meta.state2:exact;
        }
        actions = {
            match2_8;
            miss2_8;
        }
        size = 10240;
    }

    action match3_8(bit<16> state){
        meta.state3=state;
    }
    action miss3_8(){
        hdr.ipv4_option.b3=hdr.ipv4_option.b3&0b11111110;
    }
    @pragma ways 2
    table win3_8{
        key={
            hdr.patrns.p17:exact;
            meta.state3:exact;
        }
        actions = {
            match3_8;
            miss3_8;
        }
        size = 10240;
    }

    action match4_8(bit<16> state){
        meta.state4=state;
    }
    action miss4_8(){
        hdr.ipv4_option.b4=hdr.ipv4_option.b4&0b11111110;
    }
    @pragma ways 2
    table win4_8{
        key={
            hdr.patrns.p25:exact;
            meta.state4:exact;
        }
        actions = {
            match4_8;
            miss4_8;
        }
        size = 10240;
    }

    action match5_8(bit<16> state){
        meta.state5=state;
    }
    action miss5_8(){
        hdr.ipv4_option.b5=hdr.ipv4_option.b5&0b11111110;
    }
    @pragma ways 2
    table win5_8{
        key={
            hdr.patrns.p33:exact;
            meta.state5:exact;
        }
        actions = {
            match5_8;
            miss5_8;
        }
        size = 10240;
    }

    action match6_8(bit<16> state){
        meta.state6=state;
    }
    action miss6_8(){
        hdr.ipv4_option.b6=hdr.ipv4_option.b6&0b11111110;
    }
    @pragma ways 2
    table win6_8{
        key={
            hdr.patrns.p41:exact;
            meta.state6:exact;
        }
        actions = {
            match6_8;
            miss6_8;
        }
        size = 10240;
    }

    action match7_8(bit<16> state){
        meta.state7=state;
    }
    action miss7_8(){
        hdr.ipv4_option.b7=hdr.ipv4_option.b7&0b11111110;
    }
    @pragma ways 2
    table win7_8{
        key={
            hdr.patrns.p49:exact;
            meta.state7:exact;
        }
        actions = {
            match7_8;
            miss7_8;
        }
        size = 10240;
    }

    action match8_8(bit<16> state){
        meta.state8=state;
    }
    action miss8_8(){
        hdr.ipv4_option.b8=hdr.ipv4_option.b8&0b11111110;
    }
    @pragma ways 2
    table win8_8{
        key={
            hdr.patrns.p57:exact;
            meta.state8:exact;
        }
        actions = {
            match8_8;
            miss8_8;
        }
        size = 10240;
    }



    action shift_left1(){
        hdr.ipv4_option.b1=hdr.ipv4_option.b1<<1;
        hdr.ipv4_option.b2=hdr.ipv4_option.b2<<1;
        hdr.ipv4_option.b3=hdr.ipv4_option.b3<<1;
        hdr.ipv4_option.b4=hdr.ipv4_option.b4<<1;
        hdr.ipv4_option.b5=hdr.ipv4_option.b5<<1;
        hdr.ipv4_option.b6=hdr.ipv4_option.b6<<1;
        hdr.ipv4_option.b7=hdr.ipv4_option.b7<<1;
        hdr.ipv4_option.b8=hdr.ipv4_option.b8<<1;
        hdr.ipv4_option.b9=hdr.ipv4_option.b9<<1;
        hdr.ipv4_option.b10=hdr.ipv4_option.b10<<1;
        hdr.ipv4_option.b11=hdr.ipv4_option.b11<<1;
        hdr.ipv4_option.b12=hdr.ipv4_option.b12<<1;
        hdr.ipv4_option.b13=hdr.ipv4_option.b13<<1;
        hdr.ipv4_option.b14=hdr.ipv4_option.b14<<1;
        hdr.ipv4_option.b15=hdr.ipv4_option.b15<<1;
    }

    apply {
        if(hdr.ipv4_option.recircle_time<16){
            win1_1.apply();
            win2_1.apply();
            win3_1.apply();
            win4_1.apply();
            win5_1.apply();
            win6_1.apply();
            win7_1.apply();
            win8_1.apply();
            // win9_1.apply();
            // win10_1.apply();
            // win11_1.apply();
            // win12_1.apply();
            // win13_1.apply();
            // win14_1.apply();
            // win15_1.apply();


            win1_2.apply();
            win2_2.apply();
            win3_2.apply();
            win4_2.apply();
            win5_2.apply();
            win6_2.apply();
            win7_2.apply();
            win8_2.apply();
            // win9_2.apply();
            // win10_2.apply();
            // win11_2.apply();
            // win12_2.apply();
            // win13_2.apply();
            // win14_2.apply();
            // win15_2.apply();



            win1_3.apply();
            win2_3.apply();
            win3_3.apply();
            win4_3.apply();
            win5_3.apply();
            win6_3.apply();
            win7_3.apply();
            win8_3.apply();
            // win9_3.apply();
            // win10_3.apply();
            // win11_3.apply();
            // win12_3.apply();
            // win13_3.apply();
            // win14_3.apply();
            // win15_3.apply();


            win1_4.apply();
            win2_4.apply();
            win3_4.apply();
            win4_4.apply();
            win5_4.apply();
            win6_4.apply();
            win7_4.apply();
            win8_4.apply();
            // win9_4.apply();
            // win10_4.apply();
            // win11_4.apply();
            // win12_4.apply();
            // win13_4.apply();
            // win14_4.apply();
            // win15_4.apply();

            win1_5.apply();
            win2_5.apply();
            win3_5.apply();
            win4_5.apply();
            win5_5.apply();
            win6_5.apply();
            win7_5.apply();
            win8_5.apply();
            // win9_5.apply();
            // win10_5.apply();
            // win11_5.apply();
            // win12_5.apply();
            // win13_5.apply();
            // win14_5.apply();
            // win15_5.apply();

            win1_6.apply();
            win2_6.apply();
            win3_6.apply();
            win4_6.apply();
            win5_6.apply();
            win6_6.apply();
            win7_6.apply();
            win8_6.apply();
            // win9_6.apply();
            // win10_6.apply();
            // win11_6.apply();
            // win12_6.apply();
            // win13_6.apply();
            // win14_6.apply();
            // win15_6.apply();

            win1_7.apply();
            win2_7.apply();
            win3_7.apply();
            win4_7.apply();
            win5_7.apply();
            win6_7.apply();
            win7_7.apply();
            win8_7.apply();
            // win9_7.apply();
            // win10_7.apply();
            // win11_7.apply();
            // win12_7.apply();
            // win13_7.apply();
            // win14_7.apply();
            // win15_7.apply();

            win1_8.apply();
            win2_8.apply();
            win3_8.apply();
            win4_8.apply();
            win5_8.apply();
            win6_8.apply();
            win7_8.apply();
            win8_8.apply();
            // win9_8.apply();
            // win10_8.apply();
            // win11_8.apply();
            // win12_8.apply();
            // win13_8.apply();
            // win14_8.apply();
            // win15_8.apply();

            //shift bitmap
            //1.get the highest 1 bit
            if(hdr.ipv4_option.b1&0b10000000==0b10000000){
                meta.high1_1=1;
            }
            if(hdr.ipv4_option.b2&0b10000000==0b10000000){
                meta.high1_2=1;
            }
            if(hdr.ipv4_option.b3&0b10000000==0b10000000){
                meta.high1_3=1;
            }
            if(hdr.ipv4_option.b4&0b10000000==0b10000000){
                meta.high1_4=1;
            }
            if(hdr.ipv4_option.b5&0b10000000==0b10000000){
                meta.high1_5=1;
            }
            if(hdr.ipv4_option.b6&0b10000000==0b10000000){
                meta.high1_6=1;
            }
            if(hdr.ipv4_option.b7&0b10000000==0b10000000){
                meta.high1_7=1;
            }
            if(hdr.ipv4_option.b8&0b10000000==0b10000000){
                meta.high1_8=1;
            }
            if(hdr.ipv4_option.b9&0b10000000==0b10000000){
                meta.high1_9=1;
            }
            if(hdr.ipv4_option.b10&0b10000000==0b10000000){
                meta.high1_10=1;
            }
            if(hdr.ipv4_option.b11&0b10000000==0b10000000){
                meta.high1_11=1;
            }
            if(hdr.ipv4_option.b12&0b10000000==0b10000000){
                meta.high1_12=1;
            }
            if(hdr.ipv4_option.b13&0b10000000==0b10000000){
                meta.high1_13=1;
            }
            if(hdr.ipv4_option.b14&0b10000000==0b10000000){
                meta.high1_14=1;
            }
            if(hdr.ipv4_option.b15&0b10000000==0b10000000){
                meta.high1_15=1;
            }

            //2.shift the bitmap
            shift_left1();
            //3.updata the highest 1 bit of the bitmap
            if(meta.high1_2==1){
                hdr.ipv4_option.b1=hdr.ipv4_option.b1|0b00000001;
            }
            if(meta.high1_3==1){
                hdr.ipv4_option.b2=hdr.ipv4_option.b2|0b00000001;
            }
            if(meta.high1_4==1){
                hdr.ipv4_option.b3=hdr.ipv4_option.b3|0b00000001;
            }
            if(meta.high1_5==1){
                hdr.ipv4_option.b4=hdr.ipv4_option.b4|0b00000001;
            }
            if(meta.high1_6==1){
                hdr.ipv4_option.b5=hdr.ipv4_option.b5|0b00000001;
            }
            if(meta.high1_7==1){
                hdr.ipv4_option.b6=hdr.ipv4_option.b6|0b00000001;
            }
            if(meta.high1_8==1){
                hdr.ipv4_option.b7=hdr.ipv4_option.b7|0b00000001;
            }
            if(meta.high1_9==1){
                hdr.ipv4_option.b8=hdr.ipv4_option.b8|0b00000001;
            }
            if(meta.high1_10==1){
                hdr.ipv4_option.b9=hdr.ipv4_option.b9|0b00000001;
            }
            if(meta.high1_11==1){
                hdr.ipv4_option.b10=hdr.ipv4_option.b10|0b00000001;
            }
            if(meta.high1_12==1){
                hdr.ipv4_option.b11=hdr.ipv4_option.b11|0b00000001;
            }
            if(meta.high1_13==1){
                hdr.ipv4_option.b12=hdr.ipv4_option.b12|0b00000001;
            }
            if(meta.high1_14==1){
                hdr.ipv4_option.b13=hdr.ipv4_option.b13|0b00000001;
            }
            if(meta.high1_15==1){
                hdr.ipv4_option.b14=hdr.ipv4_option.b14|0b00000001;
            }
            if(meta.high1_1==1){
                hdr.ipv4_option.b15=hdr.ipv4_option.b15|0b00000001;
            }
        }
        if(hdr.ipv4_option.padding == 1){
            first_verify_egress_time_reg_write.execute(0);
        }
        else if(hdr.ipv4.total_len==168){
            last_verify_egress_time_reg_write.execute(0);
        }


    }


}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser_verifier(packet_out pkt,
    /* User */
    inout my_egress_headers_for_verifier_t          hdr,
    in    my_egress_metadata_for_verifier_t         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_option);
        pkt.emit(hdr.udp);
        //shift patrn
        pkt.emit(hdr.patrns);
        pkt.emit(hdr.p1);

    }
}


