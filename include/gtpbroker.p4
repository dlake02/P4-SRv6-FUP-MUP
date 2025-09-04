/* -*- mode: P4_16 -*- */

#ifndef _GTPBROKER_P4_ 
#define _GTPBROKER_P4_ 

#include "metadata.p4"
#include "headers.p4"
#include "drop.p4"


control ctl_gtpbroker(
    inout headers hdr,
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_metadata_t ig_md)
{
    action act_gtp_rewrite(ipv4_addr_t gtp_addr, mac_addr_t gtp_mac, gtpbroker_session_t gtpsession) {
        hdr.ipv4.dst_addr = gtp_addr;
        hdr.ethernet.dst_mac_addr = gtp_mac;
        ig_md.gtpbroker_session = gtpsession;
        hdr.udp.checksum =0;
    }

    
    table tbl_gtp_broker {
        key = {
            ig_intr_md.ingress_port : ternary @name("ingress_port");
            ig_md.inner_saddr : ternary @name("src_addr");
            ig_md.inner_daddr  : ternary @name("dst_addr");
            ig_md.inner_l4_sport : ternary @name("src_port");
            ig_md.inner_l4_dport : ternary @name("dst_port");
        }
        actions = {
            act_gtp_rewrite;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
    }
    apply {
        tbl_gtp_broker.apply();
    }
}


#endif // _GTPBROKER_P4_
