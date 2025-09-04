/* -*- mode: P4_16 -*- */

// VERSION 4.11

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "include/types.p4"
#include "include/protocol_headers.p4"
#include "include/metadata.p4"
#include "include/headers.p4"

#include "include/parser.p4"
#include "include/drop.p4"
#include "include/filter.p4"
#include "include/hash.p4"
#include "include/forward.p4"
#include "include/egress.p4"
#include "include/mirror.p4"
#include "include/gtpbroker.p4"
#include "include/srv6.p4"
#include "include/arp.p4"

control ig_ctl(
    inout headers hdr, inout ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    ARPResponder() arp_responder;
    PortFwd() port_fwd;
    SRv6() srv6;
    bit<32> sel_hash = 0;

    apply {
        if (ig_prsr_md.parser_err != PARSER_ERROR_OK) {
            // Fail hard if the parser terminated with an error
            ig_dprsr_md.drop_ctl = 1;
            exit;
        }

        ctl_maybe_drop_fragment.apply(ig_md);
        ctl_maybe_exclude_l4_from_hash.apply(ig_md);
        
        if (hdr.ipv4.isValid()) {
            ctl_filter_source_ipv4.apply(hdr, ig_md);
            //ctl_gtpbroker.apply(hdr, ig_intr_md, ig_md);
            ctl_calc_ipv4_hash.apply(hdr, ig_md, sel_hash);
            ctl_mirror_flows_ipv4.apply(hdr, ig_intr_md, ig_md, ig_dprsr_md);
            //if (ig_md.gtpbroker_session == 10) {
            //    hdr.ipv4.ttl = hdr.ipv4.ttl + 1;
            //    }
        } else if (hdr.ipv6.isValid()) {
            ctl_filter_source_ipv6.apply(hdr, ig_md);
            ctl_calc_ipv6_hash.apply(hdr, ig_md, sel_hash);
            ctl_mirror_flows_ipv6.apply(hdr, ig_intr_md, ig_md, ig_dprsr_md);
        } else {
            ctl_calc_ethernet_hash.apply(hdr, sel_hash);
            ctl_mirror_flows_non_ip.apply(hdr, ig_intr_md, ig_md, ig_dprsr_md);
            ctl_maybe_drop_non_ip.apply(ig_md);
        }
	ig_md.local_port = 0;
	arp_responder.apply(hdr, ig_md, ig_intr_md, ig_prsr_md, ig_dprsr_md, ig_tm_md);
        if (ig_md.local_port == 0) {
            port_fwd.apply(ig_intr_md.ingress_port, ig_tm_md.ucast_egress_port);
        }
        ig_md.gtp4 = 0;
        ig_md.srv6.orig_dst_add = hdr.ipv6.dst_addr;
        srv6.apply(hdr, ig_md, ig_intr_md);
        if (ig_md.gtp4 == 1) {
		if (hdr.srh.hdrExtLen == 1){
                        hdr.ipv4.total_len = ig_md.gtp4_count + 0x0014;
		} else if (hdr.srh.hdrExtLen == 2){
			hdr.ipv4.total_len = ig_md.gtp4_count + 0x000C;
		} else if (hdr.srh.hdrExtLen == 3){
			hdr.ipv4.total_len = ig_md.gtp4_count + 0x0004;
		} else if (hdr.srh.hdrExtLen == 4){
			hdr.ipv4.total_len = ig_md.gtp4_count - 0x0004;
		} else if (hdr.srh.hdrExtLen == 5) {
			hdr.ipv4.total_len = ig_md.gtp4_count - 0x000C;
		} else if (hdr.srh.hdrExtLen == 6) {
			hdr.ipv4.total_len = ig_md.gtp4_count - 0x0014;
			}
		hdr.udp.len = hdr.ipv4.total_len - 0x0014;
		hdr.gtpu.msglen = hdr.udp.len - 0x0010;
		}
	if (ig_md.rawgtp ==0) {
        	if (ig_md.no_sids == 0) {
			hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0008;
		} else if (ig_md.no_sids == 1) {
			hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0018;
		} else if (ig_md.no_sids == 2) {
			hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0028;
		} else if (ig_md.no_sids == 3) {
			hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0038;
		} else if (ig_md.no_sids == 4) {
			hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0048;
        	} else if (ig_md.no_sids == 5) {
                	hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0058;
		} else if (ig_md.no_sids == 9) {
			hdr.ipv6.payload_len = hdr.ipv4.total_len + 0x0018;
        	}
	} else if (ig_md.rawgtp == 1){

                if (ig_md.no_sids == 0) {
                        hdr.ipv6.payload_len = ig_md.sid_msglen - 0x001C;
                } else if (ig_md.no_sids == 1) {
                        hdr.ipv6.payload_len = ig_md.sid_msglen - 0x000C;
                } else if (ig_md.no_sids == 2) {
                        hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0004;
                } else if (ig_md.no_sids == 3) {
                        hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0014;
                } else if (ig_md.no_sids == 4) {
                        hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0024;
                } else if (ig_md.no_sids == 5) {
                        hdr.ipv6.payload_len = ig_md.sid_msglen + 0x0034;
                } else if (ig_md.no_sids == 9) {
                        hdr.ipv6.payload_len = hdr.ipv4.total_len + 0x0018;
                }	}



//        ctl_forward_packet.apply(ig_intr_md, sel_hash, ig_md, ig_tm_md);
	if (ig_md.dhcp_offer == 1) {
		hdr.ethernet.dst_mac_addr = ig_md.srv6.dhcp_client_mac;
		if (ig_md.srv6.dhcp_client_addr != 0x00000000){
                        hdr.ipv4.dst_addr = ig_md.srv6.dhcp_client_addr;
                        }
	} else if (hdr.inner_ipv4.dst_addr == 0xffffffff){
                hdr.ethernet.dst_mac_addr = 0xffffffffffff;
	} else if (hdr.inner_ipv4.dst_addr == 0xc0a80101){
		hdr.ethernet.dst_mac_addr = 0x0cae1cd90000;
	} else if (hdr.ipv4.dst_addr == 0xc0a80101){
		hdr.ethernet.dst_mac_addr = 0x0cae1cd90000;
	}

        // Some of the controls above can request the packet to
        // be dropped (or sent to a port for inspection).  The
        // drop is enforced in the traffic manager.
//        if (ig_md.drop == 1) {
//            ctl_drop_packet.apply(ig_dprsr_md, ig_tm_md);
//        }
    }
    
}


control ig_ctl_dprs(
    packet_out pkt,
    inout headers hdr,
    in ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Mirror() mirror;



    apply {


        if (ig_dprsr_md.mirror_type == (MirrorType_t)mirror_session_t.FLOW) {
            mirror.emit(ig_md.mirror_session);
        }
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr });
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.arp_ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.srh);
        pkt.emit(hdr.srh_sid);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.dhcpu);
        pkt.emit(hdr.gtpu);
        pkt.emit(hdr.inner_ether);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_tcp);
        pkt.emit(hdr.inner_udp);
        pkt.emit(hdr.inner_icmp);
        pkt.emit(hdr.inner_dhcp);

//        pkt.emit(hdr);
    }
}

Pipeline(
    ig_prs(), ig_ctl(), ig_ctl_dprs(),
    eg_prs(), eg_ctl(), eg_ctl_dprs()) pipe;

Switch(pipe) main;
