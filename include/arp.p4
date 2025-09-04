#ifndef _ARP_ICMP_RESPONDER_
#define _ARP_ICMP_RESPONDER_



#include "types.p4"
#include "headers.p4"

control ARPResponder(
    inout headers hdr,
    inout ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // send packet back immediately
    action send_back() {
        // we assume this runs in parallel with or after
        // UDPReceiver which will set packet type IGNORE, so
        // packet will be forwarded
	ig_md.local_port = 1;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action send_arp_reply(mac_addr_t switch_mac, ipv4_addr_t switch_ip) {
        hdr.ethernet.dst_mac_addr = hdr.arp_ipv4.sha;
        hdr.ethernet.src_mac_addr = switch_mac;
	ig_md.rawgtp = 0xff;

        hdr.arp.oper = arp_opcode_t.REPLY;
        hdr.arp_ipv4.tha = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha = switch_mac;
        hdr.arp_ipv4.spa = switch_ip;

        send_back();
    }

    table arp {
        key = {
            hdr.arp_ipv4.isValid()      : exact;
            hdr.arp.oper                : ternary;
            hdr.arp_ipv4.tpa            : ternary;
            hdr.ipv4.dst_addr           : ternary;
        }
        actions = {
            send_arp_reply;
        }
        size = 1;
    }

    apply {
        arp.apply();
    }
}

#endif /* _ARP_ICMP_RESPONDER_ */
