/* -*- mode: P4_16 -*- */

//VERSION v4.11

#ifndef _PARSER_P4_ 
#define _PARSER_P4_ 

#include "headers.p4"
#include "metadata.p4"
#include "types.p4"

parser ig_prs(
    packet_in pkt,
    out headers hdr,
    out ingress_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    /* This is a mandatory state, required by the Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        
        transition meta_init;
    }

    state meta_init {
        ig_md.l4_lookup          = { 0, 0 };
        ig_md.non_first_fragment = 0;
        ig_md.drop               = 0;
        ig_md.mirror_session     = 0;
        ig_md.gtpbroker_session  = 1;

        transition prs_ethernet;
    }
    
    state prs_ethernet {
        pkt.extract(hdr.ethernet);
        
        transition select(hdr.ethernet.ethertype) {
            ethertype_t.IPV4: prs_ipv4;
            ethertype_t.IPV6: prs_ipv6;
            ethertype_t.ARP: parse_arp;
            default: accept;
        }
    }
    state parse_arp {
        pkt.extract(hdr.arp);
	transition select(hdr.arp.htype) {
            (ARP_HTYPE_ETHERNET) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        transition parse_arp_ipv4_padding;
    }

    state parse_arp_ipv4_padding {
        pkt.extract(hdr.arp_ipv4_padding);
        transition accept;
    }

    state prs_ipv4 {
        pkt.extract(hdr.ipv4);
        ig_md.rawgtp = 0x00;
	ig_md.sid_msglen = hdr.ipv4.total_len;

        
        transition select(hdr.ipv4.ihl) {
            5         : prs_ipv4_options;
            6 &&& 0xE : prs_ipv4_no_options;
            8 &&& 0x8 : prs_ipv4_no_options;
            default   : reject;
        }
    }
    
    state prs_ipv4_options {
        pkt.extract(hdr.ipv4_options, (bit<32>)((hdr.ipv4.ihl - 5) * 0x20));
        transition prs_ipv4_no_options;
    }

    
    state prs_ipv4_no_options {
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            ( 0, ip_proto_t.TCP  ) : prs_l4;
/*            ( 0, ip_proto_t.UDP  ) : prs_l4;  */
/* Send UDP to new parse to check for GTP */
            ( 0, ip_proto_t.UDP ) : prs_udp;
            ( 0, _ )               : accept;
            default: non_first_fragment;
        }
    }

    state prs_ipv6 {
        pkt.extract(hdr.ipv6);
        
        transition select(hdr.ipv6.next_hdr) {
            ip_proto_t.TCP: prs_l4;
            ip_proto_t.UDP: prs_l4;
            ip_proto_t.IPV6_FRAG : prs_ipv6_frag;
            ip_proto_t.IPV6_ROUTE : parse_srh;
            default: accept;
        }
    }

    state prs_ipv6_frag {
        pkt.extract(hdr.ipv6_frag);

        transition select(hdr.ipv6_frag.offset, hdr.ipv6_frag.next_hdr) {
            ( 0, ip_proto_t.TCP ) : prs_l4;
            ( 0, ip_proto_t.UDP ) : prs_l4;
            ( 0, _ )              : accept;
            default: non_first_fragment;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dport) {
            UDP_PORT_GTPU: parse_gtpu;
	    UDP_PORT_DHCPU: parse_dhcpu;
	    UDP_PORT_DHCPS: parse_dhcpu;
            default: accept;
        }
    }


    state non_first_fragment {
        ig_md.non_first_fragment = 1;

        transition accept;
    }
    
    state prs_l4 {
        ig_md.l4_lookup = pkt.lookahead<l4_lookup_t>();
        
        transition accept;
    }

    state prs_udp {
        pkt.extract(hdr.udp);
        gtpu_t gtpu = pkt.lookahead<gtpu_t>();
        transition select(hdr.udp.dport, gtpu.version, gtpu.msgtype) {
            (L4Port.IPV4_IN_UDP, _, _): parse_inner_ipv4;
            // Treat GTP control traffic as payload.
            (L4Port.GTP_GPDU, GTP_V1, GTPUMessageType.GPDU): parse_gtpu;
            (L4Port.DHCP_SERV, _, _): parse_dhcpu;
	    (L4Port.DHCP_CLIENT, _, _): parse_dhcpu;
            default: accept;
        }
    }
/*  GTPU PARSE ADDED BUT NEED TO CHECK CONSTANTS */
/* OUTER PACKET PARSING */

    state parse_gtpu {
        pkt.extract(hdr.gtpu);
        ig_md.srv6.gtpv1_type = hdr.gtpu.msgtype;
        ig_md.teid = hdr.gtpu.teid;
        ig_md.rawgtp = 0x01;
        bit<4> ip_ver = pkt.lookahead<bit<4>>();
        transition select(ip_ver) {
            4w4: parse_inner_ipv4;
            default: parse_inner_ether;
        }
    }

    state parse_gtpu_options {
        pkt.extract(hdr.gtpu_options);
        bit<8> gtpu_ext_len = pkt.lookahead<bit<8>>();
        transition select(hdr.gtpu_options.next_ext, gtpu_ext_len) {
            (GTPU_NEXT_EXT_PSC, GTPU_EXT_PSC_LEN): parse_gtpu_ext_psc;
            default: accept;
        }
    }

    state parse_gtpu_ext_psc {
        pkt.extract(hdr.gtpu_ext_psc);
        transition select(hdr.gtpu_ext_psc.next_ext) {
            GTPU_NEXT_EXT_NONE: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_dhcpu {
	pkt.extract(hdr.dhcpu);
	ig_md.dhcp_offer = 1;
	ig_md.srv6.dhcp_client_addr = hdr.dhcpu.client_addr;
	ig_md.srv6.dhcp_client_mac = hdr.dhcpu.client_mac;
	transition accept;
    }

/* INNER PACKET PARSING */


    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
            ig_md.inner_saddr = hdr.inner_ipv4.src_addr;
            ig_md.inner_daddr = hdr.inner_ipv4.dst_addr;
        transition select(hdr.inner_ipv4.protocol) {
            ip_proto_t.UDP:  parse_inner_udp;
            ip_proto_t.TCP:  parse_inner_tcp;
            ip_proto_t.ICMP: parse_inner_icmp;
            default: accept;
        }
    }

    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
        ig_md.inner_l4_sport = hdr.inner_udp.sport;
        ig_md.inner_l4_dport = hdr.inner_udp.dport;
	transition select(hdr.inner_udp.dport) {
            (L4Port.DHCP_SERV): parse_inner_dhcpu;
	    (L4Port.DHCP_CLIENT): parse_inner_dhcpu;
	    default: accept;
	}
    }

    state parse_inner_dhcpu {
	pkt.extract(hdr.inner_dhcp);
//	ig_md.dhcp_offer = 1;
//	ig_md.srv6.dhcp_client_mac = hdr.inner_dhcp.client_mac;
	transition accept;
    }

    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
        ig_md.inner_l4_sport = hdr.inner_tcp.sport;
        ig_md.inner_l4_dport = hdr.inner_tcp.dport;
        transition accept;
    }

    state parse_inner_icmp {
        pkt.extract(hdr.inner_icmp);
        transition accept;
    }

    state parse_inner_ipv6 {
        pkt.extract(hdr.inner_ipv6);
        transition select(hdr.inner_ipv6.next_hdr) {
            ip_proto_t.TCP : parse_inner_tcp;
            ip_proto_t.UDP : parse_inner_udp;
            default : accept;
        }
    }
 
    state parse_inner_ether {
        pkt.extract(hdr.inner_ether);
        transition accept;
    }


/* PARSE SRH (SRv6) */
/*** PARSE SRH (SRv6) ***/
    state parse_srh {
        pkt.extract(hdr.srh);
        ig_md.srv6.gtp_message_type = hdr.srh.gtpMessageType;
        transition parse_srh_sid_0;
    }
#define PARSE_SRH_SID(curr, next)               \
    state parse_srh_sid_##curr {                \
        pkt.extract(hdr.srh_sid[curr]);         \
        transition select(hdr.srh.lastEntry) {  \
            curr : parse_srh_next_header;       \
            default : parse_srh_sid_##next;     \
        }                                       \
    }   


// switch_srv6.p4:SRH_SID_MAX 4
PARSE_SRH_SID(0, 1)
PARSE_SRH_SID(1, 2)
PARSE_SRH_SID(2, 3)
    state parse_srh_sid_3 {
        pkt.extract(hdr.srh_sid[3]);
        transition select(hdr.srh.lastEntry) {
            3 : parse_srh_next_header;
            // v1model: no default rule: all other packets rejected
        }
    }
    state parse_srh_next_header {
        transition select(hdr.srh.nextHdr) {
            ip_proto_t.TCP : parse_tcp;
            ip_proto_t.UDP : parse_udp;
            ip_proto_t.IPV4 : parse_inner_ipv4;
            ip_proto_t.IPV6_ROUTE : parse_inner_ipv6;
            default : accept;
        }
    }

}

#endif // _PARSER_P4_
