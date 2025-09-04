/* -*- mode: P4_16 -*- */

#ifndef _HEADERS_P4_ 
#define _HEADERS_P4_ 
#define SRH_SID_MAX 4

#include "protocol_headers.p4"

struct headers {
    ethernet_t ethernet;
    arp_t arp;
    arp_ipv4_t arp_ipv4;
    arp_ipv4_padding_t arp_ipv4_padding;
    ipv4_t ipv4;
    ipv4_options_t ipv4_options;
    ipv6_t ipv6;
    ipv6_frag_t ipv6_frag;
    udp_t udp;
    tcp_t tcp;
    gtpu_t gtpu;
    gtpu_options_t gtpu_options;
    gtpu_ext_psc_t gtpu_ext_psc;
    ipv4_t inner_ipv4;
    udp_t inner_udp;
    tcp_t inner_tcp;
    icmp_t inner_icmp;
    SRH_h srh;
    SRH_SegmentList_h[SRH_SID_MAX] srh_sid;
    ethernet_t inner_ether;
    ipv6_t inner_ipv6;
    ipv4_t innner_ipv4;
    dhcpu_t dhcpu;
    dhcpu_t inner_dhcp;
    ethernet_t dhcp_ether;
}


#endif // _HEADERS_P4_
