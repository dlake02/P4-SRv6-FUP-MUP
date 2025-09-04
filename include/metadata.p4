/* -*- mode: P4_16 -*- */

#ifndef _METADATA_P4_ 
#define _METADATA_P4_ 

#include "types.p4"

struct SRv6Metadata {
    bit<128> nextsid;
    bit<4> gtp_message_type;
    bit<8> gtpv1_type;
    bit<128> orig_dst_add;
    bit<128> sid_addr;
    bit<48> dhcp_client_mac;
    ipv4_addr_t relay_addr;
    ipv4_addr_t dhcp_client_addr;
}

struct ingress_metadata_t {
    l4_lookup_t l4_lookup;
    MirrorId_t mirror_session;
    gtpbroker_session_t gtpbroker_session;
    bit<1> non_first_fragment;
    bit<1> drop;
    teid_t teid;
    ipv4_addr_t inner_saddr;
    ipv4_addr_t inner_daddr;
    l4_port_t inner_l4_sport;
    l4_port_t inner_l4_dport;
    SRv6Metadata srv6;
    bit<1> gtp4;
    bit<8> no_sids;
    bit<8> dhcp_offer;
    bit<16> sid_msglen;
    bit<16> gtp4_count;
    bit<16> rawgtp;
    ipv6_addr_t next_hop2;
    bit<8> local_port;
}

#endif // _METADATA_P4
