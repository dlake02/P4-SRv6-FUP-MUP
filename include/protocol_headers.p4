/* -*- mode: P4_16 -*- */

#ifndef _PROTOCOL_HEADERS_P4_ 
#define _PROTOCOL_HEADERS_P4_ 

#include "types.p4"

header ethernet_t {
    mac_addr_t dst_mac_addr;
    mac_addr_t src_mac_addr;
    ethertype_t ethertype;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    ip_proto_t  protocol;
    bit<16>     hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv4_options_t { 
    varbit<320> data;
}

header ipv6_t {
    bit<4>     version;
    bit<8>     traffic_class;
    bit<20>    flow_label;
    bit<16>    payload_len;
    bit<8>     next_hdr;
    bit<8>     hop_limit;
    bit<128>   src_addr;
    bit<128>   dst_addr;
}

header ipv6_frag_t {
    ip_proto_t next_hdr;
    bit<8>     reserved;
    bit<13>    offset;
    bit<2>     reserved_2;
    bit<1>     more_fragments;
    bit<32>    id;
}


header tcp_t {
    l4_port_t   sport;
    l4_port_t   dport;
    bit<32>     seq_no;
    bit<32>     ack_no;
    bit<4>      data_offset;
    bit<3>      res;
    bit<3>      ecn;
    bit<6>      ctrl;
    bit<16>     window;
    bit<16>     checksum;
    bit<16>     urgent_ptr;
}

header udp_t {
    l4_port_t   sport;
    l4_port_t   dport;
    bit<16>     len;
    bit<16>     checksum;
}

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extension hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    teid_t  teid;       /* tunnel endpoint id */
//    bit<16> seq;
//    bit<8>  npdu;
//    bit<8>  nextExtHdr;

}


header dhcpu_t {
   bit<8> opcode;
   bit<8> hwtype;
   bit<8> hwlen;
   bit<8> hopcnt;
   bit<32> xid;
   bit<16> seconds;
   bit<16> flags;
   bit<32> client1_addr;
   bit<32> client_addr;
   bit<32> server_addr;
   bit<32> relay_addr;
   bit<48> client_mac;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    mac_addr_t  sha;
    ipv4_addr_t spa;
    mac_addr_t  tha;
    ipv4_addr_t tpa;
}

header arp_ipv4_padding_t {
    bit<144> padding;
}


const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4 = 0x0800;
const bit<8> ARP_HLEN_ETHERNET = 6;
const bit<8> ARP_PLEN_IPV4 = 4;

// Follows gtpu_t if any of ex_flag, seq_flag, or npdu_flag is 1.
header gtpu_options_t {
    bit<16> seq_num;   /* Sequence number */
    bit<8>  n_pdu_num; /* N-PDU number */
    bit<8>  next_ext;  /* Next extension header */
}

// GTPU extension: PDU Session Container (PSC) -- 3GPP TS 38.415 version 15.2.0
// https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.02.00_60/ts_138415v150200p.pdf
header gtpu_ext_psc_t {
    bit<8> len;      /* Length in 4-octet units (common to all extensions) */
    bit<4> type;     /* Uplink or downlink */
    bit<4> spare0;   /* Reserved */
    bit<1> ppp;      /* Paging Policy Presence (UL only, not supported) */
    bit<1> rqi;      /* Reflective QoS Indicator (UL only) */
    bit<6> qfi;      /* QoS Flow Identifier */
    bit<8> next_ext;
}

// Segment Routing Extension Header (SRH) based on version 15
// https://datatracker.ietf.org/doc/draft-ietf-6man-segment-routing-header/
// Tag field extended based on draft-murakami-dmm-user-plane-message-encoding-00
header SRH_h {
    bit<8> nextHdr;
    bit<8> hdrExtLen;
    bit<8> routingType;
    bit<8> segmentsLeft;
    bit<8> lastEntry;
    bit<8> flags;
    bit<12> tag;
    bit<4> gtpMessageType; // least significant 4 bits of tag field
}

header SRH_SegmentList_h {
    bit<128> sid;
}


#endif // _PROTOCOL_HEADERS_P4_
