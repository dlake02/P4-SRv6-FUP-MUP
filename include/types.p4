/* -*- mode: P4_16 -*- */

#ifndef _TYPES_P4_ 
#define _TYPES_P4_ 

typedef bit<8>   port_group_t;
typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<32>  teid_t;
typedef bit<16>  l4_port_t;
typedef bit<16>  gtpbroker_session_t;

//Added various GTP related constants //
const bit<16> UDP_PORT_GTPU = 2152;
const bit<3> GTP_V1 = 0x1;
const bit<1> GTP_PROTOCOL_TYPE_GTP = 0x1;
const bit<8> GTP_MESSAGE_TYPE_UPDU = 0xff;
const bit<8> GTPU_NEXT_EXT_NONE = 0x0;
const bit<8> GTPU_NEXT_EXT_PSC = 0x85;
const bit<4> GTPU_EXT_PSC_TYPE_DL = 4w0; // Downlink
const bit<4> GTPU_EXT_PSC_TYPE_UL = 4w1; // Uplink
const bit<8> GTPU_EXT_PSC_LEN = 8w1; // 1*4-octets
const bit<8> GTPV1_ECHO =1;
const bit<8> GTPV1_ECHORES = 2;
const bit<8> GTPV1_ERROR = 26;
const bit<8> GTPV1_END = 254;
const bit<8> GTPV1_GPDU = 255;
const bit<8> DHCP_TYPE = 0x1;


//Added DHCP //

const bit<16> UDP_PORT_DHCPU = 67;
const bit<16> UDP_PORT_DHCPS = 68;



// The first two 16-bit words of the L4 header for TCP and UDP.
struct l4_lookup_t {
    bit<16>  word_1;
    bit<16>  word_2;
}

// Added ICMP to the list //
enum bit<8>  ip_proto_t {
    TCP       = 6,
    UDP       = 17,
    IPV4      = 4,
    IPV6_ROUTE = 43,
    IPV6_FRAG = 44,
    ICMP      = 1
}

enum bit<16> ethertype_t {
    IPV4 = 0x0800,
    IPV6 = 0x86dd,
    ARP = 0x0806
}

enum MirrorType_t mirror_session_t {
    FLOW = 0
}



// Added L4Port details //
enum bit<16> L4Port {
    DHCP_SERV       = 67, // naming this DHCP_SERVER causes a syntax error..
    DHCP_CLIENT     = 68,
    GTP_GPDU        = 2152,
    IPV4_IN_UDP     = 9875 // placeholder. port has not yet been assigned by IANA
}

// Added GTPUMessageType //
enum bit<8> GTPUMessageType {
    GPDU = 255
}

// ARP-specific types
enum bit<16> arp_opcode_t {
    REQUEST = 1,
    REPLY   = 2
}


#endif // _TYPES_P4_
