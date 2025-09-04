/*
 * Copyright 2019 TOYOTA InfoTechnology Center Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Kentaro Ebisawa <ebisawa@jp.toyota-itc.com>
 *
 */

/*
 * Copyright 2025 David Lake - University of Surrey
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * David Lake <d.lake@surrey.ac.uk>
 *
 */

// VERSION v4.11

#ifndef _SRV6_
#define _SRV6_
#include "metadata.p4"
#include "headers.p4"
#include "drop.p4"
#include "types.p4"

typedef bit<8> IPProtocol;
const IPProtocol IPPROTO_ROUTE = 43;
const IPProtocol IPPROTO_IPv4 = 4;

control SRv6(
    inout headers hdr,
    inout ingress_metadata_t user_md,
    in ingress_intrinsic_metadata_t ig_intr_md) {
    
    /*** HELPER ACTIONS *******************************************************/
    action remove_srh_header() {
        hdr.srh.setInvalid();
        hdr.srh_sid[0].setInvalid();
        hdr.srh_sid[1].setInvalid();
        hdr.srh_sid[2].setInvalid();
        hdr.srh_sid[3].setInvalid();
        hdr.srh.setInvalid();
    }

    /*** HELPER ACTIONS : PUSH SRH/SID ****************************************/
    // https://datatracker.ietf.org/doc/draft-ietf-6man-segment-routing-header/
    // NextHeader, HdrExtLen, SegmentsLeft are defined in "RFC8200 IPv6 Specification"
    // Hdr Ext Len: 8-bit unsigned integer.  Length of the Routing header in
    //              8-octet units, not including the first 8 octets.
    //  => with no TLV, this is 2*(number_of_sid)
    // Segments Left: 8-bit unsigned integer.  Number of route segments
    //   remaining, i.e., number of explicitly listed intermediate nodes still
    //   to be visited before reaching the final destination.
    //  => "number_of_sid - 1" for normal insert/encaps
    //  => "number_of_sid" for reduced insert/encaps (TODO: double check)
    // Last Entry: contains the index (zero based), in the Segment List,
    //             of the last element of the Segment List.
    action push_srh(bit<8> nextHdr, bit<8> hdrExtLen, bit<8> segmentsLeft, bit<8> lastEntry) {
        hdr.srh.setValid();
        hdr.srh.nextHdr = nextHdr;
        hdr.srh.hdrExtLen = hdrExtLen;
        hdr.srh.routingType = 4; // TBD, to be assigned by IANA (suggested value: 4)
        hdr.srh.segmentsLeft = segmentsLeft;
        hdr.srh.lastEntry = lastEntry;
        hdr.srh.flags = 0;
        hdr.srh.tag = 0;
    }
    action push_srh_sid1(
            bit<8> nextHdr,
            bit<8> segmentsLeft,
            bit<128> sid1) {
        // SID List <sid1>
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 16w24; // SRH(8) + SID(16)
        push_srh(nextHdr, 8w2, segmentsLeft, 8w0);
        hdr.srh_sid[0].setValid();
        hdr.srh_sid[0].sid = sid1;
    }
    action push_srh_sid2(
            bit<8> nextHdr,
            bit<8> segmentsLeft,
            bit<128> sid1, bit<128> sid2) {
        // SID List <sid1, sid2>
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 16w40; // SRH(8) + SID(16)*2
        push_srh(nextHdr, 8w4, segmentsLeft, 8w1);
        hdr.srh_sid[0].setValid();
        hdr.srh_sid[0].sid = sid2;
        hdr.srh_sid[1].setValid();
        hdr.srh_sid[1].sid = sid1;
    }
    action push_srh_sid3(
            bit<8> nextHdr,
            bit<8> segmentsLeft,
            bit<128> sid1, bit<128> sid2, bit<128> sid3) {
        // SID List <sid1, sid2, sid3>
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 16w56; // SRH(8) + SID(16)*3
        push_srh(nextHdr, 8w6, segmentsLeft, 8w2);
        hdr.srh_sid[0].setValid();
        hdr.srh_sid[0].sid = sid3;
        hdr.srh_sid[1].setValid();
        hdr.srh_sid[1].sid = sid2;
        hdr.srh_sid[2].setValid();
        hdr.srh_sid[2].sid = sid1;
    }
    action push_srh_sid4(
            bit<8> nextHdr,
            bit<8> segmentsLeft,
            bit<128> sid1, bit<128> sid2, bit<128> sid3, bit<128> sid4) {
        // SID List <sid1, sid2, sid3, sid4>
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 16w72; // SRH(8) + SID(16)*4
        push_srh(nextHdr, 8w8, segmentsLeft, 8w3);
        hdr.srh_sid[0].setValid();
        hdr.srh_sid[0].sid = sid4;
        hdr.srh_sid[1].setValid();
        hdr.srh_sid[1].sid = sid3;
        hdr.srh_sid[2].setValid();
        hdr.srh_sid[2].sid = sid2;
        hdr.srh_sid[3].setValid();
        hdr.srh_sid[3].sid = sid1;
    }

    /*** TRANSIT ACTION & TABLES **********************************************/
    // hdr.srh.nextHdr:
    //   T.Insert: nextHdr in the original IPv6 hdr
    //   T.Encaps and match with IPv4 : IPPROTO_IPV4(4) 
    //   T.Encaps and match with IPv6 : IPPROTO_IPV6(41)
    //   T.Encaps.L2, T.Encaps.L2.Red : IPPROTO_NONXT(59)

    // T.Insert will use ipv6.dstAddr as 1st SID. Thus, will have +1 SIDs.
    action t_insert_sid1(bit<128> sid1) {
        push_srh_sid2(hdr.ipv6.next_hdr, 1, sid1, hdr.ipv6.dst_addr);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = sid1;
    }
    action t_insert_sid2(bit<128> sid1, bit<128> sid2) {
        push_srh_sid3(hdr.ipv6.next_hdr, 2, sid1, sid2, hdr.ipv6.dst_addr);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = sid1;
    }
    action t_insert_sid3(bit<128> sid1, bit<128> sid2, bit<128> sid3) {
        push_srh_sid4(hdr.ipv6.next_hdr, 3, sid1, sid2, sid3, hdr.ipv6.dst_addr);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = sid1;
    }


    action h_m_gtp4_d_synthesize(bit<32> iw_prefix, bit<64> src_prefix) { // TODO: make src_prefix length configurable
        hdr.ethernet.ethertype = ethertype_t.IPV6;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
        //hdr.ipv6.payload_len = hdr.ipv4.total_len - 16w40;
        //hdr.ipv6.payload_len = hdr.gtpu.msglen + 0x0054;
        hdr.ipv6.payload_len = 0x0000;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        // Synthesize IPv6 SA from GTP packet
        hdr.ipv6.src_addr[127:64] = src_prefix[63:0]; // Local SRGW Src Prefix (64)
        hdr.ipv6.src_addr[63:32] = hdr.ipv4.src_addr; //IPv4 SA (32)
        hdr.ipv6.src_addr[31:0] = 32w0; // Reserved
        // Synthesize Last SID (IPv6 DA) from GTP packet
        user_md.srv6.sid_addr[127:96] = iw_prefix; // GTP SRv6 InterWork prefix
        user_md.srv6.sid_addr[95:64] = hdr.ipv4.dst_addr;
        // TODO: Args.Mob.Session
        user_md.srv6.sid_addr[63:56] = 8w0; // GTP QFI/RQI (0 for now)
        user_md.srv6.sid_addr[55:24] = hdr.gtpu.teid;
        user_md.srv6.sid_addr[23:0] = 24w0;
        // remove IPv4/UDP/GTPU headers
        hdr.gtpu.setInvalid();
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
    }



    action mup_encap_gtp4_e(bit<32> iw_prefix, bit<64> src_prefix, bit<32> teid, bit<8> qfi, bit<32> upf_addr, bit<32> gnb_addr, bit<128> next_v6_hop){
    // This needs to be actioned by a combination of ISD from the MUP-GW and T1ST from the MUP-C
        hdr.ethernet.ethertype = ethertype_t.IPV6;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
        //hdr.ipv6.payload_len = hdr.ipv4.total_len - 16w40;
        //hdr.ipv6.payload_len = hdr.gtpu.msglen + 0x0054;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        // Synthesize IPv6 SA from T1ST + DSD;
        hdr.ipv6.src_addr[127:64] = src_prefix; // Local SRGW Src Prefix (64)
        hdr.ipv6.src_addr[63:32] = upf_addr; //IPv4 SA of the UPF
        hdr.ipv6.src_addr[31:0] = 32w0; // Reserved
        // Synthesize Last SID (IPv6 DA) from T1ST + DSD
        user_md.srv6.sid_addr[127:96] = iw_prefix; // GTP SRv6 InterWork prefix
        user_md.srv6.sid_addr[95:64] = gnb_addr;
        // TODO: Args.Mob.Session
        user_md.srv6.sid_addr[63:56] = qfi; // GTP QFI/RQI (0 for now)
        user_md.srv6.sid_addr[55:24] = teid;
        user_md.srv6.sid_addr[23:0] = 24w0;
        // remove IPv4/UDP/GTPU headers
        hdr.gtpu.setInvalid();
        //hdr.udp.setInvalid();
        //hdr.ipv4.setInvalid();
	push_srh_sid1(hdr.ipv6.next_hdr, 0, user_md.srv6.sid_addr);
	user_md.no_sids = 9;
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = user_md.srv6.sid_addr;
        hdr.ethernet.dst_mac_addr = 0x0c86a0120003;

        //Case 0 where there is no SID
    }

    action h_m_gtp4_d(bit<32> iw_prefix, bit<64> src_prefix) {
        h_m_gtp4_d_synthesize(iw_prefix, src_prefix);
        push_srh_sid1(hdr.ipv6.next_hdr, 0, user_md.srv6.orig_dst_add);
	hdr.ipv6.next_hdr = IPPROTO_ROUTE;
	user_md.no_sids = 0;
    }
    action h_m_gtp4_d_sid1(bit<32> iw_prefix, bit<64> src_prefix,
            bit<128> sid1) {
        h_m_gtp4_d_synthesize(iw_prefix, src_prefix);
        push_srh_sid2(hdr.ipv6.next_hdr, 1, sid1, user_md.srv6.orig_dst_add);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        user_md.no_sids = 1;
    }

    action h_m_gtp4_d_test_sid(bit<32> iw_prefix, bit<64> src_prefix, bit<128> next_hop) {
          h_m_gtp4_d_synthesize(iw_prefix, src_prefix);
// iw_prefix is 32 bits
        hdr.ipv6.dst_addr = next_hop;
        push_srh_sid2(hdr.ipv6.next_hdr, 1, next_hop, user_md.srv6.sid_addr);
// nextHdr is 8 bits
// segmentsLeft is 1 bit
// sid 1 is the iw_prefix plus orig GTP address info
// sid 2 is the utltimate destination
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        user_md.no_sids = 2;
    }


    action h_m_gtp4_d_sid2(bit<32> iw_prefix, bit<64> src_prefix,
            bit<128> sid1, bit<128> sid2) {
        h_m_gtp4_d_synthesize(iw_prefix, src_prefix);
        push_srh_sid3(hdr.ipv6.next_hdr, 2, sid1, sid2, hdr.ipv6.dst_addr);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = sid1;
        user_md.no_sids = 2;
    }
    action h_m_gtp4_d_sid3(bit<32> iw_prefix, bit<64> src_prefix,
            bit<128> sid1, bit<128> sid2, bit<128> sid3) {
        h_m_gtp4_d_synthesize(iw_prefix, src_prefix);
        push_srh_sid4(hdr.ipv6.next_hdr, 3, sid1, sid2, sid3, hdr.ipv6.dst_addr);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = sid1;
        user_md.no_sids = 3;
    }
    action srv6_debug_v6() {
        //debug
    }

    action fup_encap_for_end_dt4_common() {
        hdr.ethernet.ethertype = ethertype_t.IPV6;
//	hdr.ethernet.dst_mac_addr=0x0c4f14b80002;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
        hdr.ipv6.payload_len = 0x0000;
        hdr.gtpu.setInvalid();
	hdr.inner_dhcp.setInvalid();
    }


    action fup_dhcp_relay_for_end_dt4_sid1(bit<128> src_addr, bit<128> next_hop, mac_addr_t src_mac, mac_addr_t dst_mac, ipv4_addr_t relay_agent, ipv4_addr_t dhcp_server) {
    // Format the DHCP Broadcast message into a DHCP Relay message and forward unicast to DHCP server
    // using SRv6.

	hdr.ipv4.dst_addr = dhcp_server;
	hdr.ipv4.src_addr = relay_agent;
	hdr.dhcpu.relay_addr = relay_agent;
//	hdr.udp.sport = 0x0043;
        hdr.udp.checksum = 0x0000;

        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
	hdr.ipv6.src_addr = src_addr;
	hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
	push_srh_sid1(hdr.ipv6.next_hdr, 1, next_hop);
	hdr.ipv6.next_hdr = IPPROTO_ROUTE;
	hdr.ipv6.dst_addr = next_hop;
	user_md.no_sids = 1;
	hdr.ethernet.src_mac_addr = src_mac;
//	hdr.ethernet.dst_mac_addr = dst_mac;
	user_md.srv6.dhcp_client_mac = dst_mac;
	fup_encap_for_end_dt4_common();
    }

    action fup_encap_for_end_dt4_sid2(bit<128> src_addr, bit<128> sid1, bit<128> next_hop) {
    // GTPU incoming that matches the UPF DST address, TEID and GNB SRC address in the T2ST must be have a SID as given in the DSD for the N6DN
    // and stripped back to be just the INNER IP in the packet.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl; 
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        push_srh_sid2(hdr.ipv6.next_hdr, 2, sid1, next_hop);
        hdr.ipv6.dst_addr = next_hop;
        user_md.no_sids = 2; 
        fup_encap_for_end_dt4_common();
    }

    action fup_encap_for_end_dt4_sid3(bit<128> src_addr, bit<128> sid1, bit<128> sid2, bit<128> next_hop) {
    // GTPU incoming that matches the UPF DST address, TEID and GNB SRC address in the T2ST must be have a SID as given in the DSD for the N6DN
    // and stripped back to be just the INNER IP in the packet.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl; 
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        push_srh_sid3(hdr.ipv6.next_hdr, 3, sid1, sid2, next_hop);
        hdr.ipv6.dst_addr = next_hop;
        user_md.no_sids = 3; 
        fup_encap_for_end_dt4_common();
    }




    action fup_encap_for_end_dt4_sid1(bit<128> src_addr, bit<128> next_hop, mac_addr_t src_mac, mac_addr_t dst_mac) {
    // IPv4 Traffic from the CPE goes to End.DT4


        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        push_srh_sid1(hdr.ipv6.next_hdr, 1, next_hop);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = next_hop;
        user_md.no_sids = 1;
        hdr.ethernet.src_mac_addr = src_mac;
        hdr.ethernet.dst_mac_addr = dst_mac;
        user_md.srv6.dhcp_client_mac = dst_mac;
        hdr.ethernet.ethertype = ethertype_t.IPV6;
//      hdr.ethernet.dst_mac_addr=0x0c4f14b80002;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
        hdr.ipv6.payload_len = 0x0000;
    }




    action fup_encap_for_end_dt2d_common() {
        hdr.ethernet.ethertype = ethertype_t.IPV6;
//      hdr.ethernet.dst_mac_addr=0x0c4f14b80002;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
        hdr.ipv6.payload_len = 0x0000;
        hdr.gtpu.setInvalid();
        hdr.inner_dhcp.setInvalid();
    }
    
    
    action fup_dhcp_relay_for_end_dt2d_sid1(bit<128> src_addr, bit<128> next_hop, mac_addr_t src_mac, mac_addr_t dst_mac, ipv4_addr_t relay_agent, ipv4_addr_t dhcp_server) {
    // Format the DHCP Broadcast message into a DHCP Relay message and forward unicast to DHCP server
    // using SRv6.
    
        hdr.ipv4.dst_addr = dhcp_server;
        hdr.ipv4.src_addr = relay_agent;
        hdr.dhcpu.relay_addr = relay_agent;
//        hdr.udp.sport = 0x0043; 
        hdr.udp.checksum = 0x0000;
    
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
	user_md.next_hop2[127:48] = next_hop[127:48];
	user_md.next_hop2[47:0] = user_md.srv6.dhcp_client_mac;
        push_srh_sid1(hdr.ipv6.next_hdr, 1, user_md.next_hop2);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = user_md.next_hop2;
        user_md.no_sids = 1;
        hdr.ethernet.src_mac_addr = src_mac;
//      hdr.ethernet.dst_mac_addr = dst_mac;
        user_md.srv6.dhcp_client_mac = dst_mac;
        fup_encap_for_end_dt2d_common();
    }

    action fup_encap_for_end_dt2d_sid2(bit<128> src_addr, bit<128> sid1, bit<128> next_hop) {
    // GTPU incoming that matches the UPF DST address, TEID and GNB SRC address in the T2ST must be have a SID as given in the DSD for the N6DN
    // and stripped back to be just the INNER IP in the packet.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        push_srh_sid2(hdr.ipv6.next_hdr, 2, sid1, next_hop);
        hdr.ipv6.dst_addr = next_hop;
        user_md.no_sids = 2;
        fup_encap_for_end_dt2d_common();
    }

    action fup_encap_for_end_dt2d_sid3(bit<128> src_addr, bit<128> sid1, bit<128> sid2, bit<128> next_hop) {
    // GTPU incoming that matches the UPF DST address, TEID and GNB SRC address in the T2ST must be have a SID as given in the DSD for the N6DN
    // and stripped back to be just the INNER IP in the packet.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl; 
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        push_srh_sid3(hdr.ipv6.next_hdr, 3, sid1, sid2, next_hop);
        hdr.ipv6.dst_addr = next_hop;
        user_md.no_sids = 3; 
        fup_encap_for_end_dt2d_common();
    } 



    action fup_encap_dt2d_e(bit<128> src_addr, bit<128> next_hop, mac_addr_t src_mac, mac_addr_t dst_mac, mac_addr_t client_mac) {
    // Format the reverse message 
    // using SRv6.
    
    
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        user_md.next_hop2[127:48] = next_hop[127:48];
        user_md.next_hop2[47:0] = client_mac;
        push_srh_sid1(hdr.ipv6.next_hdr, 1, user_md.next_hop2);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = user_md.next_hop2;
        user_md.no_sids = 1;
        hdr.ethernet.src_mac_addr = src_mac;
        hdr.ethernet.dst_mac_addr = dst_mac;
        fup_encap_for_end_dt2d_common();
    }





    action mup_encap_for_end_dt4_common() {
        hdr.ethernet.ethertype = ethertype_t.IPV6;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.traffic_class = 8w0;
        hdr.ipv6.flow_label = 20w0;
        hdr.ipv6.payload_len = 0x0000;
        hdr.gtpu.setInvalid(); 
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
    }   
        

    action mup_encap_for_end_dt4_sid1(bit<128> src_addr, bit<128> next_hop) {
    // GTPU incoming that matches the UPF DST address, TEID and GNB SRC address in the T2ST must be have a SID as given in the DSD for the N6DN
    // and stripped back to be just the INNER IP in the packet.
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
        hdr.ipv6.src_addr = src_addr;
        hdr.ipv6.next_hdr = 8w4; // TODO: User PDU. Should be configurable.
        push_srh_sid1(hdr.ipv6.next_hdr, 1, next_hop);
        hdr.ipv6.next_hdr = IPPROTO_ROUTE;
        hdr.ipv6.dst_addr = next_hop; 
        user_md.no_sids = 1;
        mup_encap_for_end_dt4_common();
    }   


    table srv6_transit_v6 {
        key = {
            hdr.ipv6.dst_addr: exact; // TODO: change to LPM
        }
        actions = {
            @defaultonly NoAction;
            t_insert_sid1;       // T.Insert with 2 SIDs (DA + sid1)
            t_insert_sid2;       // T.Insert with 3 SIDs (DA + sid1/2)
            t_insert_sid3;       // T.Insert with 4 SIDs (DA + sid1/2/3)
            //t_encaps_sid1;       // T.Encaps
            //t_encaps_l2_sid1;    // T.Encaps.L2
            // Custom functions
            //srv6_debug_v6;
        }
        const default_action = NoAction;
    }
    table srv6_transit_v4 {
        key = {
            hdr.ipv4.dst_addr: exact; // UE dst_addr for traffic from N6 to UE
        }
        actions = {
            @defaultonly NoAction;
            mup_encap_gtp4_e; //Encode in a manner that End.Mp.GTP4.E will understand
        }
        const default_action = NoAction;
    }
    table srv6_transit_udp {
        key = {
            hdr.udp.dport : exact;
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.gtpu.teid : exact;
        }
        actions = {
            @defaultonly NoAction;
            // SRv6 Mobile Userplane : draft-ietf-dmm-srv6-mobile-uplane
            h_m_gtp4_d;
            h_m_gtp4_d_sid1;  // 2 SIDs (DA + sid1)
            h_m_gtp4_d_sid2;  // 3 SIDs (DA + sid1/2)
            h_m_gtp4_d_sid3;  // 4 SIDs (DA + sid1/2/3)
            h_m_gtp4_d_test_sid;  // DA + sid1 but next hop set to sid1
            mup_encap_for_end_dt4_sid1; // Encap for End.DT4
        }
        const default_action = NoAction;
    }
    /*** END (localsid) ACTION & TABLES ***************************************/
    // End: Prerequisite for executing End function is NH=SRH and SL>0
    //      match key should be updated to check this prerequisite.
    action end() {
        // 1.   IF NH=SRH and SL > 0
        // 2.      decrement SL
        //hdr.srh.segmentsLeft = hdr.srh.segmentsLeft - 1;
        // 3.      update the IPv6 DA with SRH[SL]
        //hdr.ipv6.dst_addr = user_md.srv6.nextsid;
        // 4.      FIB lookup on the updated DA
        // 5.      forward accordingly to the matched entry
        // TODO
    }
    action end_m_gtp4_e() {
	user_md.no_sids = 0xff;
	hdr.ethernet.dst_mac_addr = 0x965ef172e255;
        hdr.ethernet.ethertype = ethertype_t.IPV4;
        hdr.ipv4.setValid();
        hdr.ipv4.version = 4w4;
        hdr.ipv4.ihl = 4w5;
        hdr.ipv4.diffserv = 8w0;
        // IPv6 Payload Length - length of extention Headers + IPv4 Header(20) + UDP(8) + GTP(12)
        // length of ext headers = SRH(8) + hdr.srh.hdrExtLen*8
        //hdr.ipv4.total_len = hdr.ipv6.payload_len - 16w8 - (bit<16>)hdr.srh.hdrExtLen*8 + 16w40;
        user_md.gtp4 = 1;
	user_md.gtp4_count = hdr.ipv6.payload_len;
        hdr.ipv4.identification = 16w0;
        hdr.ipv4.flags = 3w0;
        hdr.ipv4.frag_offset = 13w0;
        hdr.ipv4.ttl = hdr.ipv6.hop_limit;
        hdr.ipv4.protocol = ip_proto_t.UDP;
        // IPv4 header checksum will be calculated later.
        hdr.ipv4.src_addr = hdr.ipv6.src_addr[63:32];
        hdr.ipv4.dst_addr = hdr.ipv6.dst_addr[95:64];
        hdr.udp.setValid();
        hdr.udp.sport = UDP_PORT_GTPU; // 16w2152 TODO: Should support GTP-C for Echo
        hdr.udp.dport = UDP_PORT_GTPU; // 16w2152 TODO: Should support GTP-C for Echo
        hdr.udp.len = hdr.ipv6.payload_len + 16w20 -16w40; // Payload + UDP(8) + GTP(12)
        //DEBUG hdr.udp.length = hdr.ipv6.payload_len + 16w16; // Payload + UDP(8) + GTP(8)
        hdr.gtpu.setValid();
        hdr.gtpu.version = 3w1;
        hdr.gtpu.pt = 1w1;
        hdr.gtpu.spare = 1w0;
        hdr.gtpu.ex_flag = 1w0; // No Extention Header
        hdr.gtpu.seq_flag = 1w0; // No Sequence number
        hdr.gtpu.npdu_flag = 1w0;
        hdr.gtpu.msgtype = GTPUMessageType.GPDU; // 8w255 overwritten based on gtp_message_type
        // IPv6 Payload length - length of extention headers + GTP optional headers(4)
        //TEST SET TO ZERO
        //hdr.gtpu.msglen = hdr.ipv6.payload_len - 16w8 - (bit<16>)hdr.srh.hdrExtLen*8 + 16w4; 
        //hdr.gtpu.msglen = 0;
        hdr.gtpu.teid = hdr.ipv6.dst_addr[55:24]; //TODO: make prefix length configurable
//        hdr.gtpu.seq = 16w0; // TODO: fetch from SID (Args.mob)
//        hdr.gtpu.npdu = 8w0;
//        hdr.gtpu.nextExtHdr = 8w0;
        // remove IPv6/SRH headers
        remove_srh_header();
        hdr.ipv6.setInvalid();

    }



    action end_dt2d() {
        hdr.ethernet.ethertype = ethertype_t.IPV4;
	hdr.ethernet.dst_mac_addr = hdr.ipv6.dst_addr[47:0];
        remove_srh_header();
        hdr.ipv6.setInvalid();
    }


    action end_dt4() {
	hdr.ethernet.ethertype = ethertype_t.IPV4;
        remove_srh_header();
        hdr.ipv6.setInvalid();
    }

/*
    // https://tools.ietf.org/html/draft-xuclad-spring-sr-service-programming-02#section-6.4.1
    // 6.4.1.  SRv6 masquerading proxy pseudocode
    // Masquerading: Upon receiving a packet destined for S, where S is an
    // IPv6 masquerading proxy segment, a node N processes it as follows.
    // 1.   IF NH=SRH & SL > 0 THEN
    // 2.       Update the IPv6 DA with SRH[0]
    // 3.       Forward the packet on IFACE-OUT
    // 4.   ELSE
    // 5.       Drop the packet
    action end_am(PortId_t oif, EthernetAddress dmac) {
        // TODO: "NH=SRH & SL > 0" should be validated as part of match rule
        hdr.ipv6.dst_addr = hdr.srh_sid[0].sid;
        hdr.ether.dstAddr = dmac;
        //egress_port = oif;
    }
    // De-masquerading: Upon receiving a non-link-local IPv6 packet on
    // IFACE-IN, a node N processes it as follows.
    // 1.   IF NH=SRH & SL > 0 THEN
    // 2.       Decrement SL
    // 3.       Update the IPv6 DA with SRH[SL]                      ;; Ref1
    // 4.       Lookup DA in appropriate table and proceed accordingly
    action end_am_d(PortId_t oif) {
        // TODO: "NH=SRH & SL > 0" should be validated as part of match rule
        hdr.srh.segmentsLeft = hdr.srh.segmentsLeft - 1;
        hdr.ipv6.dst_addr = user_md.srv6.nextsid;
        // egress_port = oif; // TODO: Workaround untill L2Fwd() and L3 support
    }
*/

    table srv6_end { // localsid
        key = {
            hdr.ipv6.dst_addr : ternary;
            // hdr.srh.isValid() : ternary;
            // hdr.srh.segmentLeft : ternary;
            // hdr.srh.nextHdr : ternary; // for decap
        }
        actions = {
            @defaultonly NoAction;
            // SRv6 Network Program  : draft-filsfils-spring-srv6-network-programming
            end;                    // End
            //end_x;                  // End.X

            // SRv6 Mobile Userplane : draft-ietf-dmm-srv6-mobile-uplane
            end_m_gtp4_e;           // End.M.GTP4.E
            end_dt4;
	    end_dt2d;
/*
            // Proxy Functions : draft-xuclad-spring-sr-service-programming
            end_am;
*/
        }
        const default_action = NoAction;
    }







    table ipoe_dhcp {
	key = {
	    hdr.udp.sport : exact;
	    hdr.udp.dport : exact;
	}
	actions = {
	    @defaultonly NoAction;
	    fup_dhcp_relay_for_end_dt4_sid1;
            fup_dhcp_relay_for_end_dt2d_sid1;
	}
	const default_action = NoAction;
    }

    table ipoe_transit {
	key = {
	    hdr.ipv4.src_addr : ternary;
	    hdr.ipv4.dst_addr : ternary;
	}
	actions = {
		@defaultonly NoAction;
		fup_encap_for_end_dt4_sid1;
		fup_encap_dt2d_e;
	}
	const default_action = NoAction;
    }
		


    /*** HELPER TABLE TO SET NEXT SID *****************************************/
    action set_nextsid_1() {
        user_md.srv6.nextsid = hdr.srh_sid[0].sid;
    }
    action set_nextsid_2() {
        user_md.srv6.nextsid = hdr.srh_sid[1].sid;
    }
    action set_nextsid_3() {
        user_md.srv6.nextsid = hdr.srh_sid[2].sid;
    }
    action set_nextsid_4() {
        user_md.srv6.nextsid = hdr.srh_sid[3].sid;
    }
    table srv6_set_nextsid { // helper table
        key = {
            hdr.srh.segmentsLeft : exact;
        }
        actions = {
            NoAction;
            set_nextsid_1;
            set_nextsid_2;
            set_nextsid_3;
            set_nextsid_4;
        }
        const default_action = NoAction;
        const entries = {
            (1) : set_nextsid_1();
            (2) : set_nextsid_2();
            (3) : set_nextsid_3();
            (4) : set_nextsid_4();
        }
    }
// draft-murakami-dmm-user-plane-message-encoding-00
// Bit 0 [B0]: End Marker
// Bit 1 [B1]: Error Indication
// Bit 2 [B2]: Echo Request
// Bit 3 [B3]: Echo Reply
    action set_gtpu_type(bit<8> type) {
        hdr.gtpu.msgtype = type;
    }
    action set_srv6_GTPV1_END() {
        hdr.srh.gtpMessageType = 1;
    }
    action set_srv6_GTPV1_ERROR() {
        hdr.srh.gtpMessageType = 2;
    }
    action set_srv6_GTPV1_ECHO() {
        hdr.srh.gtpMessageType = 4;
    }
    action set_srv6_GTPV1_ECHORES() {
        hdr.srh.gtpMessageType = 8;
    }
    apply {
        if (hdr.srh.isValid()) {
            srv6_set_nextsid.apply();
        }
        if (hdr.ipv6.isValid()) {
                if(srv6_end.apply().hit) {
                    // draft-murakami-dmm-user-plane-message-encoding
                    if (user_md.srv6.gtp_message_type == 1) { // TODO: replace with defined const value
                        set_gtpu_type(GTPV1_END);
                    } else if (user_md.srv6.gtp_message_type == 2) {
                        set_gtpu_type(GTPV1_ERROR);
                    } else if (user_md.srv6.gtp_message_type == 4) {
                        set_gtpu_type(GTPV1_ECHO);
                    } else if (user_md.srv6.gtp_message_type == 8) {
                        set_gtpu_type(GTPV1_ECHORES);
                    }
                } else {
                    srv6_transit_v6.apply();
                }
        } else if (hdr.ipv4.isValid()) {
            if(srv6_transit_udp.apply().hit) {
                // Assuming this is GTP/SRv6 translation
                if (user_md.srv6.gtpv1_type == GTPV1_END) {
                    set_srv6_GTPV1_END();
                } else if (user_md.srv6.gtpv1_type == GTPV1_ERROR){
                    set_srv6_GTPV1_ERROR();
                } else if (user_md.srv6.gtpv1_type == GTPV1_ECHO){
                    set_srv6_GTPV1_ECHO();
                } else if (user_md.srv6.gtpv1_type == GTPV1_ECHORES){
                    set_srv6_GTPV1_ECHORES();
                }
	    } else if (hdr.udp.dport == 0x0043){
		   ipoe_dhcp.apply();
	    } else if (hdr.udp.dport == 0x0044){
		   ipoe_dhcp.apply();
            	} else {
		ipoe_transit.apply();
                srv6_transit_v4.apply();
            }
        }
    }
}


#endif /* _SRV6_ */
