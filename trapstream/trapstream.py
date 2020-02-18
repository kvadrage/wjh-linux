#!/usr/bin/python

import re
import sys
import time
import string
import socket
import struct
import ctypes as ct
import signal
import json
import argparse
import threading

try:
   import queue
except ImportError:
   import Queue as queue
try:
    from bcc import BPF
    from bcc.utils import printb
except ImportError:
    sys.stderr.write("Can't import bcc library\n")
    exit(1)

ETH_ALEN = 6
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
TRAP_NAME_LEN = 40
TRAP_GROUP_NAME_LEN = 20
IFNAMSIZ = 16
IPPROTO_TCP = 6
IPPROTO_UDP = 17

DEFAULT_SEND_INTERVAL = 5.0 # seconds
DEFAULT_RETRY_TIMEOUT = 10.0 # seconds
DEFAULT_BATCH_SIZE = 20
DEFAULT_STREAM_FORMAT = "json"

b = None
streamer = None
wjh_events_queue = None
verbose = False
device_ip = "0.0.0.0"
trap_reasons_map = dict()

TRAP_SMAC_MC = ("Source MAC is multicast", "Bad packet was received from peer", "Error")
TRAP_RSV_MAC = ("Destination MAC is Reserved (DMAC=01-80-C2-00-00-0x)", "Bad packet was received from peer", "Error")
TRAP_VLAN_TAG_MISMATCH = ("VLAN tagging mismatch", "Validate the VLAN tag configuration on both ends of the link", "Error")
TRAP_INGRESS_VLAN_FILTER = ("Ingress VLAN filtering ", "Validate the VLAN membership configuration on both ends of the link", "Error")
TRAP_INGRESS_STP_FILTER = ("Ingress spanning tree filter", "Validate the VLAN membership configuration on both ends of the link", "Notice")
TRAP_EMPTY_TX_LIST = ("Multicast egress port list is empty", "Validate why IGMP Join or multicast router port does not exist", "Warning")
TRAP_PORT_LOOPBACK_FILTER = ("Port loopback filter", "Validate MAC table for this destination MAC ", "Error")
TRAP_BLACKHOLE_ROUTE = ("Blackhole route", "Validate routing table for this destination IP", "Warning")
TRAP_NON_IP_PACKET = ("Non IP packet", "Destination MAC is the router, packet is not routable", "Notice")
TRAP_UC_DIP_MC_DMAC = ("Unicast destination IP but multicast destination MAC", "Bad packet was recieved from peer", "Error")
TRAP_DIP_LB = ("Destination IP is loopback address", "Bad packet was recived  from the peer ", "Error")
TRAP_SIP_MC = ("Source IP is multicast", "Bad packet was recived  from the peer ", "Error")
TRAP_SIP_LB = ("Source IP is loopback address", "Bad packet was received from the peer", "Error")
TRAP_SIP_CLASS_E = ("Source IP is in class E", "Bad packet was recived  from the peer", "Error")
TRAP_SIP_UNSPEC = ("Source ip is unspecified", "Bad packet was recived  from the peer", "Error")
TRAP_CORRUPTED_IP_HDR = ("Checksum or IPver or IPv4 IHL too short", "Bad cable or bad packet was recived from the peer", "Error")
TRAP_IPV4_SIP_BC = ("IPv4 source IP is limited broadcast", "Bad packet was received from the peer", "Error")
TRAP_IPV4_DIP_LOCAL_NET = ("IPv4 destination IP is local network (destination = 0.0.0.0/8)", "Bad packet was received from the peer", "Error")
TRAP_IPV4_DIP_LINK_LOCAL = ("IPv4 destination IP is link local", "Bad packet was received from the peer ", "Error")
TRAP_IPV6_MC_DIP_RESERVED_SCOPE = ("IPv6 destination in multicast scope FFx0:/16", "Expected behavior - packet is not routable", "Notice")
TRAP_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE = ("IPv6 destination in multicast scope FFx1:/16", "Expected behavior - packet is not routable", "Notice")
TRAP_MTU_ERROR = ("Packet size is larger than router interface MTU", "Validate the router interface MTU configuration", "Warning")
TRAP_TTL_ERROR = ("TTL value is too small", "Actual path is longer than the TTL", "Warning")
TRAP_IRIF_EN = ("Ingress router interface is disabled", "Validate your configuration", "Warning")
TRAP_ERIF_EN = ("Egress router interface is disabled", "Validate your configuration", "Warning")
TRAP_RPF = ("Multicast reverse-path forwarding (RPF) error", "Validate your multicast routing configuration", "Error")
TRAP_REJECT_ROUTE = ("Non-routable packet", "Expected behavior", "Error")
TRAP_UNRESOLVED_NEIGH = ("Unresolved  neighbor /next-hop", "Validate ARP table for the neighbor/next hop", "Warning")
TRAP_BLACKHOLE_NEIGH = ("Blackhole ARP/ neighbor", "Validate ARP table for the next hop", "Warning")
TRAP_IPV4_LPM_UNICAST_MISS = ("IPv4 routing table (LPM) unicast miss", "Validate routing table for this destination IP", "Warning")
TRAP_IPV6_LPM_UNICAST_MISS = ("IPv6 routing table (LPM) unicast miss", "Validate routing table for this destination IP", "Warning")
TRAP_SIP_EQ_DIP = ("Source IP equals destination IP", "Bad packet was received from the peer", "Error")
TRAP_SMAC_EQ_DMAC = ("Source MAC equals destination MAC", "Bad packet was received from peer", "Error")
TRAP_MLAG_PORT_ISOLATE = ("MLAG port isolation ", "Expected behavior", "Notice")
TRAP_MC_DMAC_MISMATCH = ("Multicast MAC mismatch", "Bad packet was received from peer", "Error")
TRAP_LOOKUP_SWITCH_UC = ("Unicast MAC table action discard", "Validate MAC table for this destination MAC", "Error")
TRAP_OVERLAY_SMAC_MC = ("Overlay switch - Source MAC is multicast", "Bad packet was received from peer", "Error")
TRAP_OVERLAY_SMAC_EQ_DMAC = ("Overlay switch - Source MAC equals destination MAC", "Bad packet was received from peer", "Error")
TRAP_TAIL_DROP = ("Buffer Tail Drop", "Monitor network congestion", "Warning")
TRAP_WRED_DROP = ("Buffer WRED Drop", "Monitor network congestion", "Warning")

bpf_text = '''
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <net/devlink.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_tunnel.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define FLOW_UNIQUE 0
#define FLOW_LIFETIME 10000000000 /* 10 seconds */

#define IP_OFFSET                       0x1FFF
#define VLAN_VID_MASK		        0x0FFF /* VLAN Identifier */
#define TRAP_NAME_LEN                   40
#define TRAP_GROUP_NAME_LEN             20

#define vlan_tag_get_id(vlan_tci)	(vlan_tci & VLAN_VID_MASK)
#define vlan_tag_get_pcp(vlan_tci)	(vlan_tci >> 13)

struct vlan_hdr {
        __be16 h_vlan_TCI;
        __be16 h_vlan_encapsulated_proto;
};

struct gre_hdr {
        __be16 flags;
        __be16 proto;
};

struct devlink_trap_item {
        const struct devlink_trap *trap;
};

#define TRAP_NAME_LEN 40

struct flow_key_record {
        unsigned char smac[ETH_ALEN];
        unsigned char dmac[ETH_ALEN];
        __u16 eth_proto;
        __u16 vlan_id;
        __u8 vlan_pcp;
        __be32 saddrv4;
        __be32 daddrv4;
        __u32 saddrv6[4];
        __u32 daddrv6[4];
        __u16 addr_proto;	/* ETH_P_IP or ETH_P_IPV6 */
        __u16 sport;
        __u16 dport;
        __u8 ip_proto;
        __u8 tos;
        __u8 ttl;
        __u16 length;
        __u8 is_encap;
};

struct trap_data {
        __u16 id;
        char name[TRAP_NAME_LEN];
        char group_name[TRAP_GROUP_NAME_LEN];
        char in_port_name[IFNAMSIZ];
        __u64 timestamp_ns;
        struct flow_key_record packet;
};

struct trap_flow_info {
        __u64 first_ts_ns;
        __u64 counter;
};

BPF_PERF_OUTPUT(stream_trap_events);
BPF_TABLE("lru_hash", struct trap_data, struct trap_flow_info, flows, 1024);

static __always_inline bool flow_dissector_valid_access(struct sk_buff *skb,
                                                        __u16 offset,
                                                        __u16 hdr_size)
{
        unsigned int len, data_len;

        bpf_probe_read(&len, sizeof(len), &skb->len);
        bpf_probe_read(&data_len, sizeof(data_len), &skb->data_len);

        /* Verify this variable offset does not overflow. */
        if (offset > (USHRT_MAX - hdr_size))
                return false;

        /* Make sure we only access data in linear area. */
        return offset + hdr_size < len - data_len;
}

static __always_inline bool
flow_dissector_ipv4_dissect(struct sk_buff *skb, struct flow_key_record *flow,
                            __u16 *p_offset)
{
        void *skb_data = (void *)(long) skb->data;
        struct iphdr iph;

        if (!flow_dissector_valid_access(skb, *p_offset, sizeof(iph)))
                return false;

        bpf_probe_read(&iph, sizeof(iph), skb_data + *p_offset);

        if (iph.ihl < 5)
                return false;

        flow->addr_proto = ETH_P_IP;
        flow->saddrv4 = iph.saddr;
        flow->daddrv4 = iph.daddr;
        flow->ip_proto = iph.protocol;
        flow->tos = iph.tos;
        flow->ttl = iph.ttl;
        flow->length = iph.tot_len;

        /* After the first frag, packets do not have headers to parse, so
            * return false to stop the dissection.
            */
        if (iph.frag_off & htons(IP_OFFSET))
                return false;

        *p_offset += iph.ihl << 2;

        return true;
}

static __always_inline bool
flow_dissector_ipv6_dissect(struct sk_buff *skb, struct flow_key_record *flow,
                            __u16 *p_offset)
{
        void *skb_data = (void *)(long) skb->data;
        struct ipv6hdr ip6h;

        if (!flow_dissector_valid_access(skb, *p_offset, sizeof(ip6h)))
                return false;

        bpf_probe_read(&ip6h, sizeof(ip6h), skb_data + *p_offset);

        flow->addr_proto = ETH_P_IPV6;
        __builtin_memcpy(flow->saddrv6, &ip6h.saddr, sizeof(flow->saddrv6));
        __builtin_memcpy(flow->daddrv6, &ip6h.daddr, sizeof(flow->daddrv6));
        flow->ip_proto = ip6h.nexthdr;
        flow->tos = ip6h.priority;
        flow->ttl = ip6h.hop_limit;
        flow->length = ip6h.payload_len;

        *p_offset += sizeof(ip6h);

        return true;
}

static __always_inline bool
flow_dissector_gre_dissect(struct sk_buff *skb, struct flow_key_record *flow,
                            __u16 *p_offset)
{
        void *skb_data = (void *)(long) skb->data;
        struct gre_hdr gre;

        if (!flow_dissector_valid_access(skb, *p_offset, sizeof(gre)))
                return false;

        bpf_probe_read(&gre, sizeof(gre), skb_data + *p_offset);

        if (gre.flags & GRE_VERSION)
                return false;

        *p_offset += sizeof(gre);
        if (GRE_IS_CSUM(gre.flags))
                *p_offset += 4;
        if (GRE_IS_KEY(gre.flags))
                *p_offset += 4;
        if (GRE_IS_SEQ(gre.flags))
                *p_offset += 4;

        if (gre.proto == htons(ETH_P_IP))
                return flow_dissector_ipv4_dissect(skb, flow, p_offset);
        else if (gre.proto == htons(ETH_P_IPV6))
                return flow_dissector_ipv6_dissect(skb, flow, p_offset);

        return false;
}

static __always_inline bool
flow_dissector_udp_dissect(struct sk_buff *skb, struct flow_key_record *flow,
                            __u16 *p_offset)
{
        void *skb_data = (void *)(long) skb->data;
        struct udphdr udp;

        if (!flow_dissector_valid_access(skb, *p_offset, sizeof(udp)))
                return false;

        bpf_probe_read(&udp, sizeof(udp), skb_data + *p_offset);

        flow->sport = ntohs(udp.source);
        flow->dport = ntohs(udp.dest);

        *p_offset += ntohs(udp.len);

        return true;
}

static __always_inline bool
flow_dissector_tcp_dissect(struct sk_buff *skb, struct flow_key_record *flow,
                            __u16 *p_offset)
{
        void *skb_data = (void *)(long) skb->data;
        struct tcphdr tcp;

        if (!flow_dissector_valid_access(skb, *p_offset, sizeof(tcp)))
                return false;

        bpf_probe_read(&tcp, sizeof(tcp), skb_data + *p_offset);

        if (tcp.doff < 5 || tcp.doff > 15)
                return false;

        flow->sport = ntohs(tcp.source);
        flow->dport = ntohs(tcp.dest);

        *p_offset += tcp.doff << 2;

        return true;
}

static __always_inline void flow_dissector(struct sk_buff *skb,
                                            struct flow_key_record *flow)
{
        void *skb_data = (void *)(long) skb->data;
        struct vlan_hdr vlan_hdr;
        __u16 offset;
        struct ethhdr eth;

        if (!flow_dissector_valid_access(skb, 0, sizeof(eth)))
                return;

        bpf_probe_read(&eth, sizeof(eth), skb_data);

        offset = ETH_HLEN;
        __builtin_memcpy(flow->smac, &eth.h_source, sizeof(flow->smac));
        __builtin_memcpy(flow->dmac, &eth.h_dest, sizeof(flow->dmac));
        flow->eth_proto = ntohs(eth.h_proto);

        if (flow->eth_proto == ETH_P_8021AD) {
                bpf_probe_read(&vlan_hdr, sizeof(vlan_hdr), skb_data + offset);
                offset += sizeof(struct vlan_hdr);
                flow->eth_proto = ntohs(vlan_hdr.h_vlan_encapsulated_proto);
        }

        if (flow->eth_proto == ETH_P_8021Q) {
                bpf_probe_read(&vlan_hdr, sizeof(vlan_hdr), skb_data + offset);
                offset += sizeof(struct vlan_hdr);
                flow->eth_proto = ntohs(vlan_hdr.h_vlan_encapsulated_proto);
                flow->vlan_id = vlan_tag_get_id(vlan_hdr.h_vlan_TCI);
                flow->vlan_pcp = vlan_tag_get_pcp(vlan_hdr.h_vlan_TCI);
        }

        switch (flow->eth_proto) {
        case ETH_P_IP:
                if (!flow_dissector_ipv4_dissect(skb, flow, &offset))
                        return;
                break;
        case ETH_P_IPV6:
                if (!flow_dissector_ipv6_dissect(skb, flow, &offset))
                        return;
                break;
        default:
                return;
        }

        switch (flow->ip_proto) {
        case IPPROTO_IPIP:
                flow->is_encap = true;
                if (!flow_dissector_ipv4_dissect(skb, flow, &offset))
                        return;
                break;
        case IPPROTO_IPV6:
                flow->is_encap = true;
                if (!flow_dissector_ipv6_dissect(skb, flow, &offset))
                        return;
                break;
        case IPPROTO_GRE:
                flow->is_encap = true;
                if (!flow_dissector_gre_dissect(skb, flow, &offset))
                        return;
                break;
        default:
                break;
        }

        switch (flow->ip_proto) {
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
                if (!flow_dissector_udp_dissect(skb, flow, &offset))
                        return;
                break;
        case IPPROTO_TCP:
                if (!flow_dissector_tcp_dissect(skb, flow, &offset))
                        return;
                break;
        default:
                return;
        }
}

int probe_devlink_trap_report_stream(struct pt_regs *ctx, struct devlink *devlink,
			      struct sk_buff *skb, void *trap_ctx)
{
        struct devlink_trap_item *trap_item;
        const struct devlink_trap *trap;
        struct trap_data trap_data = {};
        struct trap_flow_info *val, zero = {};
        struct flow_key_record *flow = &trap_data.packet;
        __u64 ts;

        trap_item = (struct devlink_trap_item *) trap_ctx;
        trap = trap_item->trap;

        flow_dissector(skb, flow);

        bpf_probe_read(&trap_data.id, sizeof(trap_data.id), &trap->id);
        bpf_probe_read_str(&trap_data.name, TRAP_NAME_LEN, trap->name);
        bpf_probe_read_str(&trap_data.group_name, TRAP_GROUP_NAME_LEN,
                        trap->group.name);
        bpf_probe_read_str(&trap_data.in_port_name, IFNAMSIZ, 
                        skb->dev->name);

        ts = bpf_ktime_get_ns();
        if (FLOW_UNIQUE) {
                trap_data.timestamp_ns = 0;
                zero.first_ts_ns = ts;
                val = flows.lookup(&trap_data);
                if (val) {
                        if (ts - val->first_ts_ns < FLOW_LIFETIME) {
                                val->counter++;
                                return 0;
                        }
                        flows.delete(&trap_data);
                }
                flows.insert(&trap_data, &zero);
        }
        trap_data.timestamp_ns = ts;
        stream_trap_events.perf_submit(ctx, &trap_data, sizeof(trap_data));               

        return 0;
}
'''

class FlowKeyRecord(ct.Structure):
    _fields_ = [
        ('smac', ct.c_ubyte * ETH_ALEN),
        ('dmac', ct.c_ubyte * ETH_ALEN),
        ('eth_proto', ct.c_uint16),
        ('vlan_id', ct.c_uint16),
        ('vlan_pcp', ct.c_uint8),
        ('saddrv4', ct.c_uint32),
        ('daddrv4', ct.c_uint32),
        ('saddrv6', ct.c_uint32 * 4),
        ('daddrv6', ct.c_uint32 * 4),
        ('addr_proto', ct.c_uint16),
        ('sport', ct.c_uint16),
        ('dport', ct.c_uint16),
        ('ip_proto', ct.c_uint16),
        ('tos', ct.c_uint8),
        ('ttl', ct.c_uint8),
        ('length', ct.c_uint16),
        ('is_encap', ct.c_uint16),
    ]

class TrapEvent(ct.Structure):
    _fields_ = [
        ('id', ct.c_uint16),
        ('name', ct.c_char * TRAP_NAME_LEN),
        ('group_name', ct.c_char * TRAP_GROUP_NAME_LEN),
        ('in_port_name', ct.c_char * IFNAMSIZ),
        ('timestamp_ns', ct.c_uint64),
        ('packet', FlowKeyRecord),
    ]


class EventFormatInflux(object):

    class InfluxFormatter(string.Formatter):
        def convert_field(self, value, conversion):
            if conversion == 'w':
                return str(value).replace(' ', '\\ ')
            else:
                return string.Formatter.convert_field(self, value, conversion)    

    _fmt_influx_packet_ethernet = '''
packet_ethernet_etherType={etherType},
packet_ethernet_etherTypeName={etherTypeName!w},
packet_ethernet_dstMac={dstMac},
packet_ethernet_srcMac={srcMac},
packet_ethernet_pcp={pcp},
packet_ethernet_vlanId={vlanId},
'''
    _fmt_influx_packet_ip = '''
packet_ip_srcIp={srcIp},
packet_ip_dstIp={dstIp},
packet_ip_length={length},
packet_ip_protocol={protocol},
packet_ip_protocolName={protocolName!w},
packet_ip_tos={tos},
packet_ip_ttl={ttl},
'''
    _fmt_influx_packet_transport = '''
packet_transport_dstPort={dstPort},
packet_transport_dstPortName={dstPortName!w},
packet_transport_srcPort={srcPort},
packet_transport_srcPortName={srcPortName!w},
'''
    _fmt_influx = '''
DroppedPackets,description={description!w},
deviceIP={deviceIP!w},
dropReason={dropReason!w},
dropType={dropType!w},
ingressPort={ingressPort!w},
message={message!w},
{ethernet}
{ip}
{transport}
severity={severity!w} packet_packetType="{packetType}",
timestamp="{timestamp}" {influx_timestamp}
'''
    def __init__(self, event):
        self.event = event
        
    def format(self):
        fmt = self.InfluxFormatter()
        ev = self.event
        packet = ev["packet"]
        packet_type = packet["packetType"].lower()
        influx_packet_eth = ""
        influx_packet_ip = ""
        influx_packet_transport = ""
        
        if packet_type in ("ethernet", "ip", "transport"):
            influx_packet_eth = fmt.format(self._fmt_influx_packet_ethernet,
                                           **packet["ETHERNET"])
        if packet_type in ("ip", "transport"):
            influx_packet_ip = fmt.format(self._fmt_influx_packet_ip, **packet["IP"])
        if packet_type == "transport":
            influx_packet_transport = fmt.format(self._fmt_influx_packet_transport,
                                                 **packet["TRANSPORT"])
            
        timestamp = int(time.time() * 1000000)
        line = fmt.format(self._fmt_influx,
                          packetType=packet_type,
                          ethernet=influx_packet_eth,
                          ip=influx_packet_ip,
                          transport=influx_packet_transport,
                          influx_timestamp=timestamp,
                          **ev)
        return line.replace("\n","")

    def __str__(self):
        return self.format()
        

class Event(dict):
    def format(self, fmt):
        if fmt == "influx":
            return str(EventFormatInflux(self))
        return str(self)
    

class Queue(queue.Queue):
    def getall(self):
        arr = []
        with self.mutex:
            unfinished = self.unfinished_tasks - len(self.queue)
            if unfinished <= 0:
                if unfinished < 0:
                    raise ValueError('task_done() called too many times')
                self.all_tasks_done.notify_all()
            self.unfinished_tasks = unfinished
            arr = list(self.queue)
            self.queue.clear()
            self.not_full.notify_all()
        return arr

class Streamer(threading.Thread):
    def __init__(self, events_queue, collector_ip, collector_port,
                 interval=DEFAULT_SEND_INTERVAL,
                 retry_timeout=DEFAULT_RETRY_TIMEOUT,
                 batch_size=DEFAULT_BATCH_SIZE,
                 stream_fmt=DEFAULT_STREAM_FORMAT,
                 *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self._stop_event = threading.Event()
        self.events_queue = events_queue
        self.collector_ip = collector_ip
        self.collector_port = collector_port
        self.interval = interval
        self.retry_timeout = retry_timeout
        self.batch_size = batch_size
        self.stream_fmt = stream_fmt
        
    def run(self):
        print('Starting streamer...')
        while not self._stop_event.isSet():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print("Connecting to %s:%d..." % (self.collector_ip,
                                                  self.collector_port))
                s.connect((self.collector_ip, self.collector_port))
            except socket.error as e:
                # try to reconnect on error
                print("Connection error: '%s'. Reconnecting in %ds..." % 
                      (e, self.retry_timeout))
                self._stop_event.wait(self.retry_timeout)
                continue
            print("Connected.")
            socket_error = False
            while not self._stop_event.isSet():
                self._stop_event.wait(self.interval)
                events = self.events_queue.getall()
                print("Got %d WJH events from queue" % (len(events)))
                while events:
                    # send events in batches
                    batch = events[:self.batch_size]
                    events = events[self.batch_size:]
                    if self.stream_fmt == "json":
                        # convert events batch to JSON
                        msg = json.dumps(batch)+"\n"
                    else:
                        # use custom format of the events
                        fmt_batch = [event.format(self.stream_fmt) for event in batch]
                        msg = "\n".join(fmt_batch) + '\n'
                    # send the batch
                    try:
                        print("Sending batch of %d events..." % len(batch))
                        s.sendall(msg.encode("utf-8"))
                    except socket.error as e:
                        print("Error sending data: %s" % e)
                        socket_error = True
                        break
                if socket_error:       
                    break  

    def shutdown(self):
        self._stop_event.set()
        print('Shutting down streamer...')
        self.join()    


def get_trap_info(trap_id):
    return trap_reasons_map.get(trap_id, (trap_id, "N/A", "N/A"))

# convert trap event into WJH event
def process_trap_event(cpu, data, size):
    event = Event       ()
    packet = dict()
    
    trap = ct.cast(data, ct.POINTER(TrapEvent)).contents
    
    packet["packetType"] = "ETHERNET"
    packet["ETHERNET"] = {
        "etherTypeName": hex(trap.packet.eth_proto),
        "etherType": trap.packet.eth_proto,
        "srcMac": ":".join([format(x, "02x") for x in trap.packet.smac]),
        "dstMac": ":".join([format(x, "02x") for x in trap.packet.dmac]),
        "vlanId": trap.packet.vlan_id,
        "pcp": trap.packet.vlan_pcp
    }
    if trap.packet.addr_proto == ETH_P_IP:
        packet["IP"] = {
            "srcIp": socket.inet_ntop(socket.AF_INET, struct.pack('I',  trap.packet.saddrv4)), 
            "dstIp": socket.inet_ntop(socket.AF_INET, struct.pack('I',  trap.packet.daddrv4)), 
            "protocol": trap.packet.ip_proto,
            "protocolName": str(trap.packet.ip_proto),
            "length": trap.packet.length,
            "tos": trap.packet.tos,
            "ttl": trap.packet.ttl
        }
        packet["packetType"] = "IP"
    elif trap.packet.addr_proto == ETH_P_IPV6:
        packet["IP"] = {
            "srcIp": socket.inet_ntop(socket.AF_INET6, trap.packet.saddrv6), 
            "dstIp": socket.inet_ntop(socket.AF_INET6, trap.packet.daddrv6), 
            "protocol": trap.packet.ip_proto,
            "protocolName": hex(trap.packet.ip_proto),
            "length": trap.packet.length,
            "tos": trap.packet.tos,
            "ttl": trap.packet.ttl
        }
        packet["packetType"] = "IP"
    
    if trap.packet.ip_proto in (IPPROTO_TCP, IPPROTO_UDP):
        packet["TRANSPORT"] = {
            "srcPort": trap.packet.sport, 
            "dstPort": trap.packet.dport,
            "srcPortName": str(trap.packet.sport),
            "dstPortName": str(trap.packet.dport)
        }
        packet["packetType"] = "TRANSPORT"            
    
    event["deviceIP"] = device_ip
    event["ingressPort"] = trap.in_port_name.decode("utf-8")
    trap_info = get_trap_info(trap.name.decode("utf-8"))
    reason, descr, severity = trap_info 
    event["description"] = descr
    event["severity"] = severity
    event["dropType"] = "l2"
    event["dropReason"] = reason
    event["timestamp"] = str(time.time())
    event["message"] = "fwdDrop"
    event["packet"] = packet
    
    if verbose:
        print(event)
    wjh_events_queue.put(event)

def sig_handler(signum, stack):
    print('Exiting...')
    streamer.shutdown()
    sys.exit(signum)

def get_devlink_trap_reasons_map():
    devlink_trap_reasons_map = {
        "source_mac_is_multicast": TRAP_SMAC_MC,
        "vlan_tag_mismatch": TRAP_VLAN_TAG_MISMATCH,
        "ingress_vlan_filter": TRAP_INGRESS_VLAN_FILTER,
        "ingress_spanning_tree_filter": TRAP_INGRESS_STP_FILTER,
        "port_list_is_empty": TRAP_EMPTY_TX_LIST,
        "port_loopback_filter": TRAP_PORT_LOOPBACK_FILTER,
        "blackhole_route": TRAP_BLACKHOLE_ROUTE,
        "ttl_value_is_too_small": TRAP_TTL_ERROR,
        "tail_drop": TRAP_TAIL_DROP,
        "non_ip": TRAP_NON_IP_PACKET,
        "uc_dip_over_mc_dmac": TRAP_UC_DIP_MC_DMAC,
        "dip_is_loopback_address": TRAP_DIP_LB,
        "sip_is_mc": TRAP_SIP_MC,
        "sip_is_loopback_address": TRAP_SIP_LB,
        "ip_header_corrupted": TRAP_CORRUPTED_IP_HDR,
        "ipv4_sip_is_limited_bc": TRAP_IPV4_SIP_BC,
        "ipv6_mc_dip_reserved_scope": TRAP_IPV6_MC_DIP_RESERVED_SCOPE,
        "ipv6_mc_dip_interface_local_scope": TRAP_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE,
        "mtu_value_is_too_small": TRAP_MTU_ERROR,
        "unresolved_neigh": TRAP_UNRESOLVED_NEIGH,
        "mc_reverse_path_forwarding": TRAP_RPF,
        "reject_route": TRAP_REJECT_ROUTE,
        "ipv4_lpm_miss": TRAP_IPV4_LPM_UNICAST_MISS,
        "ipv6_lpm_miss": TRAP_IPV6_LPM_UNICAST_MISS,
    }
    return devlink_trap_reasons_map

def bpf_load_program(file):
    bpf_text = None
    try:
        with open(file, "r") as f:
            bpf_text = f.read()
    except:
        return None
    return bpf_text

def bpf_parametrize(bpf_text, args):
    res = bpf_text
    if args.unique_interval:
        print("Unique flows filtering enabled (within %ds interval)" % args.unique_interval)
        flow_lifetime = args.unique_interval * 1000000000 # nanoseconds
        res = re.sub("#define FLOW_UNIQUE.*", "#define FLOW_UNIQUE 1", res)
        res = re.sub("#define FLOW_LIFETIME.*", "#define FLOW_LIFETIME %s" % flow_lifetime, res)
    return res
        
def main(args):
    global verbose
    global device_ip
    global wjh_events_queue
    global trap_reasons_map
    global streamer
    global b

    verbose = args.verbose
    device_ip = args.device_ip
    wjh_events_queue = Queue()
    streamer = Streamer(wjh_events_queue,
                           args.collector_ip,
                           args.collector_port,
                           interval=args.interval,
                           retry_timeout=args.retry_timeout,
                           batch_size=args.batch_size,
                           stream_fmt=args.format)
    
    trap_reasons_map = get_devlink_trap_reasons_map()
    b = BPF(text=bpf_parametrize(bpf_text, args))
    if b.get_kprobe_functions(b"devlink_trap_report"):
        b.attach_kprobe(event="devlink_trap_report", 
                        fn_name="probe_devlink_trap_report_stream")
    else:
        print("ERROR: devlink_trap_report() kernel function not found or traceable. "
            "Older kernel versions not supported.")
        sys.exit()

    b["stream_trap_events"].open_perf_buffer(process_trap_event)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    streamer.start()
    while True:
        b.perf_buffer_poll()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description='Stream hardware packet traps to remote collector')
    parser.add_argument('collector_ip', type=str,
                        help='Collector server IP address')
    parser.add_argument('collector_port', type=int,
                        help='Collector server port')
    parser.add_argument('-v', '--verbose', help='increase output verbosity',
                    action='store_true')
    parser.add_argument('-i', '--interval', default=DEFAULT_SEND_INTERVAL,
                        help='Sent interval')
    parser.add_argument('-r', '--retry_timeout', default=DEFAULT_RETRY_TIMEOUT,
                        help='Connection retry timeout')
    parser.add_argument('-b', '--batch_size', default=DEFAULT_BATCH_SIZE,
                        help='Max number of events in one batch to send to collector')
    parser.add_argument('-d', '--device_ip', default="0.0.0.0",
                        help='Device IP address')
    parser.add_argument('-f', '--format', default=DEFAULT_STREAM_FORMAT,
                        help='Streaming format [json|influx]')
    parser.add_argument('-u', '--unique_interval', type=int,
                        help='Process only unique flows within specified interval (in seconds)')
    args = parser.parse_args()
    main(args)