#!/usr/bin/env python
"""
ryu_ddos_collector.py: SDN Flow Statistics Collector for AI Training.
"""
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import in_proto
import time
import os
import argparse

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager

CSV_FILENAME = "/ryu/app/FlowStatsfile.csv"
COLUMNS = ('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,'
           'icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,'
           'idle_timeout,hard_timeout,flags,packet_count,byte_count,'
           'packet_count_per_second,packet_count_per_nsecond,'
           'byte_count_per_second,byte_count_per_nsecond,label\n')
MONITOR_INTERVAL = 10


class CollectTrainingStatsApp(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)

        # parse custom args passed by ryu-manager (see custom_arg_parser below)
        if 'custom_args' in kwargs:
            custom_args = kwargs['custom_args']
            try:
                self.label = int(custom_args.get('label', 0))
            except Exception:
                self.label = 0
        else:
            self.label = 0

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        self.initialize_csv_file()
        self.logger.info("Collector started with LABEL={0}. Output file: {1}"
                         .format(self.label, CSV_FILENAME))

    def initialize_csv_file(self):
        """Create CSV file with header if missing."""
        if not os.path.exists(CSV_FILENAME):
            with open(CSV_FILENAME, "w") as f:
                f.write(COLUMNS)
            self.logger.info("Created new CSV file: {0}".format(CSV_FILENAME))
        else:
            self.logger.info("Appending to existing CSV file: {0}".format(CSV_FILENAME))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle PacketIn: let parent do L2 learning & flood behavior,
        then install a relatively broad flow (in_port + eth_dst [+ eth_type])
        so subsequent packets are forwarded in-switch quickly.
        """
        # call parent's learning behavior (updates mac_to_port etc)
        super(CollectTrainingStatsApp, self)._packet_in_handler(ev)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port', None)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # only install flows for IP packets (we still let parent handle ARP/LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        dst = eth.dst
        dpid = datapath.id

        # derive out_port from parent's mac_to_port table if present
        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]

        # If we know out_port, install a simple flow to forward (fast path)
        if out_port != ofproto.OFPP_FLOOD and in_port is not None:
            # prefer a simple L2-based match to avoid over-specific matches that miss traffic
            # include eth_type when available to avoid touching non-IP flows
            match_fields_simple = {'in_port': in_port, 'eth_dst': dst, 'eth_type': ether_types.ETH_TYPE_IP}
            try:
                match = parser.OFPMatch(**match_fields_simple)
            except Exception:
                # fallback to minimal match
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            # log for debug
            self.logger.debug("DPID %s: installing flow match=%s -> out=%s", dpid, match_fields_simple, out_port)

            # install at medium priority for stats collection
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=1,
                                    idle_timeout=15,
                                    hard_timeout=30,
                                    match=match,
                                    instructions=inst)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        """Periodically request flow stats from datapaths."""
        while True:
            for dp in list(self.datapaths.values()):
                try:
                    self.request_stats(dp)
                except Exception as e:
                    self.logger.exception("request_stats error: %s", e)
            hub.sleep(MONITOR_INTERVAL)

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, cookie=0, match=parser.OFPMatch(), table_id=0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Write flow stats (priority==1 flows) into CSV for ML training."""
        timestamp = time.time()
        with open(CSV_FILENAME, "a+") as f:
            body = ev.msg.body
            # only consider flows we installed (priority == 1)
            flows = [flow for flow in body if getattr(flow, 'priority', 0) == 1]
            # sort by ipv4_src, ipv4_dst for stable output
            def sort_key(flow):
                m = getattr(flow, 'match', {})
                return (m.get('ipv4_src', ''), m.get('ipv4_dst', ''))
            for stat in sorted(flows, key=sort_key):
                match = stat.match
                ip_src = match.get('ipv4_src', 'N/A')
                ip_dst = match.get('ipv4_dst', 'N/A')
                ip_proto = match.get('ip_proto', -1)

                icmp_code = -1
                icmp_type = -1
                tp_src = 0
                tp_dst = 0

                if ip_proto == in_proto.IPPROTO_ICMP:
                    icmp_code = match.get('icmpv4_code', -1)
                    icmp_type = match.get('icmpv4_type', -1)
                elif ip_proto == in_proto.IPPROTO_TCP:
                    tp_src = match.get('tcp_src', 0)
                    tp_dst = match.get('tcp_dst', 0)
                elif ip_proto == in_proto.IPPROTO_UDP:
                    tp_src = match.get('udp_src', 0)
                    tp_dst = match.get('udp_dst', 0)

                flow_id = "{}{}{}{}{}".format(ip_src, tp_src, ip_dst, tp_dst, ip_proto)

                duration_sec = getattr(stat, 'duration_sec', 0)
                duration_nsec = getattr(stat, 'duration_nsec', 0)
                packet_count = getattr(stat, 'packet_count', 0)
                byte_count = getattr(stat, 'byte_count', 0)

                # safe division
                packet_count_per_second = float(packet_count) / duration_sec if duration_sec else 0
                packet_count_per_nsecond = float(packet_count) / duration_nsec if duration_nsec else 0
                byte_count_per_second = float(byte_count) / duration_sec if duration_sec else 0
                byte_count_per_nsecond = float(byte_count) / duration_nsec if duration_nsec else 0

                f.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                    timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                    ip_proto, icmp_code, icmp_type,
                    duration_sec, duration_nsec,
                    stat.idle_timeout, stat.hard_timeout,
                    stat.flags, packet_count, byte_count,
                    packet_count_per_second, packet_count_per_nsecond,
                    byte_count_per_second, byte_count_per_nsecond,
                    self.label
                ))


def custom_arg_parser(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', type=int, default=0, help='Traffic label: 0 for Normal, 1 for Attack.')
    # parse arguments passed after the app name
    try:
        app_name = next(name for name in argv if name.startswith('ryu_ddos_collector'))
        idx = argv.index(app_name)
        args, unknown = parser.parse_known_args(argv[idx + 1:])
    except (ValueError, StopIteration):
        args, unknown = parser.parse_known_args(argv[1:])
    return {'label': args.label}


# hook custom parser into Ryu app manager
app_manager.require_app('ryu.base.app_manager', custom_arg_parser)
