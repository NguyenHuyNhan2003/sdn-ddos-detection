# /ryu/app/ryu_collect_ddos_traffic.py
# Python 2.7 compatible - defensive parsing + consistent 22-column CSV rows (label always 1)
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
import hashlib

from ryu.app import simple_switch_13 as switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

FLOW_CSV = "/ryu/app/FlowStatsfile.csv"
RAW_DIR = "/ryu/app/raw_packets"

class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self.monitor)

        # ensure raw packet dir
        try:
            if not os.path.exists(RAW_DIR):
                os.makedirs(RAW_DIR)
        except Exception:
            self.logger.exception("could not create RAW_DIR")

        # ensure CSV header (exact header you requested)
        header = ('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,'
                  'icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,'
                  'hard_timeout,flags,packet_count,byte_count,packet_count_per_second,'
                  'packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,label\n')
        try:
            if not os.path.exists(FLOW_CSV):
                f0 = open(FLOW_CSV, "w")
                f0.write(header)
                f0.close()
        except Exception:
            self.logger.exception("could not create FLOW_CSV")

    def _save_raw_packet(self, datapath, in_port, msg, err_str):
        try:
            ts = int(time.time())
            payload = getattr(msg, "data", "") or ""
            h = hashlib.sha1(payload).hexdigest()[:10]
            dpid = getattr(datapath, "id", "none")
            fname = "pkt_{0}_{1}_{2}.bin".format(dpid, ts, h)
            path = os.path.join(RAW_DIR, fname)
            try:
                with open(path, "wb") as bf:
                    bf.write(payload)
            except Exception:
                self.logger.exception("failed writing raw pkt file")
            # append simple meta
            meta_path = os.path.join(RAW_DIR, "meta.csv")
            try:
                with open(meta_path, "a") as mf:
                    mf.write("{0},{1},{2},{3},{4},\"{5}\",\"{6}\"\n".format(
                        ts,
                        dpid,
                        in_port if in_port is not None else -1,
                        getattr(msg, "buffer_id", -1),
                        len(payload) if payload else 0,
                        fname,
                        str(err_str).replace("\n", " ")
                    ))
            except Exception:
                self.logger.exception("failed writing meta csv")
        except Exception:
            self.logger.exception("unexpected error while saving raw pkt")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # safe in_port
        try:
            in_port = msg.match.get('in_port')
        except Exception:
            try:
                in_port = msg.match['in_port']
            except Exception:
                in_port = None

        timestamp = time.time()
        # open CSV append
        try:
            file0 = open(FLOW_CSV, "a+")
        except Exception:
            self.logger.exception("cannot open flow csv")
            file0 = None

        # defensive parse
        try:
            pkt = packet.Packet(msg.data)
        except Exception as e:
            byte_len = len(msg.data) if getattr(msg, "data", None) else 0
            # Write 22 columns with label=1, flow_id NA, ip/tp fields NA, packet_count=1, byte_count=byte_len
            if file0:
                try:
                    file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                        timestamp, getattr(datapath, "id", "none"),
                        "NA",        # flow_id
                        "NA", "NA",  # ip_src, tp_src
                        "NA", "NA",  # ip_dst, tp_dst
                        "NA",        # ip_proto
                        "NA", "NA",  # icmp_code, icmp_type
                        0, 0,        # flow_duration_sec, flow_duration_nsec
                        0, 0, 0,     # idle_timeout, hard_timeout, flags
                        1,           # packet_count
                        byte_len,    # byte_count
                        0, 0, 0, 0,  # per-second/nsecond fields
                        1            # label (always 1)
                    ))
                    file0.flush()
                except Exception:
                    self.logger.exception("failed writing malformed row")
            # save raw payload for offline analysis
            self._save_raw_packet(datapath, in_port, msg, e)
            if file0:
                file0.close()
            self.logger.debug("Malformed packet logged (parse error): %s", e)
            return

        # ethernet
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            if file0:
                file0.close()
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # handle ip
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip is None:
                byte_len = len(msg.data) if getattr(msg, "data", None) else 0
                if file0:
                    try:
                        file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                            timestamp, getattr(datapath, "id", "none"),
                            "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA",
                            0, 0, 0, 0, 0, 1, byte_len, 0, 0, 0, 0, 1
                        ))
                        file0.flush()
                    except Exception:
                        self.logger.exception("failed writing malformed IP row")
                self._save_raw_packet(datapath, in_port, msg, "no_ipv4")
                if file0:
                    file0.close()
                return

            protocol = ip.proto
            # prepare defaults
            ip_src = ip.src
            ip_dst = ip.dst
            ip_proto = protocol
            tp_src = "NA"
            tp_dst = "NA"
            icmp_code = "NA"
            icmp_type = "NA"

            # transport
            if protocol == in_proto.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                if t is None:
                    # write broken-tcp row (keep ip info where available)
                    if file0:
                        try:
                            file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                                timestamp, getattr(datapath, "id", "none"),
                                "NA", ip_src, "NA", ip_dst, "NA", ip_proto,
                                "NA", "NA",
                                0, 0, 0, 0, 0, 1, len(msg.data), 0, 0, 0, 0, 1
                            ))
                            file0.flush()
                        except Exception:
                            self.logger.exception("failed writing broken tcp row")
                    self._save_raw_packet(datapath, in_port, msg, "tcp_none")
                    if file0:
                        file0.close()
                    return
                tp_src = t.src_port
                tp_dst = t.dst_port

            elif protocol == in_proto.IPPROTO_UDP:
                u = pkt.get_protocol(udp.udp)
                if u is None:
                    if file0:
                        try:
                            file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                                timestamp, getattr(datapath, "id", "none"),
                                "NA", ip_src, "NA", ip_dst, "NA", ip_proto,
                                "NA", "NA",
                                0, 0, 0, 0, 0, 1, len(msg.data), 0, 0, 0, 0, 1
                            ))
                            file0.flush()
                        except Exception:
                            self.logger.exception("failed writing broken udp row")
                    self._save_raw_packet(datapath, in_port, msg, "udp_none")
                    if file0:
                        file0.close()
                    return
                tp_src = u.src_port
                tp_dst = u.dst_port

            elif protocol == in_proto.IPPROTO_ICMP:
                ic = pkt.get_protocol(icmp.icmp)
                if ic is None:
                    if file0:
                        try:
                            file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                                timestamp, getattr(datapath, "id", "none"),
                                "NA", ip_src, "NA", ip_dst, "NA", ip_proto,
                                "NA", "NA",
                                0, 0, 0, 0, 0, 1, len(msg.data), 0, 0, 0, 0, 1
                            ))
                            file0.flush()
                        except Exception:
                            self.logger.exception("failed writing broken icmp row")
                    self._save_raw_packet(datapath, in_port, msg, "icmp_none")
                    if file0:
                        file0.close()
                    return
                icmp_type = ic.type
                icmp_code = ic.code

            # install flow (only when we have ip_proto set)
            try:
                match_fields = {
                    'in_port': in_port,
                    'eth_type': ether_types.ETH_TYPE_IP,
                    'ipv4_src': ip_src,
                    'ipv4_dst': ip_dst
                }
                # add transport info only when available
                if tp_src != "NA" and tp_dst != "NA":
                    if protocol == in_proto.IPPROTO_TCP:
                        match_fields['ip_proto'] = ip_proto
                        match_fields['tcp_src'] = tp_src
                        match_fields['tcp_dst'] = tp_dst
                    elif protocol == in_proto.IPPROTO_UDP:
                        match_fields['ip_proto'] = ip_proto
                        match_fields['udp_src'] = tp_src
                        match_fields['udp_dst'] = tp_dst
                elif ip_proto == in_proto.IPPROTO_ICMP:
                    match_fields['ip_proto'] = ip_proto
                    match_fields['icmpv4_type'] = icmp_type
                    match_fields['icmpv4_code'] = icmp_code

                match = parser.OFPMatch(**match_fields)
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                        idle_timeout=15, hard_timeout=30,
                                        match=match, instructions=inst)
                datapath.send_msg(mod)
            except Exception:
                self.logger.exception("failed to install flow")

            # Write one CSV row representing this packet (label always 1)
            if file0:
                try:
                    byte_len = len(msg.data) if getattr(msg, "data", None) else 0
                    # flow_id we leave as NA (you can compute from fields if desired)
                    file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                        timestamp, getattr(datapath, "id", "none"),
                        "NA",
                        ip_src, tp_src,
                        ip_dst, tp_dst,
                        ip_proto,
                        icmp_code, icmp_type,
                        0, 0, 0, 0, 0,
                        1,           # packet_count
                        byte_len,    # byte_count
                        0, 0, 0, 0,  # per-second / per-nsecond fields
                        1            # label = 1
                    ))
                    file0.flush()
                except Exception:
                    self.logger.exception("failed writing normal flow row")

        # packet out (original forwarding)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        try:
            datapath.send_msg(out)
        except Exception:
            self.logger.exception("failed to send packetout")

        if file0:
            file0.close()

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
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
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = time.time()
        file0 = None
        try:
            file0 = open(FLOW_CSV, "a+")
            body = ev.msg.body
            for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
                (flow.match.get('eth_type'), flow.match.get('ipv4_src'), flow.match.get('ipv4_dst'), flow.match.get('ip_proto'))):

                ip_src = stat.match.get('ipv4_src', '')
                ip_dst = stat.match.get('ipv4_dst', '')
                ip_proto = stat.match.get('ip_proto', 0)
                icmp_code = -1
                icmp_type = -1
                tp_src = 0
                tp_dst = 0

                if ip_proto == 1:
                    icmp_code = stat.match.get('icmpv4_code', -1)
                    icmp_type = stat.match.get('icmpv4_type', -1)
                elif ip_proto == 6:
                    tp_src = stat.match.get('tcp_src', 0)
                    tp_dst = stat.match.get('tcp_dst', 0)
                elif ip_proto == 17:
                    tp_src = stat.match.get('udp_src', 0)
                    tp_dst = stat.match.get('udp_dst', 0)

                flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

                try:
                    packet_count_per_second = float(stat.packet_count) / stat.duration_sec
                    packet_count_per_nsecond = float(stat.packet_count) / stat.duration_nsec
                except Exception:
                    packet_count_per_second = 0
                    packet_count_per_nsecond = 0

                try:
                    byte_count_per_second = float(stat.byte_count) / stat.duration_sec
                    byte_count_per_nsecond = float(stat.byte_count) / stat.duration_nsec
                except Exception:
                    byte_count_per_second = 0
                    byte_count_per_nsecond = 0

                file0.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20},{21}\n".format(
                    timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                    ip_proto, icmp_code, icmp_type,
                    stat.duration_sec, stat.duration_nsec,
                    stat.idle_timeout, stat.hard_timeout,
                    stat.flags, stat.packet_count, stat.byte_count,
                    packet_count_per_second, packet_count_per_nsecond,
                    byte_count_per_second, byte_count_per_nsecond,
                    1  # label always 1
                ))
            file0.flush()
        except Exception:
            self.logger.exception("error handling flow stats reply")
        finally:
            if file0:
                file0.close()


"""
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = time.time()
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        file0 = open("/ryu/app/FlowStatsfile.csv","a+")
        body = ev.msg.body
        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
            try:
                packet_count_per_second = float(stat.packet_count)/stat.duration_sec
                packet_count_per_nsecond = float(stat.packet_count)/stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = float(stat.byte_count)/stat.duration_sec
                byte_count_per_nsecond = float(stat.byte_count)/stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond,1))
        file0.close()
        
"""