from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from datetime import datetime
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import os
import csv
import time # Cần import thêm time
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4

class DDoS_Monitor(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(DDoS_Monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.flow_model = None
        self.TRAIN_FILE = 'FlowStatsfile.csv' 

        self.PPS_THRESHOLD = 50       
        self.CONFIRMATION_COUNT = 3   
        self.BLOCK_DURATION = 30      # Thời gian chặn (giây)

        # Lưu lịch sử nghi ngờ
        self.attack_history = {} 
        
        # --- FIX QUAN TRỌNG: DANH SÁCH ĐANG BỊ CHẶN ---
        # Key: (src, dst), Value: thời điểm hết hạn chặn (timestamp)
        self.blocked_flows = {} 

        self.logger.info("DEBUG: System Starting...")
        self.flow_training()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('DEBUG: Switch Connected! ID=%016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        
        dst = eth.dst; src = eth.src; dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]: out_port = self.mac_to_port[dpid][dst]
        else: out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, 
                                        eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=30)
                return
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=30)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    # PHẦN 2: MONITOR & DETECT (CÓ PENALTY BOX)
    def _monitor(self):
        while True:
            hub.sleep(1) 
            if self.datapaths:
                for dp in self.datapaths.values():
                    self._request_stats(dp)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        valid_flows = [flow for flow in body if flow.priority == 1 and flow.match.get('eth_type') == 0x0800]
        
        if not valid_flows: return 

        predict_data = []
        full_info_list = []
        
        current_time = time.time()

        for stat in valid_flows:
            ip_src = stat.match.get('ipv4_src', '0.0.0.0')
            ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
            ip_proto = stat.match.get('ip_proto', 0)

            if ip_src == '0.0.0.0' or ip_dst == '0.0.0.0': continue
            
            pair_key = (ip_src, ip_dst)
            if pair_key in self.blocked_flows:
                if current_time < self.blocked_flows[pair_key]:
                    continue 
                else:
                    del self.blocked_flows[pair_key]
                    self.logger.info(f"UNBLOCKED (Timeout): {ip_src} -> {ip_dst}")

            duration_sec = stat.duration_sec
            byte_count = stat.byte_count
            packet_count = stat.packet_count
            
            pkt_per_sec = packet_count / duration_sec if duration_sec > 0 else 0
            byte_per_sec = byte_count / duration_sec if duration_sec > 0 else 0

            # Lọc thô (Hard Threshold)
            if packet_count < 10 or pkt_per_sec < self.PPS_THRESHOLD: 
                if (ip_src, ip_dst) in self.attack_history:
                    self.attack_history.pop((ip_src, ip_dst), None)
                continue 
            
            features = [ip_proto, duration_sec, packet_count, byte_count, pkt_per_sec, byte_per_sec]
            predict_data.append(features)
            
            full_info = {
                'dpid': ev.msg.datapath.id,
                'src_ip': ip_src,
                'dst_ip': ip_dst,
                'proto': ip_proto,
                'pps': pkt_per_sec
            }
            full_info_list.append(full_info)

        if predict_data and self.flow_model:
            self.predict_live(np.array(predict_data), full_info_list)

    def predict_live(self, X_predict, full_info_list):
        try:
            y_pred = self.flow_model.predict(X_predict)
            
            for i, result in enumerate(y_pred):
                info = full_info_list[i]
                src = info['src_ip']
                dst = info['dst_ip']
                pair = (src, dst)
                
                if result == 1: # DDoS Detected
                    count = self.attack_history.get(pair, 0) + 1
                    self.attack_history[pair] = count
                    
                    self.logger.info(f"Suspicious: {src} -> {dst} | PPS: {info['pps']:.1f} | Confirm: {count}/{self.CONFIRMATION_COUNT}")
                    
                    if count >= self.CONFIRMATION_COUNT:
                        self.logger.warning(f"!!! CONFIRMED DDoS: {src} -> {dst}. Blocking now...")
                        self.mitigation_handler_single(info)
                        
                        # Reset counter
                        self.attack_history[pair] = 0 
                        # --- THÊM VÀO DANH SÁCH BỊ CHẶN ---
                        # Đánh dấu là sẽ bị chặn đến thời điểm: Hiện tại + 30s
                        self.blocked_flows[pair] = time.time() + self.BLOCK_DURATION
                        
                else: # Normal
                    if pair in self.attack_history:
                        if self.attack_history[pair] > 0:
                            self.attack_history[pair] -= 1
                    
        except Exception as e:
            self.logger.error(f"Prediction Error: {e}")

    # PHẦN 3: MITIGATION
    def mitigation_handler_single(self, info):
        attacker_ip = info['src_ip']
        victim_ip = info['dst_ip']
        dpid = info['dpid']
        
        if dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=attacker_ip,
                ipv4_dst=victim_ip
            )
            
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
            
            mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                    match=match, instructions=inst, 
                                    hard_timeout=self.BLOCK_DURATION)
            datapath.send_msg(mod)
            self.logger.info(f"BLOCKED: {attacker_ip} -> {victim_ip} for {self.BLOCK_DURATION}s")

    # PHẦN 4: TRAINING (GIỮ NGUYÊN)
    def flow_training(self):
        self.logger.info("Flow Training (Loading Dataset)...")
        if not os.path.exists(self.TRAIN_FILE):
            self.logger.warning(f"Dataset {self.TRAIN_FILE} not found!")
            return
        
        try:
            data_rows = []
            with open(self.TRAIN_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader) 
                for row in reader:
                    if row: data_rows.append(row)
            
            if not data_rows:
                return

            flow_dataset = np.array(data_rows)
            feature_indices = [7, 10, 15, 16, 17, 19]
            
            X_flow = flow_dataset[:, feature_indices].astype(float)
            y_flow = flow_dataset[:, -1].astype(float)
            
            X_train, X_test, y_train, y_test = train_test_split(
                X_flow, y_flow, test_size=0.25, random_state=0, stratify=y_flow
            )

            self.logger.info("Training Decision Tree Model...")
            self.flow_model = DecisionTreeClassifier(criterion='entropy', random_state=0)
            self.flow_model.fit(X_train, y_train)

            y_pred = self.flow_model.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            cm = confusion_matrix(y_test, y_pred)
            
            self.logger.info("------------------------------------------------")
            self.logger.info(f"Model Accuracy: {acc * 100:.2f} %")
            self.logger.info(f"Confusion Matrix:\n{cm}")
            self.logger.info("------------------------------------------------")
            
        except Exception as e:
            self.logger.error(f"Training Error: {e}")
