from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from datetime import datetime
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
import os
import csv
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4

class DDoS_Monitor(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(DDoS_Monitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.flow_model = None
        
        # DUONG DAN TUYET DOI
        self.TRAIN_FILE = 'FlowStatsfile.csv'
        self.PREDICT_FILE = 'PredictFlowStatsfile.csv'

        self.logger.info("DEBUG: System Starting...")
        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        print("Training time: ", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('DEBUG: Switch Connected! ID=%016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('DEBUG: Switch Disconnected! ID=%016x', datapath.id)
                del self.datapaths[datapath.id]

    # --- GHI DE HAM PACKET_IN DE BAT SWITCH HOC IP ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Fix from previous step: Actions list (not instructions)
        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # --- QUAN TRONG: MATCH THEO CA IP NEU CO ---
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, 
                                        eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                # Priority 1 cho traffic thuong
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=10)
                return
            else:
                # Neu khong phai IP (VD: ARP), chi match MAC nhu cu
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=10)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    # -------------------------------------------------

    def _monitor(self):
        while True:
            if not self.datapaths:
                pass
            else:
                for dp in self.datapaths.values():
                    self._request_stats(dp)
            hub.sleep(5)
            if self.flow_model is not None:
                self.flow_predict()

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now()
        try:
            timestamp = timestamp.timestamp()
        except AttributeError:
            import time
            timestamp = time.time()

        with open(self.PREDICT_FILE, "w") as file0:
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

            body = ev.msg.body
            # Chi lay cac flow IPv4 (eth_type=0x0800) va priority=1 (Forwarding rules)
            # Priority=100 la luat chan (Drop), khong can monitor
            valid_flows = [flow for flow in body if flow.priority == 1 and flow.match.get('eth_type') == 0x0800]

            sorted_flows = sorted(valid_flows, key=lambda flow: (
                flow.match.get('ipv4_src', '0.0.0.0'), 
                flow.match.get('ipv4_dst', '0.0.0.0'), 
                flow.match.get('ip_proto', 0)
            ))
            
            for stat in sorted_flows:
                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                ip_proto = stat.match.get('ip_proto', 0)
                
                if ip_src == '0.0.0.0' or ip_dst == '0.0.0.0':
                    continue

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
                    packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                    packet_count_per_nsecond = stat.packet_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
                    byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0
                    byte_count_per_nsecond = stat.byte_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
                except ZeroDivisionError:
                    packet_count_per_second = 0
                    packet_count_per_nsecond = 0
                    byte_count_per_second = 0
                    byte_count_per_nsecond = 0

                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                            ip_proto, icmp_code, icmp_type,
                            stat.duration_sec, stat.duration_nsec,
                            stat.idle_timeout, stat.hard_timeout,
                            stat.flags, stat.packet_count, stat.byte_count,
                            packet_count_per_second, packet_count_per_nsecond,
                            byte_count_per_second, byte_count_per_nsecond))

    def flow_training(self):
        self.logger.info("Flow Training (Optimized) ...")
        if not os.path.exists(self.TRAIN_FILE):
            self.logger.warning("DEBUG: Dataset %s NOT FOUND!", self.TRAIN_FILE)
            return

        try:
            data_rows = []
            with open(self.TRAIN_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader)
                for row in reader:
                    if row:
                        data_rows.append(row)
            
            if not data_rows:
                return

            flow_dataset = np.array(data_rows)
            feature_indices = [7, 10, 15, 16, 17, 19]

            X_flow = flow_dataset[:, feature_indices].astype(float)
            y_flow = flow_dataset[:, -1].astype(float)

            X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(
                X_flow, y_flow, test_size=0.25, random_state=0, stratify=y_flow
            )

            classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
            self.flow_model = classifier.fit(X_flow_train, y_flow_train)

            y_flow_pred = self.flow_model.predict(X_flow_test)
            
            self.logger.info("------------------------------------------------")
            self.logger.info("Accuracy: %.2f %%", accuracy_score(y_flow_test, y_flow_pred) * 100)
            self.logger.info("------------------------------------------------")
        except Exception as e:
            self.logger.error("Training Error: {}".format(e))

    def flow_predict(self):
        try:
            if not os.path.exists(self.PREDICT_FILE) or os.stat(self.PREDICT_FILE).st_size == 0:
                return

            data_rows = []
            with open(self.PREDICT_FILE, 'r') as f:
                reader = csv.reader(f)
                next(reader)
                for row in reader:
                    if row:
                        data_rows.append(row)

            if not data_rows:
                return

            original_dataset = [list(row) for row in data_rows]
            predict_flow_dataset = np.array(data_rows)
            
            feature_indices = [7, 10, 15, 16, 17, 19]
            X_predict_flow = predict_flow_dataset[:, feature_indices].astype(float)
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = 0
            ddos_traffic = 0

            for i in y_flow_pred:
                if i == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1

            self.logger.info("------------------------------------------------")
            if len(y_flow_pred) > 0:
                if (legitimate_traffic / float(len(y_flow_pred)) * 100) > 80:
                    self.logger.info("Result: Normal Traffic")
                else:
                    self.logger.info("Result: DDoS Detected!")
                    self.mitigation_handler(y_flow_pred, original_dataset)
            self.logger.info("------------------------------------------------")

        except Exception as e:
            self.logger.error("Prediction Error: {}".format(e))

    def mitigation_handler(self, predictions, original_data_list):
        attack_indices = np.where(predictions == 1)[0]
        
        for idx in attack_indices:
            try:
                row = original_data_list[idx]
                
                datapath_id = int(row[1])
                attacker_ip = row[3]
                victim_ip = row[5]
                proto = int(row[7])
                
                if attacker_ip == '0.0.0.0' or victim_ip == '0.0.0.0':
                    continue

                if datapath_id in self.datapaths:
                    datapath = self.datapaths[datapath_id]
                    # --- FIX: Define ofproto here ---
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=attacker_ip,
                        ipv4_dst=victim_ip,
                        ip_proto=proto
                    )
                    
                    # BLOCK with Priority 100 (Hard timeout set to prevent permanent lockout during testing)
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                            match=match, instructions=inst, 
                                            idle_timeout=30)
                    datapath.send_msg(mod)
                    
                    self.logger.info("MITIGATION: Blocked %s -> %s (Proto: %s)", attacker_ip, victim_ip, proto)
            except Exception as e:
                self.logger.error("Mitigation Error: {}".format(e))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)
'''
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.app.simple_switch_13 import SimpleSwitch13
from datetime import datetime
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
import os
import csv
from ryu.ofproto import ofproto_v1_3

class DDoS_Monitor(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(DDoS_Monitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.flow_model = None
        
        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        print("Training time: ", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            if self.flow_model is not None:
                self.flow_predict()

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now()
        try:
            timestamp = timestamp.timestamp()
        except AttributeError:
            import time
            timestamp = time.time()

        with open("PredictFlowStatsfile.csv", "w") as file0:
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            
            body = ev.msg.body
            
            # [FIX KEYERROR] Su dung .get() thay vi truy cap truc tiep key
            sorted_flows = sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (
                flow.match.get('eth_type', 0), 
                flow.match.get('ipv4_src', '0.0.0.0'), 
                flow.match.get('ipv4_dst', '0.0.0.0'), 
                flow.match.get('ip_proto', 0)
            ))
            
            for stat in sorted_flows:
                # [FIX KEYERROR] Can kiem tra key co ton tai khong truoc khi gan
                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
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
                    packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                    packet_count_per_nsecond = stat.packet_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
                    byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0
                    byte_count_per_nsecond = stat.byte_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
                except ZeroDivisionError:
                    packet_count_per_second = 0
                    packet_count_per_nsecond = 0
                    byte_count_per_second = 0
                    byte_count_per_nsecond = 0

                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                            ip_proto, icmp_code, icmp_type,
                            stat.duration_sec, stat.duration_nsec,
                            stat.idle_timeout, stat.hard_timeout,
                            stat.flags, stat.packet_count, stat.byte_count,
                            packet_count_per_second, packet_count_per_nsecond,
                            byte_count_per_second, byte_count_per_nsecond))

    def flow_training(self):
        self.logger.info("Flow Training (Optimized) ...")
        if not os.path.exists('FlowStatsfile.csv'):
            self.logger.warning("No dataset found.")
            return

        try:
            data_rows = []
            with open('FlowStatsfile.csv', 'r') as f:
                reader = csv.reader(f)
                next(reader) # Skip header
                for row in reader:
                    if row:
                        data_rows.append(row)
            
            if not data_rows:
                return

            flow_dataset = np.array(data_rows)
            # Index trong CSV: 
            # 7: ip_proto
            # 10: duration_sec
            # 15: packet_count
            # 16: byte_count
            # 17: packet_rate (packet_count_per_second)
            # 19: byte_rate (byte_count_per_second)
            feature_indices = [7, 10, 15, 16, 17, 19]
  
            X_flow = flow_dataset[:, feature_indices].astype(float)
            y_flow = flow_dataset[:, -1].astype(float)

            X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(
                X_flow, y_flow, test_size=0.25, random_state=0, stratify=y_flow
            )

            classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
            self.flow_model = classifier.fit(X_flow_train, y_flow_train)

            y_flow_pred = self.flow_model.predict(X_flow_test)
            
            self.logger.info("------------------------------------------------")
            self.logger.info("Confusion Matrix:\n %s", confusion_matrix(y_flow_test, y_flow_pred))
            self.logger.info("Accuracy: %.2f %%", accuracy_score(y_flow_test, y_flow_pred) * 100)
            self.logger.info("------------------------------------------------")
        except Exception as e:
            self.logger.error("Training Error: {}".format(e))

    def flow_predict(self):
        try:
            if not os.path.exists('PredictFlowStatsfile.csv') or os.stat('PredictFlowStatsfile.csv').st_size == 0:
                return

            data_rows = []
            with open('PredictFlowStatsfile.csv', 'r') as f:
                reader = csv.reader(f)
                next(reader) 
                for row in reader:
                    if row:
                        data_rows.append(row)

            if not data_rows:
                return

            original_dataset = [list(row) for row in data_rows]
            
            predict_flow_dataset = np.array(data_rows)

            feature_indices = [7, 10, 15, 16, 17, 19]

            X_predict_flow = predict_flow_dataset[:, feature_indices].astype(float)
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = 0
            ddos_traffic = 0

            for i in y_flow_pred:
                if i == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1

            self.logger.info("------------------------------------------------")
            if len(y_flow_pred) > 0:
                if (legitimate_traffic / float(len(y_flow_pred)) * 100) > 80:
                    self.logger.info("Result: Normal Traffic")
                else:
                    self.logger.info("Result: DDoS Detected!")
                    self.mitigation_handler(y_flow_pred, original_dataset)
            self.logger.info("------------------------------------------------")

        except Exception as e:
            self.logger.error("Prediction Error: {}".format(e))

    def mitigation_handler(self, predictions, original_data_list):
        attack_indices = np.where(predictions == 1)[0]
        
        for idx in attack_indices:
            try:
                row = original_data_list[idx]
                
                datapath_id = int(row[1])
                attacker_ip = row[3]
                victim_ip = row[5]
                proto = int(row[7])
                
                if datapath_id in self.datapaths:
                    datapath = self.datapaths[datapath_id]
                    parser = datapath.ofproto_parser
                    
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=attacker_ip,
                        ipv4_dst=victim_ip,
                        ip_proto=proto
                    )
                    
                    self.add_flow(datapath, 100, match, [], idle_timeout=30)
                    self.logger.info("MITIGATION: Blocked {} -> {} (Proto: {})".format(attacker_ip, victim_ip, proto))
            except Exception as e:
                self.logger.error("Mitigation Error for index {}: {}".format(idx, e))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)
'''        
