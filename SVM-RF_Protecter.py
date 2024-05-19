# -*- coding: utf-8 -*-
#调用SDN控制器组件
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib import hub

#调用系统组件
import os
import csv
import time
import math
import statistics

#调用机器学习模块
from svm_model import SVMModel
from rf_model import RFModel

#调用结果分析模块
from accuracy_score import write_accuracy_to_file
from detection_rate import write_detection_rate_to_file
from graph import plot_results

#-------------------------------------------------------#
#                                                       
APP_TYPE = 1                                            
# 0表示数据收集, 1表示DDoS检测                            
#
PREVENTION = 1 
# 
# 0代表开启观察者模式 (不进行任何防御措施)
# 1代表开启防御者模式 (默认开启)
#
TEST_TYPE = 0
# 0 正常流量, 1 攻击流量
#
INTERVAL = 1.2  
# 数据收集时间间隔（秒）
#
#-------------------------------------------------------#


gflows = []

old_ssip_len = 0

prev_flow_count = 0

FLOW_SERIAL_NO = 0

iteration = 0


# 自适应阈值初始值
adaptive_threshold = 0.5

# 自适应阈值调节步长
adaptive_step = 0.05

# 阈值调节窗口大小
window_size = 10

# 存储最近的检测结果
recent_results = []

# 分析结果存放文件夹
analysis_folder = "analysis"
if not os.path.exists(analysis_folder):
    os.makedirs(analysis_folder)


def get_flow_number():
    global FLOW_SERIAL_NO
    FLOW_SERIAL_NO = FLOW_SERIAL_NO + 1
    return FLOW_SERIAL_NO

def init_portcsv(dpid):
    fname = "switch_" + str(dpid) + "_data.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    header = ["time", "sfe", "ssip", "rfip", "type"]
    writ.writerow(header)

def init_flowcountcsv(dpid):
    fname = "switch_" + str(dpid) + "_flowcount.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    header = ["time", "flowcount"]
    writ.writerow(header)

def update_flowcountcsv(dpid, row):
    fname = "switch_" + str(dpid) + "_flowcount.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    writ.writerow(row)

def update_portcsv(dpid, row):
    fname = "switch_" + str(dpid) + "_data.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    row.append(str(TEST_TYPE))
    writ.writerow(row)

def update_resultcsv(row):
    fname = "result.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    row.append(str(TEST_TYPE))
    writ.writerow(row)

class SimpleSwitch13(app_manager.RyuApp):                #定义一个SW13的交换机模块，并且在交换机中编写相关功能
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]            #运用Openflow13来支持交换机的基础协议

    def __init__(self, *args, **kwargs):                 #创建init方法用来实现控制器启动后自动运行交换机，可接受元组以及字典类参数
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_thread = hub.spawn(self._flow_monitor)
        self.datapaths = {}
        self.mitigation = 0
        self.svm_model = None
        self.rf_model = None
        self.arp_ip_to_port = {}
        if APP_TYPE == 1:
            self.svm_model = SVMModel()
            self.rf_model = RFModel()
        if APP_TYPE == 0:
            self._init_data_collection_mode()

    def _init_data_collection_mode(self):
        # 初始化数据收集模式的组件或变量
        self.data_collection_active = True
        self.logger.info("数据收集模式已初始化。")

    def _flow_monitor(self):
        hub.sleep(5)
        while True:
            #self.logger.info("Starts Flow monitoring")            
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        flow_serial_no = get_flow_number()

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flow_serial_no)
        init_portcsv(datapath.id)
        init_flowcountcsv(datapath.id)

    def request_flow_metrics(self, datapath):           #流量计数（特征之一）
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)


    def _speed_of_flow_entries(self, flows):            #sfe特征的计算方法
        global prev_flow_count
        curr_flow_count = 0
        #collect the packet_count from all the flows
        for flow in flows:
            curr_flow_count += 1

        #print "speed of flow entries ", flow_count
        sfe = curr_flow_count - prev_flow_count
        prev_flow_count = curr_flow_count
        return sfe


    def _speed_of_source_ip(self, flows):               #ssip特征的计算方法
        global old_ssip_len
        ssip = []
        #print "length of flow table " ,len(flows)
        for flow in flows:
            m = {}
            for i in flow.match.items():
                key = list(i)[0]  # match key
                val = list(i)[1]  # match value
                if key == "ipv4_src":
                    #print key,val
                    if val not in ssip:
                        ssip.append(val)
        #print "source_ips ", ssip
        cur_ssip_len = len(ssip)
        ssip_result = cur_ssip_len - old_ssip_len
        old_ssip_len = cur_ssip_len
        #print "ssip ", ssip
        return ssip_result


    def _ratio_of_flowpair(self, flows):                #rfip特征的计算方法
        #find total number of flows
        # find collaborative flows (ideal case - all - 1 )
        flow_count = 0
        for flow in flows:
            flow_count += 1
        #print "total number of flows ", flow_count
        #excluding the table miss entry from flow count
        flow_count -= 1

        collaborative_flows = {}
        for flow in flows:
            m = {}
            srcip = dstip = None
            for i in flow.match.items():
                key = list(i)[0]  # match key
                val = list(i)[1]  # match value
                if key == "ipv4_src":
                    srcip = val
                    #print key,val
                if key == "ipv4_dst":
                    dstip = val
            if srcip and dstip:
                fwdflowhash = srcip + "_" + dstip
                revflowhash = dstip + "_" + srcip
                #check flowhash is already exist
                if not fwdflowhash in collaborative_flows:
                    #check you have reverse flowhash exists?
                    if not revflowhash in collaborative_flows:
                        collaborative_flows[fwdflowhash] = {}
                    else:
                        collaborative_flows[revflowhash][fwdflowhash] = 1
        #identify number of collaborative flows
        onesideflow = iflow = 0
        for key in collaborative_flows:
            if collaborative_flows[key] == {}:
                onesideflow += 1
            else:
                iflow +=2
        #print "collaborative_flows", collaborative_flows
        #print "oneside flow", onesideflow
        #print "collaborative flow ", iflow
        if flow_count != 0 :
            rfip = float(iflow) / flow_count
            #print "rfip ", rfip
            return rfip
        return 1.0

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply], MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        global adaptive_threshold
        global recent_results

        flows = ev.msg.body
        dpid = ev.msg.datapath.id
        sfe = self._speed_of_flow_entries(flows)
        ssip = self._speed_of_source_ip(flows)
        rfip = self._ratio_of_flowpair(flows)

        # 打印流量信息
        self._print_flow_info(dpid, sfe, ssip, rfip)        

        if APP_TYPE == 1:
            features = [sfe, ssip, rfip]
            svm_result = self.svm_model.predict([features])[0]
            rf_result = self.rf_model.predict([features])[0]
            final_result = (svm_result + rf_result) / 2
            
            recent_results.append(final_result)
            if len(recent_results) > window_size:
                recent_results.pop(0)
            
            if len(recent_results) == window_size:
                mean_result = sum(recent_results) / window_size
                if mean_result > 0.6:
                    adaptive_threshold = min(1.0, adaptive_threshold + adaptive_step)
                elif mean_result < 0.4:
                    adaptive_threshold = max(0.0, adaptive_threshold - adaptive_step)

            self.logger.info("Adaptive threshold: {}".format(adaptive_threshold))

            if final_result > adaptive_threshold:
                print("\033[91mDDoS attack detected, activating mitigation\033[0m")
                self.mitigation = 1
                if PREVENTION == 1:
                    print("\033[91mMitigation started\033[0m")
                else:
                    print("\033[91mDDoS attack detected but mitigation is disabled (PREVENTION=0)\033[0m")
            else:
                print("Traffic is normal")

        elif APP_TYPE == 0:
            if PREVENTION == 1:
                # 预处理模式
                features = [sfe, ssip, rfip]
                self.svm_model.train(features)  
                self.rf_model.train(features)   
                print("\033[94mPreprocessing mode: Features collected and model trained: SFE={}, SSIP={}, RFIP={}\033[0m".format(sfe, ssip, rfip))
            else:
                # 单纯测试流量模式
                t = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
                row = [t, str(sfe), str(ssip), str(rfip)]
                update_portcsv(dpid, row)
                update_resultcsv([str(sfe), str(ssip), str(rfip)])
        gflows = []

    def analyze_results(self):
        results_file = "result.csv"
        analysis_folder = "analysis"
        write_accuracy_to_file(results_file, analysis_folder)
        write_detection_rate_to_file(results_file, analysis_folder)
        plot_results(results_file, analysis_folder)

    def _print_flow_info(self, dpid, sfe, ssip, rfip):
        # 打印流量信息，异常流量标注为红色
        print("DPID: {}, SFE: {}, SSIP: {}, RFIP: {}".format(dpid, sfe, ssip, rfip))       

    def add_flow(self, datapath, priority, match, actions, serial_no, buffer_id=None, idletime=0, hardtime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, buffer_id=buffer_id,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, priority=priority,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def block_port(self, datapath, portnumber):
        if PREVENTION == 0:
            print("\033[91mPREVENTION is set to 0. No action taken to block port {}.\033[0m".format(portnumber))
        else:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(in_port=portnumber)
            actions = []
            flow_serial_no = get_flow_number()
            self.add_flow(datapath, 100, match, actions, flow_serial_no, hardtime=120)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
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
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            if a.opcode == arp.ARP_REQUEST or a.opcode == arp.ARP_REPLY:
                if not a.src_ip in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(a.src_ip)

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                if self.mitigation:
                    if PREVENTION == 1:
                        if not (srcip in self.arp_ip_to_port[dpid][in_port]):
                            print("\033[91mAttack detected from port", in_port, "Block the port", in_port, "\033[0m")
                            self.block_port(datapath, in_port)
                            return
                    else:
                        print("\033[91mAttack detected from port", in_port, "but mitigation is disabled (PREVENTION=0)\033[0m")
                        return               

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip)

                flow_serial_no = get_flow_number()
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, flow_serial_no, buffer_id=msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, flow_serial_no)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

if __name__ == "__main__":
    # Initialize the controller
    from ryu.cmd import manager
    manager.main(args=['ryu.cmd.manager', '--verbose', 'SVM-RF_Protecter.py'])
