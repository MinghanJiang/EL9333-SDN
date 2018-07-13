from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import time
class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.starttime = time.time()
        self.arp_table = {}
        self.arp_table['10.0.0.1'] = '00:00:00:00:00:01'
        self.arp_table['10.0.0.2'] = '00:00:00:00:00:02'
        self.arp_table['10.0.0.3'] = '00:00:00:00:00:03'                self.v1 = 0        self.l1_prev = 0        self.l1_curr = 0        self.v2 = 0        self.l2_prev = 0        self.l2_curr = 0        self.v3 = 0        self.l3_prev = 0        self.l3_curr = 0        self.v4 = 0        self.l4_prev = 0        self.l4_curr = 0        self.v5 = 0        self.l5_prev = 0        self.l5_curr = 0        self.v6 = 0        self.l6_prev = 0        self.l6_curr = 0
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Insert Static rule
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        dpid = datapath.id  # classifying the switch ID
        if dpid == 1:  # switch S1
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
        elif dpid == 2:
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
        elif dpid == 3:
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)                        self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 2)
        elif dpid == 4:
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 2)
        elif dpid == 5:
            self.add_initial_rule(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 1)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 1)
        else:
            print "wrong switch"    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)    def _packet_in_handler(self, ev):        msg = ev.msg        datapath = msg.datapath        ofproto = datapath.ofproto        parser = datapath.ofproto_parser            in_port = msg.match['in_port']        pkt = packet.Packet(msg.data)        eth_pkt = pkt.get_protocol(ethernet.ethernet)        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)        udp_pkt = pkt.get_protocol(udp.udp)        if ipv4_pkt.proto == inet.IPPROTO_UDP:            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,                                     ip_proto=inet.IPPROTO_UDP,                                     ipv4_src=ipv4_pkt.src,                                     ipv4_dst=ipv4_pkt.dst,                                     udp_src=udp_pkt.src_port,                                     udp_dst=udp_pkt.dst_port)            action1 = [parser.OFPActionOutput(2)]            action2 = [parser.OFPActionOutput(3)]            if datapath.id == 3:                if self.v1 < self.v2:                    self.add_flow(datapath, 30, match, action1)                else:                    self.add_flow(datapath, 30, match, action2)            if datapath.id == 4:                if self.v3 < self.v4:                    self.add_flow(datapath, 30, match, action1)                else:                    self.add_flow(datapath, 30, match, action2)            if datapath.id == 5:                if self.v5 < self.v6:                    self.add_flow(datapath, 30, match, action1)                else:                    self.add_flow(datapath, 30, match, action2)			
    def add_initial_rule(self, datapath, ip_proto, ipv4_dst=None, priority=1, fwd_port=None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                ip_proto=ip_proto,
                                ipv4_dst=ipv4_dst)
        self.add_flow(datapath, priority, match, actions)
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath         '
                        'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        endtime = time.time()        timeinterval = int(endtime - self.starttime)        body = ev.msg.body
        datapath = ev.msg.datapath
        self.logger.info('datapath         port     '                         'rx-pkts  rx-bytes rx-error '                         'tx-pkts  tx-bytes tx-error')        self.logger.info('---------------- -------- '                         '-------- -------- -------- '                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors)            #link 1 s3 to s1
            if datapath.id == 3 and stat.port_no == 2:
                f1 = open('link1.txt', 'ab')
                self.l1_prev = self.l1_curr                self.l1_curr = stat.rx_bytes + stat.tx_bytes                self.v1 = (self.l1_curr - self.l1_prev) / (1024) / 10                f1.write('At time %d, link 1 bps:%.0f \n' % (timeinterval, self.v1))
                f1.close()            #link 2: s3 to s2            if datapath.id == 3 and stat.port_no == 3:                f2 = open('link2.txt', 'ab')                self.l2_prev = self.l2_curr                self.l2_curr = stat.rx_bytes + stat.tx_bytes                self.v2 = (self.l2_curr - self.l2_prev) / (1024) / 10                f2.write('At time %d, link 2 bps:%.0f \n' % (timeinterval, self.v2))                f2.close()            #link3: s4 to s1
            if datapath.id == 4 and stat.port_no == 2:                f3 = open('link3.txt', 'ab')                self.l3_prev = self.l3_curr                self.l3_curr = stat.rx_bytes + stat.tx_bytes                self.v3 = (self.l3_curr - self.l3_prev) / (1024) / 10                f3.write('At time %d, link 3 bps:%.0f \n' % (timeinterval, self.v3))                f3.close()            #link4: s4 to s2            if datapath.id == 4 and stat.port_no == 3:                f4 = open('link4.txt', 'ab')                self.l4_prev = self.l4_curr                self.l4_curr = stat.rx_bytes + stat.tx_bytes                self.v4 = (self.l4_curr - self.l4_prev) / (1024) / 10                f4.write('At time %d, link 4 bps:%.0f \n' % (timeinterval, self.v4))                f4.close()            #link5: s5 to s1
            if datapath.id == 5 and stat.port_no == 2:
                f5 = open('link5.txt', 'ab')                self.l5_prev = self.l5_curr                self.l5_curr = stat.rx_bytes + stat.tx_bytes                self.v5 = (self.l5_curr - self.l5_prev) / (1024) / 10                f5.write('At time %d, link 5 bps:%.0f \n' % (timeinterval, self.v5))                f5.close()            #link6: s5 to s2            if datapath.id == 5 and stat.port_no == 3:                f6 = open('link6.txt', 'ab')                self.l6_prev = self.l6_curr                self.l6_curr = stat.rx_bytes + stat.tx_bytes                self.v6 = (self.l6_curr - self.l6_prev) / (1024) / 10                f6.write('At time %d, link 6 bps:%.0f \n' % (timeinterval, self.v6))                f6.close()