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
        self.arp_table['10.0.0.3'] = '00:00:00:00:00:03'
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
            self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
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
            print "wrong switch"
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
        endtime = time.time()
        datapath = ev.msg.datapath
        self.logger.info('datapath         port     '
        for stat in sorted(body, key=attrgetter('port_no')):
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            if datapath.id == 3 and stat.port_no == 2:
                f1 = open('link1.txt', 'ab')
                self.l1_prev = self.l1_curr
                f1.close()
            if datapath.id == 4 and stat.port_no == 2:
            if datapath.id == 5 and stat.port_no == 2:
                f5 = open('link5.txt', 'ab')