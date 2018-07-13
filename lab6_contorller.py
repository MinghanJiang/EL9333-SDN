from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
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
from ryu.lib import hub

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.datapaths = {}
		self.monitor_thread = hub.spawn(self.monitor)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
								ip_proto = inet.IPPROTO_UDP)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 25, match, actions)
		match2 = parser.OFPMatch()
		actions2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match2, actions2)
		dpid = datapath.id
		if dpid == 1:
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 15, 1)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 15, 2)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 15, 3)
	
		elif dpid == 2:
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 15, 1)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 15, 2)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 15, 3)
			
		elif dpid == 3:
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 15, 1)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 15, 2)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 15, 2)
			
		elif dpid == 4:
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 15, 2)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 15, 1)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 15, 2)
		
		elif dpid == 5:
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 15, 2)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 15, 2)
			self.add_initial_rule(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 15, 1)
		
		else:
			print "wrong switch"
			
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
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		req = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)

		req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
		datapath.send_msg(req)

	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):
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
	def port_stats_reply_handler(self, ev):
		body = ev.msg.body

		self.logger.info('datapath         port     '
						'rx-pkts  rx-bytes rx-error '
						'tx-pkts  tx-bytes tx-error')
		self.logger.info('---------------- -------- '
						'-------- -------- -------- '
						'-------- -------- --------')
		for stat in sorted(body, key=attrgetter('port_no')):
			self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
							ev.msg.datapath.id, stat.port_no,
							stat.rx_packets, stat.rx_bytes, stat.rx_errors,
							stat.tx_packets, stat.tx_bytes, stat.tx_errors)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		in_port = msg.match['in_port']
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)
		ethertype = eth.ethertype
		if ethertype == ether.ETH_TYPE_IP:
			ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
			udp_pkt = pkt.get_protocol(udp.udp)
			eth_pkt = pkt.get_protocol(ethernet.ethernet)
			
		if (datapath.id == 1 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				#H1 to H2
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.1',
										ipv4_dst = '10.0.0.2',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(2)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
				
				#H1 to H3
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.1',
										ipv4_dst = '10.0.0.3',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(3)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
				
				#H2 to H3
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.2',
										ipv4_dst = '10.0.0.3',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(3)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
		elif (datapath.id == 3 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				#H1 to H2
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.1',
										ipv4_dst = '10.0.0.2',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(2)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
				
				#H1 to H3
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.1',
										ipv4_dst = '10.0.0.3',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(2)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
		elif (datapath.id == 4 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				#H1 to H2
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.1',
										ipv4_dst = '10.0.0.2',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(1)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
				
				#H2 to H3
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.2',
										ipv4_dst = '10.0.0.3',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(2)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
		elif (datapath.id == 4 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				#H1 to H3
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.1',
										ipv4_dst = '10.0.0.3',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(1)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
				
				#H2 to H3
				match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
										ipv4_src = '10.0.0.2',
										ipv4_dst = '10.0.0.3',
										udp_dst = udp_pkt.dst_port,
										udp_src = udp_pkt.src_port,
										ip_proto = inet.IPPROTO_UDP)
				actions = [parser.OFPActionOutput(1)]
				self.add_flow(datapath, 65535, match, actions)

				out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
									  ofproto.OFPP_CONTROLLER, actions,
									  msg.data)
				datapath.send_msg(out)
		
	def add_initial_rule(self, datapath, ip_proto, ipv4_dst = None, priority = 1, fwd_port = None):
		parser = datapath.ofproto_parser
		actions = [parser.OFPActionOutput(fwd_port)]
		match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
								ip_proto = ip_proto,
								ipv4_dst = ipv4_dst)
		self.add_flow(datapath, priority, match, actions)
		
	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]

		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
								match=match, instructions=inst)
		datapath.send_msg(mod)