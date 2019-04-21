from operator import attrgetter

import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types, arp, tcp, ipv4
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.lib import hub
import json
import time

# from ryu.app.sdnhub_apps import learning_switch


class loadbalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(loadbalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.serverlist = []  # Creating a list of servers
        self.virtual_lb_ip = "192.168.7.100"  # Virtual Load Balancer IP
        self.virtual_lb_mac = "AB:BC:CD:EF:AB:BC"  # Virtual Load Balancer MAC Address
        # self.counter = 0  # Used to calculate mod in server selection below
        self.flow_monitor = 0
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.xtime = 60

        self.ctemp = []
        self.dtemp = []
        self.ptemp = []
        self.btemp = []
        self.cookie_temp = 0
        self.longest_duration = 0
        self.cookie_idx0 = 0xffffffffffffffff
        self.clongest_dur = 0xffffffffffffffff

        self.flowentry_temp = []

	# Appending all given IP's, assumed MAC's and ports of switch to which servers are connected to the list created
        self.serverlist.append({'ip': "192.168.7.1", 'mac': "00:00:00:00:00:01","outport": "1", "used": "0"})
        self.serverlist.append({'ip': "192.168.7.2", 'mac': "00:00:00:00:00:02", "outport": "1", "used": "0"})
        self.serverlist.append({'ip': "192.168.7.3", 'mac': "00:00:00:00:00:03", "outport": "1", "used": "0"})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        cookie = self.cookie_temp
        cookie_mask = self.cookie_temp
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        buffer_id = ofproto.OFP_NO_BUFFER

        req = parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, ofproto.OFPFC_DELETE,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                    ofproto.OFPFF_SEND_FLOW_REM,)
        datapath.send_msg(req)
        print("flow dengan cookie " + hex(self.cookie_temp) + " telah dihapus")

    # Function placed here, source MAC and IP passed from below now become the destination for the reply packet
    def function_for_arp_reply(self, dst_ip,dst_mac):
        arp_target_mac = dst_mac
        src_ip = self.virtual_lb_ip  # Making the load balancers IP and MAC as source IP and MAC
        src_mac = self.virtual_lb_mac

        arp_opcode = 2  # ARP opcode is 2 for ARP reply
        hardware_type = 1  # 1 indicates Ethernet ie 10Mb
        arp_protocol = 2048  # 2048 means IPv4 packet
        ether_protocol = 2054  # 2054 indicates ARP protocol
        len_of_mac = 6  # Indicates length of MAC in bytes
        len_of_ip = 4  # Indicates length of IP in bytes

        pkt = packet.Packet()
	    # Dealing with only layer 2
        ether_frame = ethernet.ethernet(dst_mac, src_mac, ether_protocol)
	    # Building the ARP reply packet, dealing with layer 3
        arp_reply_pkt = arp.arp(hardware_type, arp_protocol, len_of_mac, len_of_ip, arp_opcode, src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(ether_frame)
        pkt.add_protocol(arp_reply_pkt)
        pkt.serialize()
        return pkt

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        # print("Debugging purpose dpid", dpid)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        # Jika ethernet frame type = 2054 mengindikasikan ARP packet..
        if eth.ethertype == ether.ETH_TYPE_ARP:
            arp_header = pkt.get_protocols(arp.arp)[0]
            # dan jika destination IP adalah virtual IP LB dan Opcode = 1 mengindikasikan ARP Request
            if arp_header.dst_ip == self.virtual_lb_ip and arp_header.opcode == arp.ARP_REQUEST:
                #memanggil fungsi untuk membangun packet ARP reply dengan parameter MAC dan IP src
                reply_packet = self.function_for_arp_reply(arp_header.src_ip, arp_header.src_mac)
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
                datapath.send_msg(packet_out)

            return
        ip_header = pkt.get_protocols(ipv4.ipv4)[0]
        # print("IP_Header", ip_header)
        tcp_header = pkt.get_protocols(tcp.tcp)[0]
        #print("TCP_Header", tcp_header)

        # Route to server
        match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_src=eth.src, eth_dst=eth.dst,
                                ip_proto=ip_header.proto, ipv4_src=ip_header.src, ipv4_dst=ip_header.dst,
                                tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port)

#        if ip_header.src == "192.168.7.4" or ip_header.src == "10.0.0.5":
#            server_mac_selected = self.serverlist[0]['mac']
#            server_ip_selected = self.serverlist[0]['ip']
#            server_outport_selected = int(self.serverlist[0]['outport'])
#        elif ip_header.src == "10.0.0.6":
#            server_mac_selected = self.serverlist[1]['mac']
#            server_ip_selected = self.serverlist[1]['ip']
#            server_outport_selected = int(self.serverlist[1]['outport'])
#        else:
#            server_mac_selected = self.serverlist[2]['mac']
#            server_ip_selected = self.serverlist[2]['ip']
#            server_outport_selected = int(self.serverlist[2]['outport'])

        for server_selected in self.serverlist:
            if server_selected['used'] is "0":
                server_selected['used'] = "1"
                server_mac_selected = server_selected['mac']
                server_ip_selected = server_selected['ip']
                server_outport_selected = int(server_selected['outport'])
                if server_selected['outport'] is "3":
                    for i in range(3):
                        self.serverlist[i]['used'] = "0"

                break

        actions = [parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
                   parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
                   parser.OFPActionSetField(eth_dst=server_mac_selected),
                   parser.OFPActionSetField(ipv4_dst=server_ip_selected),
                   parser.OFPActionOutput(server_outport_selected)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie = random.randint(0, 0xffffffffffffffff)

        # tambahkan timeout dinamis
        if self.flow_monitor > (0.7 * 100):
            self.xtime -= 1
            if self.xtime <= 5:
                self.xtime = 10
        if self.flow_monitor < (0.7 * 100):
            self.xtime += 1
            if self.xtime > 59:
                self.xtime = 60
        # if self.flow_monitor <= (0.3 * 100):
        #     self.xtime = 60

        flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=60, instructions=inst, buffer_id=msg.buffer_id, cookie=cookie)
        datapath.send_msg(flow_mod)
        # print("timeouts saat ini route to server : " + str(self.xtime))

        # Reverse route from server
        match = parser.OFPMatch(in_port=server_outport_selected, eth_type=eth.ethertype, eth_src=server_mac_selected,
                                eth_dst=self.virtual_lb_mac, ip_proto=ip_header.proto, ipv4_src=server_ip_selected,
                                ipv4_dst=self.virtual_lb_ip, tcp_src=tcp_header.dst_port, tcp_dst=tcp_header.src_port)
        actions = [parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
                   parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
                   parser.OFPActionSetField(ipv4_dst=ip_header.src), parser.OFPActionSetField(eth_dst=eth.src),
                   parser.OFPActionOutput(in_port)]
        inst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie = random.randint(0, 0xffffffffffffffff)
        # tambahkan timeout dinamis
        flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=60, instructions=inst2, cookie=cookie)
        datapath.send_msg(flow_mod2)
        # print("timeouts saat ini reverse from server : " + str(self.xtime))

    #Method untuk melakukan monitoring flow table setiap x detik
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
            hub.sleep(5)

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
        ctemp_idx = 0

        self.flow_monitor = len(body)
        print("Flow Entry saat ini : " + str(self.flow_monitor))
        self.logger.info('  Cookie     '
                         '       Duration        '
                         ' Packets     Bytes')
        self.logger.info('---------------- '
                         '----------------- '
                         '----------  ----------')

        flow_table = ev.msg.to_jsondict()
        for i in range (self.flow_monitor):
            # print(i)
            cookie = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["cookie"])
            duration = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["duration_sec"])
            packet_count = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["packet_count"])
            byte_count = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["byte_count"])
            # print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))

            # print("longest duration : " + str(longest_duration))

            if not cookie in self.ctemp:
                self.ctemp.append(cookie)
                self.dtemp.append(duration)
                self.ptemp.append(packet_count)
                self.btemp.append(byte_count)
                print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))

            elif cookie in self.ctemp and cookie !=0:
                ctemp_idx = self.ctemp.index(cookie)

                if byte_count > self.btemp[ctemp_idx] and packet_count > self.ptemp[ctemp_idx]:

                    self.ctemp[ctemp_idx] = cookie
                    self.btemp[ctemp_idx] = byte_count
                    self.dtemp[ctemp_idx] = duration
                    self.ptemp[ctemp_idx] = packet_count
                    # print("Flow Entry saat ini : " + str(self.flow_monitor))
                    print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))

                elif byte_count == self.btemp[ctemp_idx]:
                    if self.flow_monitor > (0.6*20):
                        print("hapus flow dengan cookie " + hex(cookie))
                        self.cookie_temp = cookie
                        # call function delete_flow(cookie)
                        self.delete_flow(ev)

                    else:
                        print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))
            else:
                # print("Flow Entry saat ini NORMAL : " + str(flow_monitor))
                print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))

            # function to check longest duration
            if self.longest_duration < self.dtemp[ctemp_idx]:
                self.longest_duration = self.dtemp[ctemp_idx]
                self.clongest_dur = self.ctemp[ctemp_idx]
            else:
                self.longest_duration = self.longest_duration

        # print("longest duration : " + str(self.longest_duration))
        self.longest_duration = 0
        # print(hex(self.cookie_idx0))
        # print(hex(self.clongest_dur))
        if self.flow_monitor >= (0.8*20):
            print("Flow Table PENUH!!!! Perlu dilakukan penghapusan paksa !!")
            self.cookie_temp = self.clongest_dur
            print("menghapus flow entry dengan 'total duration' paling lama . . . ." + hex(self.clongest_dur))
            self.delete_flow(ev)
