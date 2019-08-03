import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types, arp, tcp, ipv4

CLASS loadbalancer(app_manager.RyuApp):
    OFP_VERSIONS <- [ofproto_v1_3.OFP_VERSION]
    FUNCTION __init__(self, *args, **kwargs):
        super(loadbalancer, self).__init__(*args, **kwargs)
         i <- 0
         mac_to_port <- {}
         serverlist <- []
         virtual_lb_ip <- "10.0.0.100"
         virtual_lb_mac <- "AB:BC:CD:EF:AB:BC"
         serverlist.append({'ip': "10.0.0.1", 'mac': "00:00:00:00:00:01", "outport": "1"})
         serverlist.append({'ip': "10.0.0.2", 'mac': "00:00:00:00:00:02", "outport": "2"})
         serverlist.append({'ip': "10.0.0.3", 'mac': "00:00:00:00:00:03", "outport": "3"})
    ENDFUNCTION

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    FUNCTION switch_features_handler(self, ev):
        datapath <- ev.msg.datapath
        ofproto <- datapath.ofproto
        parser <- datapath.ofproto_parser
        match <- parser.OFPMatch()
        actions <- [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
         add_flow(datapath, 0, match, actions)
    ENDFUNCTION

    FUNCTION add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto <- datapath.ofproto
        parser <- datapath.ofproto_parser
        inst <- [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        IF buffer_id:
            mod <- parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        ELSE:
            mod <- parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        ENDIF
        datapath.send_msg(mod)
    ENDFUNCTION

    FUNCTION function_for_arp_reply(self, dst_ip, dst_mac):
        arp_target_mac <- dst_mac
        src_ip <-  virtual_lb_ip
        src_mac <-  virtual_lb_mac
        arp_opcode <- 2
        hardware_type <- 1
        arp_protocol <- 2048
        ether_protocol <- 2054
        len_of_mac <- 6
        len_of_ip <- 4
        pkt <- packet.Packet()
        ether_frame <- ethernet.ethernet(dst_mac, src_mac, ether_protocol)
        arp_reply_pkt <- arp.arp(hardware_type, arp_protocol, len_of_mac, len_of_ip, arp_opcode, src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(ether_frame)
        pkt.add_protocol(arp_reply_pkt)
        pkt.serialize()
        RETURN pkt
    ENDFUNCTION

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    FUNCTION _packet_in_handler(self, ev):
        msg <- ev.msg
        datapath <- msg.datapath
        ofproto <- datapath.ofproto
        parser <- datapath.ofproto_parser
        in_port <- msg.match['in_port']
        dpid <- datapath.id
        pkt <- packet.Packet(msg.data)
        eth <- pkt.get_protocols(ethernet.ethernet)[0]
        dst <- eth.dst
        src <- eth.src
        mac_to_port.setdefault(dpid, {})
        mac_to_port[dpid][src] <- in_port
        IF eth.ethertype = ether_types.ETH_TYPE_LLDP:
            RETURN
        ENDIF
        IF eth.ethertype = ether.ETH_TYPE_ARP:
            arp_header <- pkt.get_protocols(arp.arp)[0]
            IF arp_header.dst_ip =  virtual_lb_ip AND arp_header.opcode = arp.ARP_REQUEST:
                reply_packet <-  function_for_arp_reply(arp_header.src_ip, arp_header.src_mac)
                actions <- [parser.OFPActionOutput(in_port)]
                packet_out <- parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
                datapath.send_msg(packet_out)
                RETURN
            ELSE:
                mac_to_port.setdefault(dpid, {})
                mac_to_port[dpid][src] <- in_port
                IF dst in  mac_to_port[dpid]:
                    out_port <-  mac_to_port[dpid][dst]
                ELSE:
                    out_port <- ofproto.OFPP_FLOOD
                ENDIF
                actions <- [parser.OFPActionOutput(out_port)]
                IF out_port != ofproto.OFPP_FLOOD:
                    match <- parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    instarp <- [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    IF msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        mod <- parser.OFPFlowMod(datapath=datapath, buffer_id=msg.buffer_id, priority=1, match=match, idle_timeout=2, instructions=instarp)
                    ELSE:
                        mod <- parser.OFPFlowMod(datapath=datapath, priority=1, match=match, idle_timeout=2, instructions=instarp)
                    ENDIF
                    datapath.send_msg(mod)
                ENDIF
                data <- None
                IF msg.buffer_id = ofproto.OFP_NO_BUFFER:
                    data <- msg.data
                ENDIF
                out <- parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                RETURN
            ENDIF
        ENDIF
        ip_header <- pkt.get_protocols(ipv4.ipv4)[0]
        tcp_header <- pkt.get_protocols(tcp.tcp)[0]
        IF tcp_header.dst_port = 80:
            index <-  i
            server_mac_selected <-  serverlist[index]['mac']
            server_ip_selected <-  serverlist[index]['ip']
            server_outport_selected <- int( serverlist[index]['outport'])
            OUTPUT "Server ", index
             i <-  i + 1
            IF  i = 3:
                 i <- 0
            ENDIF
            match <- parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_src=eth.src, eth_dst=eth.dst, ip_proto=ip_header.proto, ipv4_src=ip_header.src, ipv4_dst=ip_header.dst,tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port)
            actions <- [parser.OFPActionSetField(eth_dst=server_mac_selected),parser.OFPActionSetField(ipv4_dst=server_ip_selected), parser.OFPActionOutput(server_outport_selected)]
            inst <- [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            cookie <- random.randint(0, 0xffffffffffffffff)
            flow_mod <- parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=2, instructions=inst, buffer_id=msg.buffer_id, cookie=cookie)
            datapath.send_msg(flow_mod)
            match <- parser.OFPMatch(in_port=server_outport_selected, eth_type=eth.ethertype, eth_src=server_mac_selected, eth_dst=eth.src, ip_proto=ip_header.proto, ipv4_src=server_ip_selected, ipv4_dst=ip_header.src, tcp_src=tcp_header.dst_port, tcp_dst=tcp_header.src_port)
            actions <- [parser.OFPActionSetField(eth_src= virtual_lb_mac), parser.OFPActionSetField(ipv4_src= virtual_lb_ip), parser.OFPActionOutput(in_port)]
            inst2 <- [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            cookie <- random.randint(0, 0xffffffffffffffff)
            flow_mod2 <- parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=2, instructions=inst2, cookie=cookie)
            datapath.send_msg(flow_mod2)
        ENDIF
