from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls, CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet


class hub(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(hub, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # memanggil fungsi untuk mengenerate flowmod (fungsi 	#add_flow
        self.add_flow(datapath, 0, match, actions)
    #

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        data = msg.data
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        inport = msg.match['in_port']

        if src == "00:19:21:68:00:04":
            output = 1
        else:
            output = 2
        #match = ofp_parser.OFPMatch(in_port=inport,eth_src=src)
        actions = [ofp_parser.OFPActionOutput(output)]

        # self.add_flow(dp,10,match,actions)

        out = ofp_parser.OFPPacketOut(
            datapath=dp,
            in_port=inport,
            actions=actions,
            data=data)
        # print actions
        dp.send_msg(out)
