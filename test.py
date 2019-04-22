from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet

class hub(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(hub, self).__init__(*args,**kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        data =msg.data
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # (2)
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst

        in_port = msg.inport
        match = parser.OFPMatch(in_port=in_port)

        if src == "00:19:21:68:00:04":
            output = 1
        else:
            output = 1

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id = msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
