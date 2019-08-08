
import struct 
import logging
import six
import struct
import time
from ryu import utils
from ryu import cfg

from ryu.lib import addrconv, hub
from ryu.exception import RyuException
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib.mac import DONTCARE_STR
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.port_no import port_no_to_str
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import lldp, ether_types
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.ofproto.ether import ETH_TYPE_CFM

from ryu.controller import dpset

from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import copy
from decimal import *

class delay_probe(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }

    DEFAULT_TTL = 120 # unused. ignored.

    def __init__(self, *args, **kwargs):
        super(delay_probe, self).__init__(*args, **kwargs)
        # Holds the topology data and structure
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.link_timestamp = {} # maps Links -> timestamp
        self.dpid_dp = {} #maps dpid -> Datapath instance
        self.link_delay = {} #maps Link -> delay
        self.lldp_probe_event = hub.Event()
        self.delay_display_event = hub.Event()
        self.threads.append(hub.spawn(self.probe_packet_loop))
        self.threads.append(hub.spawn(self.delay_display_loop))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))

        print(" \t" + "Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))
            #self.logger.info('>> Source Port object dpid: %d port_no:%d', l.src.dpid, l.src.port_no)

        print(" \t" + "Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))
        
        print ev
        # DEBUG: TEMPORARY ADDITION FOR DEBUGGING. PLEASE COMMENT OUT OR REMOVE
        dp = ev.switch.dp
        dpid = ev.switch.dp.id
        self.dpid_dp[dpid] = dp
        self.send_probe_packet(dp, 1, 3)   
        #######################################################################
        #self.probe_packet_loop()
    
    def get_dpid(self, dpid):
        return self.dpid_dp[dpid]    

    """
    Handle when the switch leaves. TODO: update the links
    """
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")

    ##################################################################
    # FOR reference: spawning threads as in switches.py
    #   self.lldp_event = hub.Event()
    #   self.link_event = hub.Event()
    #   self.threads.append(hub.spawn(self.lldp_loop))
    #   self.threads.append(hub.spawn(self.link_loop))  
    # Creating events for an unknown reason? TODO: Find out reason
    #   self.lldp_event = hub.Event()
    #   self.link_event = hub.Event()  
    ##################################################################

    def send_probe_packet(self, dp, port, queue_id):
        dl_addr = '01:80:c2:00:00:0e'
        ttl = self.DEFAULT_TTL
        pkt = LLDPPacket.lldp_packet(dp.id, port, queue_id, dl_addr, ttl)
        actions = [dp.ofproto_parser.OFPActionSetQueue(queue_id), dp.ofproto_parser.OFPActionOutput(port)]
        out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
                buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
                data=pkt)        
        dp.send_msg(out)
        #self.logger.info('Packet sent')

    def probe_packet_loop(self):
        while True: 
            self.lldp_probe_event.clear()
            now = time.time()

            for link in self.topo_raw_links:
                self.link_timestamp[link] = now
                dp = self.get_dpid(link.src.dpid)
                port = link.src.port_no
                queue_id = 3 #queue_id hardcoded now for experimental purposes, TODO: implement per queue probe
                self.send_probe_packet(dp, port, queue_id)
                #self.logger.info('Sent probe packet: dpid: %d port_no: %d queue_id: %d', link.src.dpid, link.src.port_no, queue_id)

            #hub.sleep(3)
            self.lldp_probe_event.wait(timeout=3)  

    def delay_display_loop(self):
        while True:
            self.delay_display_event.clear()
            #self.logger.info('Inside delay display!')
            for link in self.link_delay:
                #print link
                #print self.link_delay[link]
                self.logger.info('Link: %s | Delay: %.5f', link, self.link_delay[link])
            self.delay_display_event.wait(timeout=3)                

           


    #########################################################################
    # Handle the LLDP packets. 
    # Parse the LLDP packet on entry, the first TLV contains the dpid
    # second TLV contains the port_no, and third TLV contains the queue_id
    # to which the packet was queued for delay probe 
    #########################################################################

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def lldp_packet_in_handler(self, ev): 
        #self.logger.info(">> Recieved a packet!")  
        data = ev.msg.data
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = six.next(i)
        assert type(eth_pkt) == ethernet.ethernet

        lldp_pkt = six.next(i)
        ### Since this handler can recieve any packet, this will filter out any packet which is not LLDP
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()
            self.logger.info('Packet returned!')
            return
        #return the packets sent by --observe-links (switches.py)
        if type(lldp_pkt.tlvs[3]) == lldp.End:
            return    

        #print lldp_pkt.tlvs[3]
        #print lldp_pkt.tlvs[4]
        #print lldp_pkt.tlvs[5]
        dpid = lldp_pkt.tlvs[3].info
        port_no = lldp_pkt.tlvs[4].info
        queue_id = lldp_pkt.tlvs[5].info
        link_timestamp = lldp_pkt.tlvs[6].info
        #dpid = lldp.OrganizationallySpecific(buf=lldp_pkt.tlvs[3])
        #port_no = lldp.OrganizationallySpecific(buf=lldp_pkt.tlvs[4])
        #queue_id = lldp.OrganizationallySpecific(buf=lldp_pkt.tlvs[5])
        #self.logger.info('>> LLDP Probe packet recieved: dpid: %s, port_no: %s, queue: %s', dpid, port_no, queue_id)
        # find the link corresponding to this data
        for link in self.topo_raw_links:
            #self.logger.info(' DEBUG:[LOOPING LINKS] Link %s, dpid: %d', link, link.src.dpid)
            if int(dpid) == link.src.dpid:
                #self.logger.info('dpid matched')
                if int(port_no) == link.src.port_no:
                    #self.logger.info('port_no matched')
                    #self.link_delay[link] = time.time() - self.link_timestamp[link]
                    self.link_delay[link] = Decimal(time.time()) - Decimal(link_timestamp)
                    #self.logger.info('Link: %s | Delay: %.5f', link, self.link_delay[link])
                    break


###########################################################################################
# Class for handling LLDP Packets picked up from ryu/topology/switches.py
# 1. Modify the sending of lldp_packet so that it contains dpid, port_no, and queue
# 2. Modify lldp_parse() to actually parse TLV, which contains the 
#    mark of our delay probe packet  
###########################################################################################

class LLDPPacket(object):
    # make a LLDP packet for link discovery.

    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'      # uint32_t
    PORT_ID_SIZE = 4

    class LLDPUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_packet(dpid, port_no, queue_id, dl_addr, ttl):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=(LLDPPacket.CHASSIS_ID_FMT %
                        dpid_to_str(dpid)).encode('ascii'))

        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
                                  port_id=struct.pack(
                                      LLDPPacket.PORT_ID_STR,
                                      port_no))

        tlv_ttl = lldp.TTL(ttl=ttl)
        tlv_end = lldp.End()
        ############################################################################################
        # ADD: Organisationally specific TLV, which consists of the link data
        # dpid, port_no, queue
        # ########################################################################################## 
        tlv_link_data_1 = lldp.OrganizationallySpecific(oui='1', subtype=0, info=str(dpid))
        tlv_link_data_2 = lldp.OrganizationallySpecific(oui='1', subtype=0, info=str(port_no))
        tlv_link_data_3 = lldp.OrganizationallySpecific(oui='1', subtype=0, info=str(queue_id))
        tlv_link_data_4 = lldp.OrganizationallySpecific(oui='1', subtype=0, info=str(Decimal(time.time())))
        ############################################################################################
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_link_data_1, tlv_link_data_2,
        tlv_link_data_3, tlv_link_data_4, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)
        pkt.serialize()
        return pkt.data

    @staticmethod
    def lldp_parse(data):
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = six.next(i)
        assert type(eth_pkt) == ethernet.ethernet

        lldp_pkt = six.next(i)
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()

        tlv_chassis_id = lldp_pkt.tlvs[0]
        if tlv_chassis_id.subtype != lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % tlv_chassis_id.subtype)
        chassis_id = tlv_chassis_id.chassis_id.decode('utf-8')
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])

        tlv_port_id = lldp_pkt.tlvs[1]
        if tlv_port_id.subtype != lldp.PortID.SUB_PORT_COMPONENT:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id subtype %d' % tlv_port_id.subtype)
        port_id = tlv_port_id.port_id
        if len(port_id) != LLDPPacket.PORT_ID_SIZE:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id %d' % port_id)
        (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)

        return src_dpid, src_port_no
     
