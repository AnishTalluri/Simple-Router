# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
#
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    
    def drop(packet, packet_in):
      msg = of.ofp_flow_mod()

      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 30
      msg.hard_timeout = 30
      msg.data = packet_in
      self.connection.send(msg)

    def flood(packet, packet_in, portNum):
      msg = of.ofp_flow_mod()

      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 30
      msg.hard_timeout = 30
      msg.actions.append(of.ofp_action_output(port=portNum))
      msg.data = packet_in
      self.connection.send(msg)

    arp = packet.find('arp')
    icmp = packet.find('icmp')
    ipv4 = packet.find('ipv4')

    addresses = {
      "128.114.1.101": 3, # Floor 1 (h101)
      "128.114.1.102": 3, # Floor 1 (h102)
      "128.114.1.103": 4, # Floor 1 (h103)
      "128.114.1.104": 4, # Floor 1 (h104)
      "128.114.2.201": 5, # Floor 2 (h201)
      "128.114.2.202": 5, # Floor 2 (h202)
      "128.114.2.203": 6, # Floor 2 (h203)
      "128.114.2.204": 6, # Floor 2 (h204)
      "108.35.24.113": 1, # Untrust host
      "192.47.38.109": 2, # Trust host
      "128.114.3.178": 7 # LLM Server
    }

    if arp:
      # log.debug(f"Handling ARP packet on switch {switch_id}, port {port_on_switch}")
      msg = of.ofp_flow_mod()
      # installs the role to the switch
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 30
      msg.hard_timeout = 30
      msg.data = packet_in
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)

    if ipv4 is not None:
      if icmp is not None:
        # dest_ip: receiver's ip address
        dest_ip = str(ipv4.dstip)
        
        # SWITCH 1
        if switch_id == 1:
          # check dest_ip and forward it
          # from core
          if dest_ip == "128.114.1.101":
            flood(packet, packet_in, 8) # flood -> h101
          elif dest_ip == "128.114.1.102":
            flood(packet, packet_in, 9) # flood -> h102
          else:
            flood(packet, packet_in, 1) # flood -> s6/core

        # SWITCH 2
        elif switch_id == 2:
          # check dest_ip and forward it
          if dest_ip == "128.114.1.103":
            flood(packet, packet_in, 8) # flood -> h103
          elif dest_ip == "128.114.1.104":
            flood(packet, packet_in, 9) # flood -> h104
          else:
            flood(packet, packet_in, 1) # flood -> s6/core
        
        # SWITCH 3
        elif switch_id == 3:
          # check dest_ip and forward it
          if dest_ip == "128.114.2.201":
            flood(packet, packet_in, 8) # flood -> h201  
          elif dest_ip == "128.114.2.202":
            flood(packet, packet_in, 9) # flood -> h202
          else:
            flood(packet, packet_in, 1) # flood -> s6/core

        # SWITCH 4
        elif switch_id == 4:
          # check dest_ip and forward it
          if dest_ip == "128.114.2.203":
            flood(packet, packet_in, 8) # flood -> h203
          elif dest_ip == "128.114.2.204":
            flood(packet, packet_in, 9) # flood -> h204
          else:
            flood(packet, packet_in, 1) # flood -> s6/core

        # SWITCH 5
        elif switch_id == 5:
          # check dest_ip and forward it
          # from core
          if port_on_switch == 1:
            flood(packet, packet_in, 8) # flood -> s6/core
          
          # from h_server
          if port_on_switch == 8:
            flood(packet, packet_in, 1) # flood -> h_llm

        # SWITCH 6 (CORE SWITCH)
        elif switch_id == 6: 

          # The firewall part
          if port_on_switch == 1: # from h_untrust
            if dest_ip == "128.114.1.101":
              drop(packet, packet_in) # drop h101
            if dest_ip == "128.114.1.102":
              drop(packet, packet_in) # drop h102
            if dest_ip == "128.114.1.103":
              drop(packet, packet_in) # drop h103
            if dest_ip == "128.114.1.104":
              drop(packet, packet_in) # drop h104
            if dest_ip == "128.114.2.201":
              drop(packet, packet_in) # drop h201
            if dest_ip == "128.114.2.202":
              drop(packet, packet_in) # drop h202
            if dest_ip == "128.114.2.203":
              drop(packet, packet_in) # drop h203
            if dest_ip == "128.114.2.204":
              drop(packet, packet_in) # drop h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood h_trust
            if dest_ip == "128.114.3.178":
              drop(packet, packet_in) # drop h_llm

          if port_on_switch == 2: # from h_trust
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              drop(packet, packet_in) # drop h201
            if dest_ip == "128.114.2.202":
              drop(packet, packet_in) # drop h202
            if dest_ip == "128.114.2.203":
              drop(packet, packet_in) # drop h203
            if dest_ip == "128.114.2.204":
              drop(packet, packet_in) # drop h204
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses ["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              drop(packet, packet_in) # drop h_llm

          if port_on_switch == 3 or port_on_switch == 4: # Department A (h101-h104)
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              drop(packet, packet_in) # drop h201
            if dest_ip == "128.114.2.202":
              drop(packet, packet_in) # drop h202
            if dest_ip == "128.114.2.203":
              drop(packet, packet_in) # drop h203
            if dest_ip == "128.114.2.204":
              drop(packet, packet_in) # drop h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood -> h_trust
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              flood(packet, packet_in, addresses["128.114.3.178"]) # flood -> h_llm

          if port_on_switch == 5 or port_on_switch == 6: # Department B (h201-h204)
            if dest_ip == "128.114.1.101":
              drop(packet, packet_in) # drop h101
            if dest_ip == "128.114.1.102":
              drop(packet, packet_in) # drop h102
            if dest_ip == "128.114.1.103":
              drop(packet, packet_in) # drop h103
            if dest_ip == "128.114.1.104":
              drop(packet, packet_in) # drop h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood -> h_trust
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              flood(packet, packet_in, addresses["128.114.3.178"]) # flood -> h_llm
            
          if port_on_switch == 7: # from h_server
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood -> h_trust
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses["108.35.24.113"]) # flood -> h_untrust

      else:
        dest_ip = str(ipv4.dstip)

        # SWITCH 1
        if switch_id == 1:
          if dest_ip == "128.114.1.101":
            flood(packet, packet_in, 8) # flood -> h101
          elif dest_ip == "128.114.1.102":
            flood(packet, packet_in, 9) # flood -> h102
          else:
            flood(packet, packet_in, 1) # flood -> s0/core

        # SWITCH 2
        if switch_id == 2:
          # check dest_ip and forward it
          if dest_ip == "128.114.1.103":
            flood(packet, packet_in, 8) # flood -> h103
          elif dest_ip == "128.114.1.104":
            flood(packet, packet_in, 9) # flood -> h104
          else:
            flood(packet, packet_in, 1) # flood -> s0/core

        # SWITCH 3
        if switch_id == 3:
          # check dest_ip and forward it
          if dest_ip == "128.114.2.201":
            flood(packet, packet_in, 8) # flood -> h203
          elif dest_ip == "128.114.2.202":
            flood(packet, packet_in, 9) # flood -> h204
          else:
            flood(packet, packet_in, 1) # flood -> s0/core
        
        # SWITCH 4
        if switch_id == 4:
          # check dest_ip and forward it
          if dest_ip == "128.114.2.203":
            flood(packet, packet_in, 8) # flood -> h203
          elif dest_ip == "128.114.2.204":
            flood(packet, packet_in, 9) # flood -> h204
          else:
            flood(packet, packet_in, 1) # flood -> s0/core

        # SWITCH 5
        if switch_id == 5:
          if port_on_switch == 1:
            flood(packet, packet_in, 8) # flood -> h_llm
          
          # from h_server
          if port_on_switch == 8:
            flood(packet, packet_in, 1) # flood -> s0/core

        # SWITCH 0
        if switch_id == 6: 

          # The firewall part
          if port_on_switch == 1: # from h_untrust
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood h_trust
            if dest_ip == "128.114.3.178":
              drop(packet, packet_in) # drop h_llm

          if port_on_switch == 2: # from h_trust
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses ["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              drop(packet, packet_in) # drop h_llm

          if port_on_switch == 3 or port_on_switch == 4: # Department A (h101-h104)
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood -> h_trust
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              flood(packet, packet_in, addresses["128.114.3.178"]) # flood -> h_llm

          if port_on_switch == 5 or port_on_switch == 6: # Department B (h201-h204)
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood -> h_trust
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              flood(packet, packet_in, addresses["128.114.3.178"]) # flood -> h_llm

          if port_on_switch == 7: # from h_server
            if dest_ip == "128.114.1.101":
              flood(packet, packet_in, addresses["128.114.1.101"]) # flood -> h101
            if dest_ip == "128.114.1.102":
              flood(packet, packet_in, addresses["128.114.1.102"]) # flood -> h102
            if dest_ip == "128.114.1.103":
              flood(packet, packet_in, addresses["128.114.1.103"]) # flood -> h103
            if dest_ip == "128.114.1.104":
              flood(packet, packet_in, addresses["128.114.1.104"]) # flood -> h104
            if dest_ip == "128.114.2.201":
              flood(packet, packet_in, addresses["128.114.2.201"]) # flood -> h201
            if dest_ip == "128.114.2.202":
              flood(packet, packet_in, addresses["128.114.2.202"]) # flood -> h202
            if dest_ip == "128.114.2.203":
              flood(packet, packet_in, addresses["128.114.2.203"]) # flood -> h203
            if dest_ip == "128.114.2.204":
              flood(packet, packet_in, addresses["128.114.2.204"]) # flood -> h204
            if dest_ip == "192.47.38.109":
              flood(packet, packet_in, addresses["192.47.38.109"]) # flood -> h_trust
            if dest_ip == "108.35.24.113":
              flood(packet, packet_in, addresses["108.35.24.113"]) # flood -> h_untrust
            if dest_ip == "128.114.3.178":
              flood(packet, packet_in, addresses["128.114.3.178"]) # flood -> h_llm

    else:
      drop(packet, packet_in)

    return



    # print "Example code."

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
