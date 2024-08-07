#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController

class final_topo(Topo):
  def build(self):
    # Examples!
    # Create a host with a default route of the ethernet interface. You'll need to set the
    # default gateway like this for every host you make on this assignment to make sure all 
    # packets are sent out that port. Make sure to change the h# in the defaultRoute area
    # and the MAC address when you add more hosts!

    # Outside Hosts
    h_untrust = self.addHost('h_untrust',mac='66:66:66:66:66:66',ip='108.35.24.113/24', defaultRoute="h_untrust-eth0")
    h_trust = self.addHost('h_trust',mac='77:77:77:77:77:77',ip='192.47.38.109/24', defaultRoute="h_trust-eth0")

    # Floor 1 Hosts
    h101 = self.addHost('h101',mac='00:00:00:00:00:01',ip='128.114.1.101/24', defaultRoute="h101-eth0")
    h102 = self.addHost('h102',mac='00:00:00:00:00:02',ip='128.114.1.102/24', defaultRoute="h102-eth0")
    h103 = self.addHost('h103',mac='00:00:00:00:00:03',ip='128.114.1.103/24', defaultRoute="h103-eth0")
    h104 = self.addHost('h104',mac='00:00:00:00:00:04',ip='128.114.1.104/24', defaultRoute="h104-eth0")

    # Floor 2 Hosts
    h201 = self.addHost('h201',mac='00:00:00:00:00:05',ip='128.114.2.201/24', defaultRoute="h201-eth0")
    h202 = self.addHost('h202',mac='00:00:00:00:00:06',ip='128.114.2.202/24', defaultRoute="h202-eth0")
    h203 = self.addHost('h203',mac='00:00:00:00:00:07',ip='128.114.2.203/24', defaultRoute="h203-eth0")
    h204 = self.addHost('h204',mac='00:00:00:00:00:08',ip='128.114.2.204/24', defaultRoute="h204-eth0")

    # LLM Server Host
    h_llm = self.addHost('h_llm',mac='99:99:99:99:99:99',ip='128.114.3.178/24', defaultRoute="h_llm-eth0")


    # Create a switch. No changes here from Lab 1.

    # Floor 1 Switches
    s1 = self.addSwitch('s1')
    s2 = self.addSwitch('s2')

    # Floor 2 Switches
    s3 = self.addSwitch('s3')
    s4 = self.addSwitch('s4')

    # Data Center Switch
    s5 = self.addSwitch('s5')

    # Core Switch
    s6 = self.addSwitch('s6')

    # Connect Port 8 on the Switch to Port 0 on Host 1 and Port 9 on the Switch to Port 0 on 
    # Host 2. This is representing the physical port on the switch or host that you are 
    # connecting to.

    # IMPORTANT NOTES: 
    # - On a single device, you can only use each port once! So, on s1, only 1 device can be
    #   plugged in to port 1, only one device can be plugged in to port 2, etc.
    # - On the "host" side of connections, you must make sure to always match the port you 
    #   set as the default route when you created the device above. Usually, this means you 
    #   should plug in to port 0 (since you set the default route to h#-eth0).

    # Floor 1 Switch 1
    self.addLink(s1,h101, port1=8, port2=0)
    self.addLink(s1,h102, port1=9, port2=0)

    # Floor 2 Switch 1
    self.addLink(s3,h201, port1=8, port2=0)
    self.addLink(s3,h202, port1=9, port2=0)

    # Floor 1 Switch 2
    self.addLink(s2,h103, port1=8, port2=0)
    self.addLink(s2,h104, port1=9, port2=0)

    # Floor 2 Switch 2
    self.addLink(s4,h203, port1=8, port2=0)
    self.addLink(s4,h204, port1=9, port2=0)

    # Datacenter Link to Server
    self.addLink(s5,h_llm, port1=8, port2=0)

    # Core Switch Links
    self.addLink(s6,h_untrust, port1=1, port2=0)
    self.addLink(s6,h_trust, port1=2, port2=0)
    self.addLink(s6,s1, port1=3, port2=1)
    self.addLink(s6,s2, port1=4, port2=1)
    self.addLink(s6,s3, port1=5, port2=1)
    self.addLink(s6,s4, port1=6, port2=1)
    self.addLink(s6,s5, port1=7, port2=1)

    # print "Delete me!"

def configure():
  topo = final_topo()
  net = Mininet(topo=topo, controller=RemoteController)
  net.start()

  CLI(net)
  
  net.stop()


if __name__ == '__main__':
  configure()