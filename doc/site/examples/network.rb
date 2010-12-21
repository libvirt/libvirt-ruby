# this example program shows how to create a new network, get information
# about it, start it, and stop it
require 'libvirt'

# the XML describing the network.  This network will be a NAT'ed network with
# host IP of 192.168.134.1, and can hand out DHCP addresses to guests between
# 192.168.134.2 and 192.168.134.254.  http://libvirt.org/formatnetwork.html has
# much more information about the format of the XML.
network_xml = <<EOF
<network>
  <name>ruby-libvirt-tester</name>
  <uuid>04068860-d9a2-47c5-bc9d-9e047ae901da</uuid>
  <forward mode='nat'/>
  <bridge name='rubybr0' stp='on' delay='0' />
  <ip address='192.168.134.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.134.2' end='192.168.134.254' />
    </dhcp>
  </ip>
</network>
EOF

# connect to libvirt
conn = Libvirt::open('qemu:///system')

# print out the number of networks before we do anything
puts "Number of networks: #{conn.num_of_networks}"

# define a new network based on the XML
net = conn.define_network_xml(network_xml)

# print out some information about our new network
puts "Network:"
puts " Name: #{net.name}"
puts " UUID: #{net.uuid}"
puts " Bridge Name: #{net.bridge_name}"
puts " Autostart?: #{net.autostart?}"

# start the new network
net.create

# print out the number of networks, which should be one more than earlier
puts "Number of networks: #{conn.num_of_networks}"

sleep 2

# shutdown the new network
net.destroy

# undefine the new network
net.undefine

conn.close
