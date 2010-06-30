#!/usr/bin/ruby

# Test the network methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of Networks: #{conn.num_of_networks}"
puts "Number of Defined Networks: #{conn.num_of_defined_networks}"

new_network_xml = <<EOF
<network>
  <name>testnetwork</name>
  <uuid>e0eed9fa-cb64-433f-066c-257a29b1c13a</uuid>
</network>
EOF

newnetwork = conn.define_network_xml(new_network_xml)
newnetwork.create
newnetwork.destroy
newnetwork.undefine

defined = conn.list_defined_networks
running = conn.list_networks

(defined+running).each do |netname|
  network = conn.lookup_network_by_name(netname)
  net2 = conn.lookup_network_by_uuid(network.uuid)

  puts "Network #{network.name}:"
  puts " UUID: #{network.uuid}"
  puts " Autostart?: #{network.autostart?}"
  puts " Active?: #{network.active?}"
  puts " Persistent?: #{network.persistent?}"
  puts " Bridge Name: #{network.bridge_name}"
  puts " XML:"
  puts network.xml_desc
end

conn.close
