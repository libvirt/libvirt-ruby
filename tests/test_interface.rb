#!/usr/bin/ruby

# Test the interface methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of Interfaces: #{conn.num_of_interfaces}"
puts "Number of Defined Interfaces: #{conn.num_of_defined_interfaces}"

new_interface_xml = <<EOF
<interface type='bridge' name='testbr7'>
  <bridge>
    <interface type='ethernet' name='dummy'>
    </interface>
  </bridge>
</interface>
EOF

# FIXME: doesn't work at the moment
#new_interface = conn.define_interface_xml(new_interface_xml)
#new_interface.undefine

defined = conn.list_defined_interfaces
running = conn.list_interfaces

(defined+running).each do |intname|
  interface = conn.lookup_interface_by_name(intname)
  int2 = conn.lookup_interface_by_mac(interface.mac)
  puts "Interface #{interface.name}:"
  puts " MAC: #{interface.mac}"
  puts " XML:"
  puts interface.xml_desc
end
conn.close
