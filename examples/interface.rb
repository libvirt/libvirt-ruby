# this example program demonstrates how to create a new interface using
# the libvirt APIs

require 'libvirt'

# the new interface XML.  This example XML creates a bridge named
# "ruby-libvirt-tester", intended to start on boot, with a bridge delay of 0.
interface_xml = <<EOF
<interface type="bridge" name="ruby-libvirt-tester">
  <start mode="onboot"/>
  <bridge delay="0">
  </bridge>
</interface>
EOF

# open the connection to libvirt
conn = Libvirt::open('qemu:///system')

# list the number of interfaces defined
puts "Number of interfaces: #{conn.num_of_interfaces}"

# define (but do not start) the new interface
intf = conn.define_interface_xml(interface_xml)

# print some information about this new interface
puts "Interface:"
puts " Name: #{intf.name}"
puts " MAC: #{intf.mac}"

# start the new interface
intf.create

# now there should be one more interface than there was before
puts "Number of interfaces: #{conn.num_of_interfaces}"

# shutdown the interface
intf.destroy

# undefine the interface
intf.undefine

conn.close
