#!/usr/bin/ruby

# Test the nodedevice methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of NodeDevices: #{conn.num_of_nodedevices}"

conn.list_nodedevices.each do |nodename|
  nodedevice = conn.lookup_nodedevice_by_name(nodename)
  puts "NodeDevice #{nodedevice.name}:"
  puts " Parent: #{nodedevice.parent}"
  puts " Number Caps: #{nodedevice.num_of_caps}"
  puts " Caps:"
  nodedevice.list_caps.each do |cap|
    puts "  #{cap}"
  end
  puts " XML:"
  puts nodedevice.xml_desc
end

conn.close
