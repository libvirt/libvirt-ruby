# this example program goes through all of the node (aka host) devices on
# the current machine and prints some information about each device

require 'libvirt'

# connect to libvirt
conn = Libvirt::open('qemu:///system')

# find out how many devices there are on this system
puts "Number of node devices: #{conn.num_of_nodedevices}"

# look at each device.  list_nodedevices returns an array of names, so it is
# necessary to look each device up by name to get a nodedevice object
conn.list_nodedevices.each do |device|
  nd = conn.lookup_nodedevice_by_name(device)

  # print some information about the device
  puts "Nodedevice:"
  puts " Name: #{nd.name}"
  puts " Parent: #{nd.parent}"
  puts " Number of Capabilities: #{nd.num_of_caps}"
  puts " Capabilities: #{nd.list_caps.inspect}"
end

conn.close
