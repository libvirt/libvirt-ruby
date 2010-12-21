# this example program shows how to define and undefine a new network filter.

require 'libvirt'

# the XML to describe a silly network filter.  This network filter allows any
# ipv4 tcp traffic to host 255.255.255.255 from port 63000 to port 62000 to
# go out.  It also allows any ipv4 tcp traffic from port 63000 to port 62000 to
# come in.  There is a lot more documentation on the nwfilter XML format at
# http://libvirt.org/formatnwfilter.html
nwfilter_xml = <<EOF
<filter name='ruby-libvirt-tester' chain='ipv4'>
  <uuid>bd339530-134c-6d07-441a-17fb90dad807</uuid>
  <rule action='accept' direction='out' priority='100'>
    <ip srcipaddr='0.0.0.0' dstipaddr='255.255.255.255' protocol='tcp' srcportstart='63000' dstportstart='62000'/>
  </rule>
  <rule action='accept' direction='in' priority='100'>
    <ip protocol='tcp' srcportstart='63000' dstportstart='62000'/>
  </rule>
</filter>
EOF

# open the connection to libvirt
conn = Libvirt::open('qemu:///system')

# print out how many filters are currently defined
puts "Number of nwfilters: #{conn.num_of_nwfilters}"

# define our new filter
nwf = conn.define_nwfilter_xml(nwfilter_xml)

# now there should be one more filter than before
puts "Number of nwfilters: #{conn.num_of_nwfilters}"

# print out some information about our filter
puts "NWFilter:"
puts " Name: #{nwf.name}"
puts " UUID: #{nwf.uuid}"

# remove the filter
nwf.undefine

conn.close
