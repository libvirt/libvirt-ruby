#!/usr/bin/ruby

# Test the nwfilter methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of NWFilters: #{conn.num_of_nwfilters}"

new_nwfilter_xml = <<EOF
<filter name='no-spamming'>
  <uuid>d217f2d7-5a04-0e01-8b90-ec274a436b74</uuid>
</filter>
EOF

newnwfilter = conn.define_nwfilter_xml(new_nwfilter_xml)
newnwfilter.undefine

conn.list_nwfilters.each do |nwfname|
  nwfilter = conn.lookup_nwfilter_by_name(nwfname)
  nwf2 = conn.lookup_nwfilter_by_uuid(nwfilter.uuid)
  puts "NWFilter #{nwfilter.name}:"
  puts " UUID: #{nwfilter.uuid}"
  puts " XML:"
  puts nwfilter.xml_desc
end

conn.close
