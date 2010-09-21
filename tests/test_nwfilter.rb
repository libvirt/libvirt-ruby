#!/usr/bin/ruby

# Test the nwfilter methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

new_nwfilter_xml = <<EOF
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

# TESTGROUP: conn.num_of_nwfilters
expect_too_many_args(conn, "num_of_nwfilters", 1)
numfilters = conn.num_of_nwfilters
puts_ok "conn.num_of_nwfilters no args = #{numfilters}"

# TESTGROUP: conn.list_nwfilters
expect_too_many_args(conn, "list_nwfilters", 1)
filterlist = conn.list_nwfilters
puts_ok "conn.list_nwfilters no args = "

# TESTGROUP: conn.lookup_nwfilter_by_name
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(conn, "lookup_nwfilter_by_name", 1, 2)
expect_too_few_args(conn, "lookup_nwfilter_by_name")
expect_invalid_arg_type(conn, "lookup_nwfilter_by_name", 1)

filt = conn.lookup_nwfilter_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_nwfilter_by_name succeeded"

newnw.undefine

# TESTGROUP: conn.lookup_nwfilter_by_uuid
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(conn, "lookup_nwfilter_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_nwfilter_by_uuid")
expect_invalid_arg_type(conn, "lookup_nwfilter_by_uuid", 1)

filt = conn.lookup_nwfilter_by_uuid("bd339530-134c-6d07-441a-17fb90dad807")
puts_ok "conn.lookup_nwfilter_by_uuid succeeded"

newnw.undefine

# TESTGROUP: conn.define_nwfilter_xml
expect_too_many_args(conn, "define_nwfilter_xml", 1, 2)
expect_too_few_args(conn, "define_nwfilter_xml")
expect_invalid_arg_type(conn, "define_nwfilter_xml", 1)
expect_invalid_arg_type(conn, "define_nwfilter_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_nwfilter_xml", "hello")

newnw = conn.define_nwfilter_xml(new_nwfilter_xml)
puts_ok "conn.define_nwfilter_xml succeeded"
newnw.undefine

# TESTGROUP: nwfilter.undefine
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "undefine", 1)

newnw.undefine
puts_ok "nwfilter.undefine succeeded"

# TESTGROUP: nwfilter.name
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "name", 1)
name = newnw.name
if name != "ruby-libvirt-tester"
  puts_fail "nwfilter.name expected to be ruby-libvirt-tester, but was #{name}"
else
  puts_ok "nwfilter.name succeeded"
end

newnw.undefine

# TESTGROUP: nwfilter.uuid
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "uuid", 1)
uuid = newnw.uuid
if uuid != "bd339530-134c-6d07-441a-17fb90dad807"
  puts_fail "nwfilter.uuid expected to be bd339530-134c-6d07-441a-17fb90dad807, but was #{uuid}"
else
  puts_ok "nwfilter.uuid succeeded"
end

newnw.undefine

# TESTGROUP: nwfilter.xml_desc
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "xml_desc", 1, 2)
expect_invalid_arg_type(newnw, "xml_desc", "foo")

newnw.xml_desc
puts_ok "nwfilter.xml_desc succeeded"

newnw.undefine

# TESTGROUP: nwfilter.free


conn.close

finish_tests
