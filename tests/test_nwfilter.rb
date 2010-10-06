#!/usr/bin/ruby

# Test the nwfilter methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

UUID = "bd339530-134c-6d07-441a-17fb90dad807"

conn = Libvirt::open("qemu:///system")

new_nwfilter_xml = <<EOF
<filter name='ruby-libvirt-tester' chain='ipv4'>
  <uuid>#{UUID}</uuid>
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
expect_success(conn, "no args", "num_of_nwfilters")

# TESTGROUP: conn.list_nwfilters
expect_too_many_args(conn, "list_nwfilters", 1)
expect_success(conn, "no args", "list_nwfilters")

# TESTGROUP: conn.lookup_nwfilter_by_name
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(conn, "lookup_nwfilter_by_name", 1, 2)
expect_too_few_args(conn, "lookup_nwfilter_by_name")
expect_invalid_arg_type(conn, "lookup_nwfilter_by_name", 1)

expect_success(conn, "name arg", "lookup_nwfilter_by_name", "ruby-libvirt-tester")

newnw.undefine

# TESTGROUP: conn.lookup_nwfilter_by_uuid
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(conn, "lookup_nwfilter_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_nwfilter_by_uuid")
expect_invalid_arg_type(conn, "lookup_nwfilter_by_uuid", 1)

expect_success(conn, "uuid arg", "lookup_nwfilter_by_uuid", UUID) {|x| x.uuid == UUID}

newnw.undefine

# TESTGROUP: conn.define_nwfilter_xml
expect_too_many_args(conn, "define_nwfilter_xml", 1, 2)
expect_too_few_args(conn, "define_nwfilter_xml")
expect_invalid_arg_type(conn, "define_nwfilter_xml", 1)
expect_invalid_arg_type(conn, "define_nwfilter_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_nwfilter_xml", "hello")

newnw = expect_success(conn, "nwfilter XML", "define_nwfilter_xml", new_nwfilter_xml)

newnw.undefine

# TESTGROUP: nwfilter.undefine
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "undefine", 1)

expect_success(newnw, "no args", "undefine")

# TESTGROUP: nwfilter.name
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "name", 1)

expect_success(newnw, "no args", "name") {|x| x == "ruby-libvirt-tester"}

newnw.undefine

# TESTGROUP: nwfilter.uuid
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "uuid", 1)

expect_success(newnw, "no args", "uuid") {|x| x == UUID}

newnw.undefine

# TESTGROUP: nwfilter.xml_desc
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)

expect_too_many_args(newnw, "xml_desc", 1, 2)
expect_invalid_arg_type(newnw, "xml_desc", "foo")

expect_success(newnw, "no args", "xml_desc")

newnw.undefine

# TESTGROUP: nwfilter.free
newnw = conn.define_nwfilter_xml(new_nwfilter_xml)
newnw.undefine
expect_too_many_args(newnw, "free", 1)

expect_success(newnw, "no args", "free")

conn.close

finish_tests
