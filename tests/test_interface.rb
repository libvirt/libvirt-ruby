#!/usr/bin/ruby

# Test the interface methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

begin
  `rm -f /etc/sysconfig/network-scripts/ifcfg-ruby-libvirt-tester`
  `brctl delbr ruby-libvirt-tester >& /dev/null`
rescue
end

new_interface_xml = <<EOF
<interface type="bridge" name="ruby-libvirt-tester">
  <start mode="onboot"/>
  <bridge delay="0">
  </bridge>
</interface>
EOF

# TESTGROUP: conn.num_of_interfaces
expect_too_many_args(conn, "num_of_interfaces", 1)
numifaces = conn.num_of_interfaces
puts_ok "conn.num_of_interfaces no args = #{numifaces}"

# TESTGROUP: conn.list_interfaces
expect_too_many_args(conn, "list_interfaces", 1)
ifacelist = conn.list_interfaces
puts_ok "conn.list_interfaces no args = "

# TESTGROUP: conn.num_of_defined_interfaces
expect_too_many_args(conn, "num_of_defined_interfaces", 1)
numifaces = conn.num_of_defined_interfaces
puts_ok "conn.num_of_defined_interfaces no args = #{numifaces}"

# TESTGROUP: conn.list_defined_interfaces
expect_too_many_args(conn, "list_defined_interfaces", 1)
ifacelist = conn.list_defined_interfaces
puts_ok "conn.list_defined_interfaces no args = "

# TESTGROUP: conn.lookup_interface_by_name
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(conn, "lookup_interface_by_name", 1, 2)
expect_too_few_args(conn, "lookup_interface_by_name")
expect_invalid_arg_type(conn, "lookup_interface_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_interface_by_name", "foobarbazsucker")

conn.lookup_interface_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_interface_by_name running interface succeeded"

newiface.destroy
conn.lookup_interface_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_interface_by_name defined but off interface succeeded"
newiface.undefine

# TESTGROUP: conn.lookup_interface_by_mac
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(conn, "lookup_interface_by_mac", 1, 2)
expect_too_few_args(conn, "lookup_interface_by_mac")
expect_invalid_arg_type(conn, "lookup_interface_by_mac", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent mac arg", "lookup_interface_by_mac", "foobarbazsucker")

#conn.lookup_interface_by_mac("ruby-libvirt-tester")
#puts_ok "conn.lookup_interface_by_mac running interface succeeded"
#newiface.destroy

#newiface = conn.define_interface_xml(new_interface_xml)
#conn.lookup_interface_by_mac("ruby-libvirt-tester")
#puts_ok "conn.lookup_interface_by_mac defined but off interface succeeded"
newiface.undefine

# TESTGROUP: conn.define_interface_xml
expect_too_many_args(conn, "define_interface_xml", 1, 2, 3)
expect_too_few_args(conn, "define_interface_xml")
expect_invalid_arg_type(conn, "define_interface_xml", 1)
expect_invalid_arg_type(conn, "define_interface_xml", nil)
expect_invalid_arg_type(conn, "define_interface_xml", "hello", 'foo')
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_interface_xml", "hello")

newiface = conn.define_interface_xml(new_interface_xml)
puts_ok "conn.define_interface_xml with valid XML succeeded"
newiface.undefine

# TESTGROUP: iface.undefine
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "undefine", 1)

newiface.undefine
puts_ok "iface.undefine succeeded"

# TESTGROUP: iface.create
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "create", 1, 2)
expect_invalid_arg_type(newiface, "create", 'foo')

#newiface.create
#puts_ok "iface.create succeeded"

#expect_fail(newiface, Libvirt::Error, "on already running interface", "create")

#newiface.destroy
newiface.undefine

# TESTGROUP: iface.destroy
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "destroy", 1, 2)
expect_invalid_arg_type(newiface, "destroy", 'foo')
newiface.destroy
puts_ok "iface.destroy succeeded"

newiface.undefine

# TESTGROUP: iface.active?
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "active?", 1)

#active = newiface.active?
#if not active
#  puts_fail "iface.active? on running interface was false"
#else
#  puts_ok "iface.active? on running interface was true"
#end

#newiface.destroy

#newiface = conn.define_interface_xml(new_interface_xml)

active = newiface.active?
if active
  puts_fail "iface.active? on shutoff interface was true"
else
  puts_ok "iface.active? on shutoff interface was false"
end

#newiface.create

#active = newiface.active?
#if not active
#  puts_fail "iface.active? on running interface was false"
#else
#  puts_ok "iface.active? on running interface was true"
#end

#newiface.destroy
newiface.undefine

# TESTGROUP: iface.name
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "name", 1)
name = newiface.name
if name != "ruby-libvirt-tester"
  puts_fail "iface.name expected to be ruby-libvirt-tester, but was #{name}"
else
  puts_ok "iface.name succeeded"
end

newiface.undefine

# TESTGROUP: iface.mac
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "mac", 1)
#mac = newiface.mac
#if mac != "ruby-libvirt-tester"
#  puts_fail "iface.mac expected to be ruby-libvirt-tester, but was #{mac}"
#else
#  puts_ok "iface.mac succeeded"
#end

newiface.undefine

# TESTGROUP: iface.xml_desc
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "xml_desc", 1, 2)
expect_invalid_arg_type(newiface, "xml_desc", "foo")

#newiface.xml_desc
#puts_ok "iface.xml_desc succeeded"

newiface.undefine

# TESTGROUP: iface.free

conn.close

finish_tests
