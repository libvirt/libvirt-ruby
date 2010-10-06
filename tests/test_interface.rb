#!/usr/bin/ruby

# Test the interface methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

def find_valid_iface(conn)
  conn.list_interfaces.each do |ifname|
    iface = conn.lookup_interface_by_name(ifname)
    if iface.mac == "00:00:00:00:00:00"
      next
    end
    return iface
  end
end


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
expect_success(conn, "no args", "num_of_interfaces")

# TESTGROUP: conn.list_interfaces
expect_too_many_args(conn, "list_interfaces", 1)
expect_success(conn, "no args", "list_interfaces")

# TESTGROUP: conn.num_of_defined_interfaces
expect_too_many_args(conn, "num_of_defined_interfaces", 1)
expect_success(conn, "no args", "num_of_defined_interfaces")

# TESTGROUP: conn.list_defined_interfaces
expect_too_many_args(conn, "list_defined_interfaces", 1)
expect_success(conn, "no args", "list_defined_interfaces")

# TESTGROUP: conn.lookup_interface_by_name
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(conn, "lookup_interface_by_name", 1, 2)
expect_too_few_args(conn, "lookup_interface_by_name")
expect_invalid_arg_type(conn, "lookup_interface_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_interface_by_name", "foobarbazsucker")

expect_success(conn, "name arg", "lookup_interface_by_name", "ruby-libvirt-tester")

newiface.destroy

expect_success(conn, "name arg", "lookup_interface_by_name", "ruby-libvirt-tester")

newiface.undefine

# TESTGROUP: conn.lookup_interface_by_mac
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(conn, "lookup_interface_by_mac", 1, 2)
expect_too_few_args(conn, "lookup_interface_by_mac")
expect_invalid_arg_type(conn, "lookup_interface_by_mac", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent mac arg", "lookup_interface_by_mac", "foobarbazsucker")

testiface = find_valid_iface(conn)
if not testiface.nil?
  expect_success(conn, "name arg", "lookup_interface_by_mac", testiface.mac) {|x| x.mac == testiface.mac}
end

newiface.undefine

# TESTGROUP: conn.define_interface_xml
expect_too_many_args(conn, "define_interface_xml", 1, 2, 3)
expect_too_few_args(conn, "define_interface_xml")
expect_invalid_arg_type(conn, "define_interface_xml", 1)
expect_invalid_arg_type(conn, "define_interface_xml", nil)
expect_invalid_arg_type(conn, "define_interface_xml", "hello", 'foo')
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_interface_xml", "hello")

expect_success(conn, "interface XML", "define_interface_xml", new_interface_xml)
newiface.undefine

# TESTGROUP: iface.undefine
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "undefine", 1)

expect_success(newiface, "no args", "undefine")

# TESTGROUP: iface.create
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "create", 1, 2)
expect_invalid_arg_type(newiface, "create", 'foo')

#expect_success(newiface, "no args", "create")

#expect_fail(newiface, Libvirt::Error, "on already running interface", "create")

#newiface.destroy
newiface.undefine

# TESTGROUP: iface.destroy
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "destroy", 1, 2)
expect_invalid_arg_type(newiface, "destroy", 'foo')

expect_success(newiface, "no args", "destroy")

newiface.undefine

# TESTGROUP: iface.active?
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "active?", 1)

expect_success(newiface, "no args", "active?") {|x| x == false}

#newiface.create
#expect_success(newiface, "no args", "active?") {|x| x == true}

#newiface.destroy
newiface.undefine

# TESTGROUP: iface.name
newiface = conn.define_interface_xml(new_interface_xml)

expect_too_many_args(newiface, "name", 1)

expect_success(newiface, "no args", "name") {|x| x == "ruby-libvirt-tester"}

newiface.undefine

# TESTGROUP: iface.mac
testiface = find_valid_iface(conn)
if not testiface.nil?
  expect_too_many_args(testiface, "mac", 1)

  expect_success(testiface, "no args", "mac") {|x| x == testiface.mac}
end

# TESTGROUP: iface.xml_desc
testiface = find_valid_iface(conn)
if not testiface.nil?
  expect_too_many_args(testiface, "xml_desc", 1, 2)
  expect_invalid_arg_type(testiface, "xml_desc", "foo")
  expect_success(testiface, "no args", "xml_desc")
end

# TESTGROUP: iface.free
newiface = conn.define_interface_xml(new_interface_xml)
newiface.undefine
expect_too_many_args(newiface, "free", 1)

expect_success(newiface, "no args", "free")

conn.close

finish_tests
