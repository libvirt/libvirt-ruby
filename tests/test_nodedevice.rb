#!/usr/bin/ruby

# Test the nodedevice methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

# TESTGROUP: conn.num_of_nodedevices
expect_too_many_args(conn, "num_of_nodedevices", 1, 2, 3)
expect_invalid_arg_type(conn, "num_of_nodedevices", 1)
expect_invalid_arg_type(conn, "num_of_nodedevices", 'foo', 'bar')
numnodes = conn.num_of_nodedevices
puts_ok "conn.num_of_nodedevices no args = #{numnodes}"

# TESTGROUP: conn.list_nodedevices
expect_too_many_args(conn, "list_nodedevices", 1, 2, 3)
expect_invalid_arg_type(conn, "list_nodedevices", 1)
expect_invalid_arg_type(conn, "list_nodedevices", 'foo', 'bar')
devlist = conn.list_nodedevices
puts_ok "conn.list_nodedevices no args = "

# TESTGROUP: conn.lookup_nodedevice_by_name
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(conn, "lookup_nodedevice_by_name", 1, 2)
expect_too_few_args(conn, "lookup_nodedevice_by_name")
expect_invalid_arg_type(conn, "lookup_nodedevice_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_nodedevice_by_name", "foobarbazsucker")

conn.lookup_nodedevice_by_name(testnode.name)
puts_ok "conn.lookup_nodedevice_by_name running nodedevice succeeded"

# TESTGROUP: conn.create_nodedevice_xml

# TESTGROUP: nodedevice.name
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "name", 1)
name = testnode.name
puts_ok "nodedevice.name no args = #{name}"

# TESTGROUP: nodedevice.parent
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "parent", 1)
parent = testnode.parent
puts_ok "nodedevice.parent no args = #{parent}"

# TESTGROUP: nodedevice.num_of_caps
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "num_of_caps", 1)
num_of_caps = testnode.num_of_caps
puts_ok "nodedevice.num_of_caps no args = #{num_of_caps}"

# TESTGROUP: nodedevice.list_caps
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "list_caps", 1)
caplist = testnode.list_caps
puts_ok "nodedevice.list_caps no args = "


# TESTGROUP: nodedevice.xml_desc
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "xml_desc", 1, 2)
expect_invalid_arg_type(testnode, "xml_desc", 'foo')
xml = testnode.xml_desc
puts_ok "nodedevice.xml_desc no args = "

# TESTGROUP: nodedevice.detach

# TESTGROUP: nodedevice.reattach

# TESTGROUP: nodedevice.reset

# TESTGROUP: nodedevice.destroy

# TESTGROUP: nodedevice.free

conn.close

finish_tests
