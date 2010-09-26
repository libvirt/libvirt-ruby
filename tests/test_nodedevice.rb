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
expect_too_many_args(conn, "create_nodedevice_xml", 1, 2, 3)
expect_too_few_args(conn, "create_nodedevice_xml")
expect_invalid_arg_type(conn, "create_nodedevice_xml", 1)
expect_invalid_arg_type(conn, "create_nodedevice_xml", "foo", 'bar')
expect_fail(conn, Libvirt::Error, "invalid XML", "create_nodedevice_xml", "hello")

#conn.create_nodedevice_xml("<nodedevice>")
#puts_ok "conn.create_nodedevice_xml succeeded

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
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "detach", 1)

#nodedevice.detach
#puts_ok "nodedevice.detach no args = "

# TESTGROUP: nodedevice.reattach
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "reattach", 1)

#nodedevice.reattach
#puts_ok "nodedevice.reattach no args = "

# TESTGROUP: nodedevice.reset
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "reset", 1)

#nodedevice.reset
#puts_ok "nodedevice.reset no args = "

# TESTGROUP: nodedevice.destroy
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "destroy", 1)

#nodedevice.destroy
#puts_ok "nodedevice.destroy no args = "

# TESTGROUP: nodedevice.free
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(testnode, "free", 1)

testnode.free
puts_ok "nodedevice.free succeeded"

conn.close

finish_tests
