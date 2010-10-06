#!/usr/bin/ruby

# Test the network methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

UUID = "04068860-d9a2-47c5-bc9d-9e047ae901da"

conn = Libvirt::open("qemu:///system")

# initial cleanup for previous run
begin
  oldnet = conn.lookup_network_by_name("ruby-libvirt-tester")
  oldnet.destroy
  oldnet.undefine
rescue
  # in case we didn't find it, don't do anything
end

new_net_xml = <<EOF
<network>
  <name>ruby-libvirt-tester</name>
  <uuid>#{UUID}</uuid>
  <forward mode='nat'/>
  <bridge name='rubybr0' stp='on' delay='0' />
  <ip address='192.168.134.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.134.2' end='192.168.134.254' />
    </dhcp>
  </ip>
</network>
EOF

# TESTGROUP: conn.num_of_networks
expect_too_many_args(conn, "num_of_networks", 1)
expect_success(conn, "no args", "num_of_networks")

# TESTGROUP: conn.list_networks
expect_too_many_args(conn, "list_networks", 1)
expect_success(conn, "no args", "list_networks")

# TESTGROUP: conn.num_of_defined_networks
expect_too_many_args(conn, "num_of_defined_networks", 1)
expect_success(conn, "no args", "num_of_defined_networks")

# TESTGROUP: conn.list_defined_networks
expect_too_many_args(conn, "list_defined_networks", 1)
expect_success(conn, "no args", "list_defined_networks")

# TESTGROUP: conn.lookup_network_by_name
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(conn, "lookup_network_by_name", 1, 2)
expect_too_few_args(conn, "lookup_network_by_name")
expect_invalid_arg_type(conn, "lookup_network_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_network_by_name", "foobarbazsucker")

expect_success(conn, "name arg", "lookup_network_by_name", "ruby-libvirt-tester")
newnet.destroy

newnet = conn.define_network_xml(new_net_xml)
expect_success(conn, "name arg", "lookup_network_by_name", "ruby-libvirt-tester")
newnet.undefine

# TESTGROUP: conn.lookup_network_by_uuid
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(conn, "lookup_network_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_network_by_uuid")
expect_invalid_arg_type(conn, "lookup_network_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent uuid arg", "lookup_network_by_uuid", "foobarbazsucker")

expect_success(conn, "uuid arg", "lookup_network_by_uuid", UUID)
newnet.destroy

newnet = conn.define_network_xml(new_net_xml)
expect_success(conn, "uuid arg", "lookup_network_by_uuid", UUID)
newnet.undefine

# TESTGROUP: conn.create_network_xml
expect_too_many_args(conn, "create_network_xml", new_net_xml, 0)
expect_too_few_args(conn, "create_network_xml")
expect_invalid_arg_type(conn, "create_network_xml", nil)
expect_invalid_arg_type(conn, "create_network_xml", 1)
expect_fail(conn, Libvirt::Error, "invalid xml", "create_network_xml", "hello")

newnet = expect_success(conn, "network XML", "create_network_xml", new_net_xml)

expect_fail(conn, Libvirt::Error, "already existing network", "create_network_xml", new_net_xml)

newnet.destroy

# TESTGROUP: conn.define_network_xml
expect_too_many_args(conn, "define_network_xml", 1, 2)
expect_too_few_args(conn, "define_network_xml")
expect_invalid_arg_type(conn, "define_network_xml", 1)
expect_invalid_arg_type(conn, "define_network_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_network_xml", "hello")

newnet = expect_success(conn, "network XML", "define_network_xml", new_net_xml)
newnet.undefine

# TESTGROUP: net.undefine
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "undefine", 1)

expect_success(newnet, "no args", "undefine")

# TESTGROUP: net.create
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "create", 1)

expect_success(newnet, "no args", "create")

expect_fail(newnet, Libvirt::Error, "on already running network", "create")

newnet.destroy
newnet.undefine

# TESTGROUP: net.destroy
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "destroy", 1)

expect_success(newnet, "no args", "destroy")

# TESTGROUP: net.name
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "name", 1)

expect_success(newnet, "no args", "name") {|x| x == "ruby-libvirt-tester"}

newnet.destroy

# TESTGROUP: net.uuid
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "uuid", 1)

expect_success(newnet, "no args", "uuid") {|x| x == UUID}

newnet.destroy

# TESTGROUP: net.xml_desc
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "xml_desc", 1, 2)
expect_invalid_arg_type(newnet, "xml_desc", "foo")

expect_success(newnet, "no args", "xml_desc")

newnet.destroy

# TESTGROUP: net.bridge_name
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "bridge_name", 1)

expect_success(newnet, "no args", "bridge_name") {|x| x == "rubybr0"}

newnet.destroy

# TESTGROUP: net.autostart?
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "autostart?", 1)

expect_success(newnet, "no args", "autostart?") {|x| x == false}

newnet.autostart = true

expect_success(newnet, "no args", "autostart?") {|x| x == true}

newnet.undefine

# TESTGROUP: net.autostart=
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "autostart=", 1, 2)
expect_invalid_arg_type(newnet, "autostart=", 'foo')
expect_invalid_arg_type(newnet, "autostart=", nil)
expect_invalid_arg_type(newnet, "autostart=", 1234)

expect_success(newnet, "boolean arg", "autostart=", true)
if not newnet.autostart?
  puts_fail "net.autostart= did not set autostart to true"
else
  puts_ok "net.autostart= set autostart to true"
end

expect_success(newnet, "boolean arg", "autostart=", false)
if newnet.autostart?
  puts_fail "net.autostart= did not set autostart to false"
else
  puts_ok "net.autostart= set autostart to false"
end

newnet.undefine

# TESTGROUP: net.free
newnet = conn.define_network_xml(new_net_xml)
newnet.undefine
expect_too_many_args(newnet, "free", 1)

expect_success(newnet, "no args", "free")

# TESTGROUP: net.active?
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "active?", 1)

expect_success(newnet, "no args", "active?") {|x| x == true}

newnet.destroy

newnet = conn.define_network_xml(new_net_xml)

expect_success(newnet, "no args", "active?") {|x| x == false}

newnet.create

expect_success(newnet, "no args", "active?") {|x| x == true}

newnet.destroy
newnet.undefine

# TESTGROUP: net.persistent?
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "persistent?", 1)

expect_success(newnet, "no args", "persistent?") {|x| x == false}

newnet.destroy

newnet = conn.define_network_xml(new_net_xml)

expect_success(newnet, "no args", "persistent?") {|x| x == true}

newnet.undefine


conn.close

finish_tests
