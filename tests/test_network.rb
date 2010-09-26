#!/usr/bin/ruby

# Test the network methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

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
  <uuid>04068860-d9a2-47c5-bc9d-9e047ae901da</uuid>
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
numnets = conn.num_of_networks
puts_ok "conn.num_of_networks no args = #{numnets}"

# TESTGROUP: conn.list_networks
expect_too_many_args(conn, "list_networks", 1)
netlist = conn.list_networks
puts_ok "conn.list_networks no args = "

# TESTGROUP: conn.num_of_defined_networks
expect_too_many_args(conn, "num_of_defined_networks", 1)
numnets = conn.num_of_defined_networks
puts_ok "conn.num_of_defined_networks no args = #{numnets}"

# TESTGROUP: conn.list_defined_networks
expect_too_many_args(conn, "list_defined_networks", 1)
netlist = conn.list_defined_networks
puts_ok "conn.list_defined_networks no args = "

# TESTGROUP: conn.lookup_network_by_name
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(conn, "lookup_network_by_name", 1, 2)
expect_too_few_args(conn, "lookup_network_by_name")
expect_invalid_arg_type(conn, "lookup_network_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_network_by_name", "foobarbazsucker")

conn.lookup_network_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_network_by_name running network succeeded"
newnet.destroy

newnet = conn.define_network_xml(new_net_xml)
conn.lookup_network_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_network_by_name defined but off network succeeded"
newnet.undefine

# TESTGROUP: conn.lookup_network_by_uuid
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(conn, "lookup_network_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_network_by_uuid")
expect_invalid_arg_type(conn, "lookup_network_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent uuid arg", "lookup_network_by_uuid", "foobarbazsucker")

conn.lookup_network_by_uuid("04068860-d9a2-47c5-bc9d-9e047ae901da")
puts_ok "conn.lookup_network_by_uuid running network succeeded"
newnet.destroy

newnet = conn.define_network_xml(new_net_xml)
conn.lookup_network_by_uuid("04068860-d9a2-47c5-bc9d-9e047ae901da")
puts_ok "conn.lookup_network_by_uuid defined but off network succeeded"
newnet.undefine

# TESTGROUP: conn.create_network_xml
expect_too_many_args(conn, "create_network_xml", new_net_xml, 0)
expect_too_few_args(conn, "create_network_xml")
expect_invalid_arg_type(conn, "create_network_xml", nil)
expect_invalid_arg_type(conn, "create_network_xml", 1)
expect_fail(conn, Libvirt::Error, "invalid xml", "create_network_xml", "hello")

newnet = conn.create_network_xml(new_net_xml)
puts_ok "conn.create_network_xml started new network"

expect_fail(conn, Libvirt::Error, "already existing network", "create_network_xml", new_net_xml)

newnet.destroy

# TESTGROUP: conn.define_network_xml
expect_too_many_args(conn, "define_network_xml", 1, 2)
expect_too_few_args(conn, "define_network_xml")
expect_invalid_arg_type(conn, "define_network_xml", 1)
expect_invalid_arg_type(conn, "define_network_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_network_xml", "hello")

newnet = conn.define_network_xml(new_net_xml)
puts_ok "conn.define_network_xml with valid XML succeeded"
newnet.undefine

# TESTGROUP: net.undefine
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "undefine", 1)

newnet.undefine
puts_ok "net.undefine succeeded"

# TESTGROUP: net.create
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "create", 1)

newnet.create
puts_ok "net.create succeeded"

expect_fail(newnet, Libvirt::Error, "on already running network", "create")

newnet.destroy
newnet.undefine

# TESTGROUP: net.destroy
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "destroy", 1)
newnet.destroy
puts_ok "net.destroy succeeded"

# TESTGROUP: net.name
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "name", 1)
name = newnet.name
if name != "ruby-libvirt-tester"
  puts_fail "net.name expected to be ruby-libvirt-tester, but was #{name}"
else
  puts_ok "net.name succeeded"
end

newnet.destroy

# TESTGROUP: net.uuid
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "uuid", 1)
uuid = newnet.uuid
if uuid != "04068860-d9a2-47c5-bc9d-9e047ae901da"
  puts_fail "net.uuid expected to be 04068860-d9a2-47c5-bc9d-9e047ae901da, but was #{uuid}"
else
  puts_ok "net.uuid succeeded"
end

newnet.destroy

# TESTGROUP: net.xml_desc
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "xml_desc", 1, 2)
expect_invalid_arg_type(newnet, "xml_desc", "foo")

newnet.xml_desc
puts_ok "net.xml_desc succeeded"

newnet.destroy

# TESTGROUP: net.bridge_name
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "bridge_name", 1)
bridge_name = newnet.bridge_name
if bridge_name != "rubybr0"
  puts_fail "net.bridge_name expected to be rubybr0, but was #{bridge_name}"
else
  puts_ok "net.bridge_name succeeded"
end

newnet.destroy

# TESTGROUP: net.autostart?
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "autostart?", 1)

if newnet.autostart?
  puts_fail "net.autostart? on new network is true"
else
  puts_ok "net.autostart? on new network is false"
end

newnet.autostart = true

if not newnet.autostart?
  puts_fail "net.autostart? after setting autostart is false"
else
  puts_ok "net.autostart? after setting autostart is true"
end

newnet.undefine

# TESTGROUP: net.autostart=
newnet = conn.define_network_xml(new_net_xml)

expect_too_many_args(newnet, "autostart=", 1, 2)
expect_invalid_arg_type(newnet, "autostart=", 'foo')
expect_invalid_arg_type(newnet, "autostart=", nil)
expect_invalid_arg_type(newnet, "autostart=", 1234)

newnet.autostart=true
if not newnet.autostart?
  puts_fail "net.autostart= did not set autostart to true"
else
  puts_ok "net.autostart= set autostart to true"
end

newnet.autostart=false

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

newnet.free
puts_ok "network.free succeeded"

# TESTGROUP: net.active?
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "active?", 1)

active = newnet.active?
if not active
  puts_fail "net.active? on running network was false"
else
  puts_ok "net.active? on running network was true"
end

newnet.destroy

newnet = conn.define_network_xml(new_net_xml)

active = newnet.active?
if active
  puts_fail "net.active? on shutoff network was true"
else
  puts_ok "net.active? on shutoff network was false"
end

newnet.create

active = newnet.active?
if not active
  puts_fail "net.active? on running network was false"
else
  puts_ok "net.active? on running network was true"
end

newnet.destroy
newnet.undefine

# TESTGROUP: net.persistent?
newnet = conn.create_network_xml(new_net_xml)

expect_too_many_args(newnet, "persistent?", 1)

per = newnet.persistent?
if per
  puts_fail "net.persistent? on transient network was true"
else
  puts_ok "net.persistent? on transient network was false"
end

newnet.destroy

newnet = conn.define_network_xml(new_net_xml)

per = newnet.persistent?
if not per
  puts_fail "net.persisent? on permanent network was false"
else
  puts_ok "net.persistent? on permanent network was true"
end

newnet.undefine


conn.close

finish_tests
