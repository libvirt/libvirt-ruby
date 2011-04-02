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

# TESTGROUP: net.undefine
newnet = conn.define_network_xml($new_net_xml)

expect_too_many_args(newnet, "undefine", 1)

expect_success(newnet, "no args", "undefine")

# TESTGROUP: net.create
newnet = conn.define_network_xml($new_net_xml)

expect_too_many_args(newnet, "create", 1)

expect_success(newnet, "no args", "create")

expect_fail(newnet, Libvirt::Error, "on already running network", "create")

newnet.destroy
newnet.undefine

# TESTGROUP: net.destroy
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "destroy", 1)

expect_success(newnet, "no args", "destroy")

# TESTGROUP: net.name
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "name", 1)

expect_success(newnet, "no args", "name") {|x| x == "ruby-libvirt-tester"}

newnet.destroy

# TESTGROUP: net.uuid
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "uuid", 1)

expect_success(newnet, "no args", "uuid") {|x| x == $NETWORK_UUID}

newnet.destroy

# TESTGROUP: net.xml_desc
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "xml_desc", 1, 2)
expect_invalid_arg_type(newnet, "xml_desc", "foo")

expect_success(newnet, "no args", "xml_desc")

newnet.destroy

# TESTGROUP: net.bridge_name
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "bridge_name", 1)

expect_success(newnet, "no args", "bridge_name") {|x| x == "rubybr0"}

newnet.destroy

# TESTGROUP: net.autostart?
newnet = conn.define_network_xml($new_net_xml)

expect_too_many_args(newnet, "autostart?", 1)

expect_success(newnet, "no args", "autostart?") {|x| x == false}

newnet.autostart = true

expect_success(newnet, "no args", "autostart?") {|x| x == true}

newnet.undefine

# TESTGROUP: net.autostart=
newnet = conn.define_network_xml($new_net_xml)

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
newnet = conn.define_network_xml($new_net_xml)
newnet.undefine
expect_too_many_args(newnet, "free", 1)

expect_success(newnet, "no args", "free")

# TESTGROUP: net.active?
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "active?", 1)

expect_success(newnet, "no args", "active?") {|x| x == true}

newnet.destroy

newnet = conn.define_network_xml($new_net_xml)

expect_success(newnet, "no args", "active?") {|x| x == false}

newnet.create

expect_success(newnet, "no args", "active?") {|x| x == true}

newnet.destroy
newnet.undefine

# TESTGROUP: net.persistent?
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(newnet, "persistent?", 1)

expect_success(newnet, "no args", "persistent?") {|x| x == false}

newnet.destroy

newnet = conn.define_network_xml($new_net_xml)

expect_success(newnet, "no args", "persistent?") {|x| x == true}

newnet.undefine


conn.close

finish_tests
