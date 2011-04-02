#!/usr/bin/ruby

# Test the conn methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

# test setup
begin
  `rm -f /etc/sysconfig/network-scripts/ifcfg-ruby-libvirt-tester`
  `brctl delbr ruby-libvirt-tester >& /dev/null`
rescue
end
`rm -f #{$GUEST_DISK} ; qemu-img create -f qcow2 #{$GUEST_DISK} 5G`
`rm -f /var/lib/libvirt/images/ruby-libvirt-test.save`
`rm -rf #{$POOL_PATH}; mkdir #{$POOL_PATH} ; echo $?`

conn = Libvirt::open("qemu:///system")

cpu_xml = <<EOF
<cpu>
  <arch>x86_64</arch>
  <model>athlon</model>
</cpu>
EOF

# TESTGROUP: conn.close
conn2 = Libvirt::open("qemu:///system")
expect_too_many_args(conn2, "close", 1)
expect_success(conn2, "no args", "close")

# TESTGROUP: conn.closed?
conn2 = Libvirt::open("qemu:///system")

expect_too_many_args(conn2, "closed?", 1)
expect_success(conn2, "no args", "closed?") {|x| x == false }
conn2.close
expect_success(conn2, "no args", "closed?") {|x| x == true }

# TESTGROUP: conn.type
expect_too_many_args(conn, "type", 1)

expect_success(conn, "no args", "type") {|x| x == "QEMU"}

# TESTGROUP: conn.version
expect_too_many_args(conn, "version", 1)

expect_success(conn, "no args", "version")

# TESTGROUP: conn.libversion
expect_too_many_args(conn, "libversion", 1)

expect_success(conn, "no args", "libversion")

# TESTGROUP: conn.hostname
expect_too_many_args(conn, "hostname", 1)

expect_success(conn, "no args", "hostname")

# TESTGROUP: conn.uri
expect_too_many_args(conn, "uri", 1)

expect_success(conn, "no args", "uri") {|x| x == "qemu:///system" }

# TESTGROUP: conn.max_vcpus
expect_too_many_args(conn, "max_vcpus", 'kvm', 1)
expect_fail(conn, Libvirt::RetrieveError, "invalid arg", "max_vcpus", "foo")

expect_success(conn, "no args", "max_vcpus")
expect_success(conn, "nil arg", "max_vcpus")
expect_success(conn, "kvm arg", "max_vcpus")
expect_success(conn, "qemu arg", "max_vcpus")

# TESTGROUP: conn.node_get_info
expect_too_many_args(conn, "node_get_info", 1)

expect_success(conn, "no args", "node_get_info")

begin
  # TESTGROUP: conn.node_free_memory
  expect_too_many_args(conn, "node_free_memory", 1)

  conn.node_free_memory
  puts_ok "conn.node_free_memory no args"
rescue Libvirt::RetrieveError
  puts_skipped "conn.node_free_memory not supported on this host"
rescue NoMethodError
  puts_skipped "conn.node_free_memory does not exist"
end

begin
  # TESTGROUP: conn.node_cells_free_memory
  expect_too_many_args(conn, "node_cells_free_memory", 1, 2, 3)
  expect_invalid_arg_type(conn, "node_cells_free_memory", 'start')
  expect_invalid_arg_type(conn, "node_cells_free_memory", 0, 'end')

  cell_mem = conn.node_cells_free_memory
  puts_ok "conn.node_cells_free_memory no args = "
  cell_mem = conn.node_cells_free_memory(0)
  puts_ok "conn.node_cells_free_memory(0) = "
  cell_mem = conn.node_cells_free_memory(0, 1)
  puts_ok "conn.node_cells_free_memory(0, 1) = "
rescue Libvirt::RetrieveError
  puts_skipped "conn.node_cells_free_memory not supported on this host"
rescue NoMethodError
  puts_skipped "conn.node_cells_free_memory does not exist"
end

# TESTGROUP: conn.node_get_security_model
expect_too_many_args(conn, "node_get_security_model", 1)
expect_success(conn, "no args", "node_get_security_model")

# TESTGROUP: conn.encrypted?
expect_too_many_args(conn, "encrypted?", 1)
expect_success(conn, "no args", "encrypted?")

# TESTGROUP: conn.secure?
expect_too_many_args(conn, "secure?", 1)
expect_success(conn, "no args", "secure?") {|x| x == true}

# TESTGROUP: conn.capabilities
expect_too_many_args(conn, "capabilities", 1)
expect_success(conn, "no args", "capabilities")

# TESTGROUP: conn.compare_cpu
expect_too_many_args(conn, "compare_cpu", 1, 2, 3)
expect_too_few_args(conn, "compare_cpu")
expect_invalid_arg_type(conn, "compare_cpu", 1)
expect_invalid_arg_type(conn, "compare_cpu", "hello", 'bar')
expect_fail(conn, Libvirt::RetrieveError, "invalid XML", "compare_cpu", "hello")
expect_success(conn, "CPU XML", "compare_cpu", cpu_xml)

# TESTGROUP: conn.baseline_cpu
expect_too_many_args(conn, "baseline_cpu", 1, 2, 3)
expect_too_few_args(conn, "baseline_cpu")
expect_invalid_arg_type(conn, "baseline_cpu", 1)
expect_invalid_arg_type(conn, "baseline_cpu", [], "foo")
expect_fail(conn, ArgumentError, "empty array", "baseline_cpu", [])
expect_success(conn, "CPU XML", "baseline_cpu", [cpu_xml])

# TESTGROUP: conn.domain_event_register_any
dom_event_callback_proc = lambda {|conn, dom, event, detail, opaque|
}

def dom_event_callback_symbol(conn, dom, event, detail, opaque)
end

expect_too_many_args(conn, "domain_event_register_any", 1, 2, 3, 4, 5)
expect_too_few_args(conn, "domain_event_register_any")
expect_too_few_args(conn, "domain_event_register_any", 1)
expect_invalid_arg_type(conn, "domain_event_register_any", "hello", 1)
expect_invalid_arg_type(conn, "domain_event_register_any", Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, 1)
expect_invalid_arg_type(conn, "domain_event_register_any", Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, dom_event_callback_proc, 1)
expect_fail(conn, ArgumentError, "invalid event ID", "domain_event_register_any", 456789, dom_event_callback_proc)

callbackID = expect_success(conn, "eventID and proc", "domain_event_register_any", Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, dom_event_callback_proc)
conn.domain_event_deregister_any(callbackID)

callbackID = expect_success(conn, "eventID and symbol", "domain_event_register_any", Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, :dom_event_callback_symbol)
conn.domain_event_deregister_any(callbackID)

callbackID = expect_success(conn, "eventID, proc, nil domain", "domain_event_register_any", Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, dom_event_callback_proc, nil)
conn.domain_event_deregister_any(callbackID)

callbackID = expect_success(conn, "eventID, proc, nil domain, opaque", "domain_event_register_any", Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, dom_event_callback_proc, nil, "opaque user data")
conn.domain_event_deregister_any(callbackID)

# TESTGROUP: conn.domain_event_deregister_any
dom_event_callback_proc = lambda {|conn, dom, event, detail, opaque|
}

callbackID = conn.domain_event_register_any(Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE, dom_event_callback_proc)

expect_too_many_args(conn, "domain_event_deregister_any", 1, 2)
expect_too_few_args(conn, "domain_event_deregister_any")
expect_invalid_arg_type(conn, "domain_event_deregister_any", "hello")

expect_success(conn, "callbackID", "domain_event_deregister_any", callbackID)

# TESTGROUP: conn.domain_event_register
dom_event_callback_proc = lambda {|conn, dom, event, detail, opaque|
}

def dom_event_callback_symbol(conn, dom, event, detail, opaque)
end

expect_too_many_args(conn, "domain_event_register", 1, 2, 3)
expect_too_few_args(conn, "domain_event_register")
expect_invalid_arg_type(conn, "domain_event_register", "hello")

expect_success(conn, "proc", "domain_event_register", dom_event_callback_proc)
conn.domain_event_deregister

expect_success(conn, "symbol", "domain_event_register", :dom_event_callback_symbol)
conn.domain_event_deregister

expect_success(conn, "proc and opaque", "domain_event_register", dom_event_callback_proc, "opaque user data")
conn.domain_event_deregister

# TESTGROUP: conn.domain_event_deregister
dom_event_callback_proc = lambda {|conn, dom, event, detail, opaque|
}

conn.domain_event_register(dom_event_callback_proc)

expect_too_many_args(conn, "domain_event_deregister", 1)
expect_success(conn, "no args", "domain_event_deregister")

# TESTGROUP: conn.num_of_domains
expect_too_many_args(conn, "num_of_domains", 1)
expect_success(conn, "no args", "num_of_domains")

# TESTGROUP: conn.list_domains
expect_too_many_args(conn, "list_domains", 1)
expect_success(conn, "no args", "list_domains")

# TESTGROUP: conn.num_of_defined_domains
expect_too_many_args(conn, "num_of_defined_domains", 1)
expect_success(conn, "no args", "num_of_defined_domains")

# TESTGROUP: conn.list_defined_domains
expect_too_many_args(conn, "list_defined_domains", 1)
expect_success(conn, "no args", "list_defined_domains")

# TESTGROUP: conn.create_domain_linux
expect_too_many_args(conn, "create_domain_linux", $new_dom_xml, 0, 1)
expect_too_few_args(conn, "create_domain_linux")
expect_invalid_arg_type(conn, "create_domain_linux", nil)
expect_invalid_arg_type(conn, "create_domain_linux", 1)
expect_invalid_arg_type(conn, "create_domain_linux", $new_dom_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "create_domain_linux", "hello")
newdom = expect_success(conn, "domain xml", "create_domain_linux", $new_dom_xml) {|x| x.class == Libvirt::Domain}
sleep 1

expect_fail(conn, Libvirt::Error, "already existing domain", "create_domain_linux", $new_dom_xml)

newdom.destroy

# TESTGROUP: conn.create_domain_xml
expect_too_many_args(conn, "create_domain_xml", $new_dom_xml, 0, 1)
expect_too_few_args(conn, "create_domain_xml")
expect_invalid_arg_type(conn, "create_domain_xml", nil)
expect_invalid_arg_type(conn, "create_domain_xml", 1)
expect_invalid_arg_type(conn, "create_domain_xml", $new_dom_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "create_domain_xml", "hello")
newdom = expect_success(conn, "domain xml", "create_domain_xml", $new_dom_xml) {|x| x.class == Libvirt::Domain}
sleep 1

expect_fail(conn, Libvirt::Error, "already existing domain", "create_domain_xml", $new_dom_xml)

newdom.destroy

# TESTGROUP: conn.lookup_domain_by_name
newdom = conn.create_domain_xml($new_dom_xml)
sleep 1

expect_too_many_args(conn, "lookup_domain_by_name", 1, 2)
expect_too_few_args(conn, "lookup_domain_by_name")
expect_invalid_arg_type(conn, "lookup_domain_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_domain_by_name", "foobarbazsucker")

expect_success(conn, "name arg for running domain", "lookup_domain_by_name", "ruby-libvirt-tester") {|x| x.name == "ruby-libvirt-tester"}
newdom.destroy

newdom = conn.define_domain_xml($new_dom_xml)
expect_success(conn, "name arg for defined domain", "lookup_domain_by_name", "ruby-libvirt-tester") {|x| x.name == "ruby-libvirt-tester"}
newdom.undefine

# TESTGROUP: conn.lookup_domain_by_id
newdom = conn.create_domain_xml($new_dom_xml)
sleep 1

expect_too_many_args(conn, "lookup_domain_by_id", 1, 2)
expect_too_few_args(conn, "lookup_domain_by_id")
expect_invalid_arg_type(conn, "lookup_domain_by_id", "foo")
expect_fail(conn, Libvirt::Error, "with negative value", "lookup_domain_by_id", -1)

expect_success(conn, "id arg for running domain", "lookup_domain_by_id", newdom.id)
newdom.destroy

# TESTGROUP: conn.lookup_domain_by_uuid
newdom = conn.create_domain_xml($new_dom_xml)
sleep 1

expect_too_many_args(conn, "lookup_domain_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_domain_by_uuid")
expect_invalid_arg_type(conn, "lookup_domain_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "invalid UUID", "lookup_domain_by_uuid", "abcd")

expect_success(conn, "UUID arg for running domain", "lookup_domain_by_uuid", newdom.uuid) {|x| x.uuid == $GUEST_UUID}
newdom.destroy

newdom = conn.define_domain_xml($new_dom_xml)
expect_success(conn, "UUID arg for defined domain", "lookup_domain_by_uuid", newdom.uuid) {|x| x.uuid == $GUEST_UUID}
newdom.undefine

# TESTGROUP: conn.define_domain_xml
expect_too_many_args(conn, "define_domain_xml", 1, 2)
expect_too_few_args(conn, "define_domain_xml")
expect_invalid_arg_type(conn, "define_domain_xml", 1)
expect_invalid_arg_type(conn, "define_domain_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_domain_xml", "hello")

newdom = expect_success(conn, "domain xml arg", "define_domain_xml", $new_dom_xml)
newdom.undefine

# TESTGROUP: conn.domain_xml_from_native
expect_too_many_args(conn, "domain_xml_from_native", 1, 2, 3, 4)
expect_too_few_args(conn, "domain_xml_from_native")
expect_too_few_args(conn, "domain_xml_from_native", 1)
expect_invalid_arg_type(conn, "domain_xml_from_native", 1, 2)
expect_invalid_arg_type(conn, "domain_xml_from_native", nil, 2)
expect_invalid_arg_type(conn, "domain_xml_from_native", "qemu-argv", 2)
expect_invalid_arg_type(conn, "domain_xml_from_native", "qemu-argv", nil)
expect_invalid_arg_type(conn, "domain_xml_from_native", "qemu-argv", "foo", "bar")
expect_fail(conn, Libvirt::Error, "unsupported first arg", "domain_xml_from_native", "foo", "bar")

expect_success(conn, "qemu-argv and qemu_cmd_line", "domain_xml_from_native", "qemu-argv", $qemu_cmd_line)

# TESTGROUP: conn.domain_xml_to_native
expect_too_many_args(conn, "domain_xml_to_native", 1, 2, 3, 4)
expect_too_few_args(conn, "domain_xml_to_native")
expect_too_few_args(conn, "domain_xml_to_native", 1)
expect_invalid_arg_type(conn, "domain_xml_to_native", 1, 2)
expect_invalid_arg_type(conn, "domain_xml_to_native", nil, 2)
expect_invalid_arg_type(conn, "domain_xml_to_native", "qemu-argv", 2)
expect_invalid_arg_type(conn, "domain_xml_to_native", "qemu-argv", nil)
expect_invalid_arg_type(conn, "domain_xml_to_native", "qemu-argv", "foo", "bar")
expect_fail(conn, Libvirt::Error, "unsupported first arg", "domain_xml_to_native", "foo", "bar")

expect_success(conn, "qemu-argv and domain XML", "domain_xml_to_native", "qemu-argv", $new_dom_xml)

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
newiface = conn.define_interface_xml($new_interface_xml)

expect_too_many_args(conn, "lookup_interface_by_name", 1, 2)
expect_too_few_args(conn, "lookup_interface_by_name")
expect_invalid_arg_type(conn, "lookup_interface_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_interface_by_name", "foobarbazsucker")

expect_success(conn, "name arg", "lookup_interface_by_name", "ruby-libvirt-tester")

newiface.destroy

expect_success(conn, "name arg", "lookup_interface_by_name", "ruby-libvirt-tester")

newiface.undefine

# TESTGROUP: conn.lookup_interface_by_mac
newiface = conn.define_interface_xml($new_interface_xml)

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

expect_success(conn, "interface XML", "define_interface_xml", $new_interface_xml)
newiface.undefine

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
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(conn, "lookup_network_by_name", 1, 2)
expect_too_few_args(conn, "lookup_network_by_name")
expect_invalid_arg_type(conn, "lookup_network_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_network_by_name", "foobarbazsucker")

expect_success(conn, "name arg", "lookup_network_by_name", "ruby-libvirt-tester")
newnet.destroy

newnet = conn.define_network_xml($new_net_xml)
expect_success(conn, "name arg", "lookup_network_by_name", "ruby-libvirt-tester")
newnet.undefine

# TESTGROUP: conn.lookup_network_by_uuid
newnet = conn.create_network_xml($new_net_xml)

expect_too_many_args(conn, "lookup_network_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_network_by_uuid")
expect_invalid_arg_type(conn, "lookup_network_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent uuid arg", "lookup_network_by_uuid", "foobarbazsucker")

expect_success(conn, "uuid arg", "lookup_network_by_uuid", $NETWORK_UUID)
newnet.destroy

newnet = conn.define_network_xml($new_net_xml)
expect_success(conn, "uuid arg", "lookup_network_by_uuid", $NETWORK_UUID)
newnet.undefine

# TESTGROUP: conn.create_network_xml
expect_too_many_args(conn, "create_network_xml", $new_net_xml, 0)
expect_too_few_args(conn, "create_network_xml")
expect_invalid_arg_type(conn, "create_network_xml", nil)
expect_invalid_arg_type(conn, "create_network_xml", 1)
expect_fail(conn, Libvirt::Error, "invalid xml", "create_network_xml", "hello")

newnet = expect_success(conn, "network XML", "create_network_xml", $new_net_xml)

expect_fail(conn, Libvirt::Error, "already existing network", "create_network_xml", $new_net_xml)

newnet.destroy

# TESTGROUP: conn.define_network_xml
expect_too_many_args(conn, "define_network_xml", 1, 2)
expect_too_few_args(conn, "define_network_xml")
expect_invalid_arg_type(conn, "define_network_xml", 1)
expect_invalid_arg_type(conn, "define_network_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_network_xml", "hello")

newnet = expect_success(conn, "network XML", "define_network_xml", $new_net_xml)
newnet.undefine

# TESTGROUP: conn.num_of_nodedevices
expect_too_many_args(conn, "num_of_nodedevices", 1, 2, 3)
expect_invalid_arg_type(conn, "num_of_nodedevices", 1)
expect_invalid_arg_type(conn, "num_of_nodedevices", 'foo', 'bar')
expect_success(conn, "no args", "num_of_nodedevices")

# TESTGROUP: conn.list_nodedevices
expect_too_many_args(conn, "list_nodedevices", 1, 2, 3)
expect_invalid_arg_type(conn, "list_nodedevices", 1)
expect_invalid_arg_type(conn, "list_nodedevices", 'foo', 'bar')
expect_success(conn, "no args", "list_nodedevices")

# TESTGROUP: conn.lookup_nodedevice_by_name
testnode = conn.lookup_nodedevice_by_name(conn.list_nodedevices[0])

expect_too_many_args(conn, "lookup_nodedevice_by_name", 1, 2)
expect_too_few_args(conn, "lookup_nodedevice_by_name")
expect_invalid_arg_type(conn, "lookup_nodedevice_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_nodedevice_by_name", "foobarbazsucker")

expect_success(conn, "name arg", "lookup_nodedevice_by_name", testnode.name)

# TESTGROUP: conn.create_nodedevice_xml
expect_too_many_args(conn, "create_nodedevice_xml", 1, 2, 3)
expect_too_few_args(conn, "create_nodedevice_xml")
expect_invalid_arg_type(conn, "create_nodedevice_xml", 1)
expect_invalid_arg_type(conn, "create_nodedevice_xml", "foo", 'bar')
expect_fail(conn, Libvirt::Error, "invalid XML", "create_nodedevice_xml", "hello")

#expect_success(conn, "nodedevice XML", "create_nodedevice_xml", "<nodedevice/>")

# TESTGROUP: conn.num_of_nwfilters
expect_too_many_args(conn, "num_of_nwfilters", 1)
expect_success(conn, "no args", "num_of_nwfilters")

# TESTGROUP: conn.list_nwfilters
expect_too_many_args(conn, "list_nwfilters", 1)
expect_success(conn, "no args", "list_nwfilters")

# TESTGROUP: conn.lookup_nwfilter_by_name
newnw = conn.define_nwfilter_xml($new_nwfilter_xml)

expect_too_many_args(conn, "lookup_nwfilter_by_name", 1, 2)
expect_too_few_args(conn, "lookup_nwfilter_by_name")
expect_invalid_arg_type(conn, "lookup_nwfilter_by_name", 1)

expect_success(conn, "name arg", "lookup_nwfilter_by_name", "ruby-libvirt-tester")

newnw.undefine

# TESTGROUP: conn.lookup_nwfilter_by_uuid
newnw = conn.define_nwfilter_xml($new_nwfilter_xml)

expect_too_many_args(conn, "lookup_nwfilter_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_nwfilter_by_uuid")
expect_invalid_arg_type(conn, "lookup_nwfilter_by_uuid", 1)

expect_success(conn, "uuid arg", "lookup_nwfilter_by_uuid", $NWFILTER_UUID) {|x| x.uuid == $NWFILTER_UUID}

newnw.undefine

# TESTGROUP: conn.define_nwfilter_xml
expect_too_many_args(conn, "define_nwfilter_xml", 1, 2)
expect_too_few_args(conn, "define_nwfilter_xml")
expect_invalid_arg_type(conn, "define_nwfilter_xml", 1)
expect_invalid_arg_type(conn, "define_nwfilter_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_nwfilter_xml", "hello")

newnw = expect_success(conn, "nwfilter XML", "define_nwfilter_xml", $new_nwfilter_xml)

newnw.undefine

# TESTGROUP: conn.num_of_secrets
expect_too_many_args(conn, "num_of_secrets", 1)
expect_success(conn, "no args", "num_of_secrets")

# TESTGROUP: conn.list_secrets
expect_too_many_args(conn, "list_secrets", 1)
expect_success(conn, "no args", "list_secrets")

# TESTGROUP: conn.lookup_secret_by_uuid
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(conn, "lookup_secret_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_secret_by_uuid")
expect_invalid_arg_type(conn, "lookup_secret_by_uuid", 1)

expect_success(conn, "uuid arg", "lookup_secret_by_uuid", $SECRET_UUID) {|x| x.uuid == $SECRET_UUID}

newsecret.undefine

# TESTGROUP: conn.lookup_secret_by_usage
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(conn, "lookup_secret_by_usage", 1, 2, 3)
expect_too_few_args(conn, "lookup_secret_by_usage")
expect_invalid_arg_type(conn, "lookup_secret_by_usage", 'foo', 1)
expect_invalid_arg_type(conn, "lookup_secret_by_usage", 1, 2)
expect_fail(conn, Libvirt::RetrieveError, "invalid secret", "lookup_secret_by_usage", Libvirt::Secret::USAGE_TYPE_VOLUME, "foo")

expect_success(conn, "usage type and key", "lookup_secret_by_usage", Libvirt::Secret::USAGE_TYPE_VOLUME, "/var/lib/libvirt/images/mail.img")

newsecret.undefine

# TESTGROUP: conn.define_secret_xml
expect_too_many_args(conn, "define_secret_xml", 1, 2, 3)
expect_too_few_args(conn, "define_secret_xml")
expect_invalid_arg_type(conn, "define_secret_xml", 1)
expect_invalid_arg_type(conn, "define_secret_xml", nil)
expect_invalid_arg_type(conn, "define_secret_xml", "hello", 'foo')
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_secret_xml", "hello")

expect_success(conn, "secret XML", "define_secret_xml", $new_secret_xml)

newsecret.undefine

# TESTGROUP: conn.list_storage_pools
expect_too_many_args(conn, "list_storage_pools", 1)
expect_success(conn, "no args", "list_storage_pools")

# TESTGROUP: conn.num_of_storage_pools
expect_too_many_args(conn, "num_of_storage_pools", 1)
expect_success(conn, "no args", "num_of_storage_pools")

# TESTGROUP: conn.list_defined_storage_pools
expect_too_many_args(conn, "list_defined_storage_pools", 1)
expect_success(conn, "no args", "list_defined_storage_pools")

# TESTGROUP: conn.num_of_defined_storage_pools
expect_too_many_args(conn, "num_of_defined_storage_pools", 1)
expect_success(conn, "no args", "num_of_defined_storage_pools")

# TESTGROUP: conn.lookup_storage_pool_by_name
newpool = conn.create_storage_pool_xml($new_storage_pool_xml)

expect_too_many_args(conn, "lookup_storage_pool_by_name", 1, 2)
expect_too_few_args(conn, "lookup_storage_pool_by_name")
expect_invalid_arg_type(conn, "lookup_storage_pool_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_storage_pool_by_name", "foobarbazsucker")

expect_success(conn, "name arg", "lookup_storage_pool_by_name", "ruby-libvirt-tester")

newpool.destroy

newpool = conn.define_storage_pool_xml($new_storage_pool_xml)
expect_success(conn, "name arg", "lookup_storage_pool_by_name", "ruby-libvirt-tester")
newpool.undefine

# TESTGROUP: conn.lookup_storage_pool_by_uuid
newpool = conn.create_storage_pool_xml($new_storage_pool_xml)

expect_too_many_args(conn, "lookup_storage_pool_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_storage_pool_by_uuid")
expect_invalid_arg_type(conn, "lookup_storage_pool_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent uuid arg", "lookup_storage_pool_by_uuid", "foobarbazsucker")

expect_success(conn, "uuid arg", "lookup_storage_pool_by_uuid", $POOL_UUID)

newpool.destroy

newpool = conn.define_storage_pool_xml($new_storage_pool_xml)

expect_success(conn, "uuid arg", "lookup_storage_pool_by_uuid", $POOL_UUID)

newpool.undefine

# TESTGROUP: conn.create_storage_pool_xml
expect_too_many_args(conn, "create_storage_pool_xml", $new_storage_pool_xml, 0, 1)
expect_too_few_args(conn, "create_storage_pool_xml")
expect_invalid_arg_type(conn, "create_storage_pool_xml", nil)
expect_invalid_arg_type(conn, "create_storage_pool_xml", 1)
expect_invalid_arg_type(conn, "create_storage_pool_xml", $new_storage_pool_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "create_storage_pool_xml", "hello")

expect_success(conn, "storage pool XML", "create_storage_pool_xml", $new_storage_pool_xml)

expect_fail(conn, Libvirt::Error, "already existing domain", "create_storage_pool_xml", $new_storage_pool_xml)

newpool.destroy

# TESTGROUP: conn.define_storage_pool_xml
expect_too_many_args(conn, "define_storage_pool_xml", $new_storage_pool_xml, 0, 1)
expect_too_few_args(conn, "define_storage_pool_xml")
expect_invalid_arg_type(conn, "define_storage_pool_xml", nil)
expect_invalid_arg_type(conn, "define_storage_pool_xml", 1)
expect_invalid_arg_type(conn, "define_storage_pool_xml", $new_storage_pool_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "define_storage_pool_xml", "hello")

expect_success(conn, "storage pool XML", "define_storage_pool_xml", $new_storage_pool_xml)

newpool.undefine

# TESTGROUP: conn.discover_storage_pool_sources
expect_too_many_args(conn, "discover_storage_pool_sources", 1, 2, 3, 4)
expect_too_few_args(conn, "discover_storage_pool_sources")
expect_invalid_arg_type(conn, "discover_storage_pool_sources", 1)
expect_invalid_arg_type(conn, "discover_storage_pool_sources", "foo", 1)
expect_invalid_arg_type(conn, "discover_storage_pool_sources", "foo", "bar", "baz")

expect_fail(conn, Libvirt::Error, "invalid pool type", "discover_storage_pool_sources", "foo")

expect_success(conn, "pool type", "discover_storage_pool_sources", "logical")

# TESTGROUP: conn.sys_info
expect_too_many_args(conn, "sys_info", 1, 2)
expect_invalid_arg_type(conn, "sys_info", "foo")

expect_success(conn, "system info", "sys_info")

conn.close

finish_tests
