#!/usr/bin/ruby

# Test the domain methods the bindings support.  Note that this tester requires
# the qemu driver to be enabled and available for use.

# Note that the order of the TESTGROUPs below match the order that the
# functions are defined in the ext/libvirt/domain.c file

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

GUEST_DISK = '/var/lib/libvirt/images/ruby-libvirt-tester.qcow2'
UUID = "93a5c045-6457-2c09-e56f-927cdf34e17a"

conn = Libvirt::open("qemu:///system")

# initial cleanup for previous runs
begin
  olddom = conn.lookup_domain_by_name("ruby-libvirt-tester")
  olddom.destroy
  olddom.undefine
rescue
  # in case we didn't find it, don't do anything
end

# XML data for later tests
new_dom_xml = <<EOF
<domain type='kvm'>
  <name>ruby-libvirt-tester</name>
  <uuid>#{UUID}</uuid>
  <memory>1048576</memory>
  <currentMemory>1048576</currentMemory>
  <vcpu>2</vcpu>
  <os>
    <type arch='x86_64'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <pae/>
  </features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>restart</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='#{GUEST_DISK}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:00:60:3c:95'/>
      <source bridge='virbr0'/>
      <model type='virtio'/>
      <target dev='rl556'/>
    </interface>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'>
      <target port='0'/>
    </console>
    <input type='mouse' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' keymap='en-us'/>
    <video>
      <model type='cirrus' vram='9216' heads='1'/>
    </video>
  </devices>
</domain>
EOF

# qemu command-line that roughly corresponds to the above XML
qemu_cmd_line = "/usr/bin/qemu-kvm -S -M pc-0.13 -enable-kvm -m 1024 -smp 1,sockets=1,cores=1,threads=1 -name ruby-libvirt-tester -uuid #{UUID} -nodefconfig -nodefaults -chardev socket,id=monitor,path=/var/lib/libvirt/qemu/ruby-libvirt-tester.monitor,server,nowait -mon chardev=monitor,mode=readline -rtc base=utc -boot c -chardev pty,id=serial0 -device isa-serial,chardev=serial0 -usb -vnc 127.0.0.1:0 -k en-us -vga cirrus -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5"

# setup for later tests
`rm -f #{GUEST_DISK} ; qemu-img create -f qcow2 #{GUEST_DISK} 5G`
`rm -f /var/lib/libvirt/images/ruby-libvirt-test.save`

new_hostdev_xml = <<EOF
<hostdev mode='subsystem' type='pci' managed='yes'>
  <source>
    <address bus='0x45' slot='0x55' function='0x33'/>
  </source>
</hostdev>
EOF

# start tests

# TESTGROUP: conn.num_of_domains
expect_too_many_args(conn, "num_of_domains", 1)
expect_success(conn, "no args", "num_of_domains")

# TESTGROUP: conn.list_domains
expect_too_many_args(conn, "list_domains", 1)
expect_success(conn, "no args", "list_domains")

# TESTGROUP: conn.num_of_defined_domains
expect_too_many_args(conn, "num_of_defined_domains", 1)
expect_success(conn, "no args", "num_of_defined_domains")

# TESTGROUP: conn.list_domains
expect_too_many_args(conn, "list_defined_domains", 1)
expect_success(conn, "no args", "list_defined_domains")

# TESTGROUP: conn.create_domain_linux
expect_too_many_args(conn, "create_domain_linux", new_dom_xml, 0, 1)
expect_too_few_args(conn, "create_domain_linux")
expect_invalid_arg_type(conn, "create_domain_linux", nil)
expect_invalid_arg_type(conn, "create_domain_linux", 1)
expect_invalid_arg_type(conn, "create_domain_linux", new_dom_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "create_domain_linux", "hello")
newdom = expect_success(conn, "domain xml", "create_domain_linux", new_dom_xml) {|x| x.class == Libvirt::Domain}
sleep 1

expect_fail(conn, Libvirt::Error, "already existing domain", "create_domain_linux", new_dom_xml)

newdom.destroy

# TESTGROUP: conn.create_domain_xml
expect_too_many_args(conn, "create_domain_xml", new_dom_xml, 0, 1)
expect_too_few_args(conn, "create_domain_xml")
expect_invalid_arg_type(conn, "create_domain_xml", nil)
expect_invalid_arg_type(conn, "create_domain_xml", 1)
expect_invalid_arg_type(conn, "create_domain_xml", new_dom_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "create_domain_xml", "hello")
newdom = expect_success(conn, "domain xml", "create_domain_xml", new_dom_xml) {|x| x.class == Libvirt::Domain}
sleep 1

expect_fail(conn, Libvirt::Error, "already existing domain", "create_domain_xml", new_dom_xml)

newdom.destroy

# TESTGROUP: conn.lookup_domain_by_name
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(conn, "lookup_domain_by_name", 1, 2)
expect_too_few_args(conn, "lookup_domain_by_name")
expect_invalid_arg_type(conn, "lookup_domain_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_domain_by_name", "foobarbazsucker")

expect_success(conn, "name arg for running domain", "lookup_domain_by_name", "ruby-libvirt-tester") {|x| x.name == "ruby-libvirt-tester"}
newdom.destroy

newdom = conn.define_domain_xml(new_dom_xml)
expect_success(conn, "name arg for defined domain", "lookup_domain_by_name", "ruby-libvirt-tester") {|x| x.name == "ruby-libvirt-tester"}
newdom.undefine

# TESTGROUP: conn.lookup_domain_by_id
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(conn, "lookup_domain_by_id", 1, 2)
expect_too_few_args(conn, "lookup_domain_by_id")
expect_invalid_arg_type(conn, "lookup_domain_by_id", "foo")
expect_fail(conn, Libvirt::Error, "with negative value", "lookup_domain_by_id", -1)

expect_success(conn, "id arg for running domain", "lookup_domain_by_id", newdom.id)
newdom.destroy

# TESTGROUP: conn.lookup_domain_by_uuid
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(conn, "lookup_domain_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_domain_by_uuid")
expect_invalid_arg_type(conn, "lookup_domain_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "invalid UUID", "lookup_domain_by_uuid", "abcd")

expect_success(conn, "UUID arg for running domain", "lookup_domain_by_uuid", newdom.uuid) {|x| x.uuid == UUID}
newdom.destroy

newdom = conn.define_domain_xml(new_dom_xml)
expect_success(conn, "UUID arg for defined domain", "lookup_domain_by_uuid", newdom.uuid) {|x| x.uuid == UUID}
newdom.undefine

# TESTGROUP: conn.define_domain_xml
expect_too_many_args(conn, "define_domain_xml", 1, 2)
expect_too_few_args(conn, "define_domain_xml")
expect_invalid_arg_type(conn, "define_domain_xml", 1)
expect_invalid_arg_type(conn, "define_domain_xml", nil)
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_domain_xml", "hello")

newdom = expect_success(conn, "domain xml arg", "define_domain_xml", new_dom_xml)
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

expect_success(conn, "qemu-argv and qemu_cmd_line", "domain_xml_from_native", "qemu-argv", qemu_cmd_line)

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

expect_success(conn, "qemu-argv and domain XML", "domain_xml_to_native", "qemu-argv", new_dom_xml)

# TESTGROUP: dom.migrate
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

dconn = Libvirt::open("qemu:///system")

expect_too_many_args(newdom, "migrate", 1, 2, 3, 4, 5, 6)
expect_too_few_args(newdom, "migrate")
expect_fail(newdom, ArgumentError, "invalid connection object", "migrate", "foo")
expect_invalid_arg_type(newdom, "migrate", dconn, 'foo')
expect_invalid_arg_type(newdom, "migrate", dconn, 0, 1)
expect_invalid_arg_type(newdom, "migrate", dconn, 0, 'foo', 1)
expect_invalid_arg_type(newdom, "migrate", dconn, 0, 'foo', 'bar', 'baz')

# FIXME: how can we make this work?
#expect_success(newdom, "conn arg", "migrate", dconn)

dconn.close

newdom.destroy

# TESTGROUP: dom.migrate_to_uri
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "migrate_to_uri", 1, 2, 3, 4, 5)
expect_too_few_args(newdom, "migrate_to_uri")
expect_invalid_arg_type(newdom, "migrate_to_uri", 1)
expect_invalid_arg_type(newdom, "migrate_to_uri", "qemu:///system", 'foo')
expect_invalid_arg_type(newdom, "migrate_to_uri", "qemu:///system", 0, 1)
expect_invalid_arg_type(newdom, "migrate_to_uri", "qemu:///system", 0, 'foo', 'bar')

#expect_success(newdom, "URI arg", "migrate_to_uri", "qemu://remote/system")

dconn.close

newdom.destroy

# TESTGROUP: dom.migrate_set_max_downtime
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "migrate_set_max_downtime", 1, 2, 3)
expect_too_few_args(newdom, "migrate_set_max_downtime")
expect_invalid_arg_type(newdom, "migrate_set_max_downtime", 'foo')
expect_invalid_arg_type(newdom, "migrate_set_max_downtime", 10, 'foo')
expect_fail(newdom, Libvirt::Error, "on off domain", "migrate_set_max_downtime", 10)

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1
expect_fail(newdom, Libvirt::Error, "while no migration in progress", "migrate_set_max_downtime", 10)

#newdom.migrate_to_uri("qemu://remote/system")
#expect_success(newdom, "10 second downtime", "migrate_set_max_downtime", 10)

newdom.destroy

# TESTGROUP: dom.shutdown
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "shutdown", 1)
expect_success(newdom, "no args", "shutdown")
sleep 1
newdom.destroy

# TESTGROUP: dom.reboot
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1
expect_too_many_args(newdom, "reboot", 1, 2)
expect_invalid_arg_type(newdom, "reboot", "hello")

# Qemu driver doesn't currently support reboot, so this is going to fail
begin
  newdom.reboot
  puts_ok "dom.reboot succeeded"
rescue Libvirt::Error => e
  puts_skipped "dom.reboot not supported, skipped"
end

sleep 1
newdom.destroy

# TESTGROUP: dom.destroy
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "destroy", 1)
expect_success(newdom, "no args", "destroy")

# TESTGROUP: dom.suspend
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "suspend", 1)
expect_success(newdom, "no args", "suspend")
newdom.destroy

# TESTGROUP: dom.resume
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_success(newdom, "no args running domain", "resume")

newdom.suspend
expect_too_many_args(newdom, "resume", 1)
expect_success(newdom, "no args suspended domain", "resume")
newdom.destroy

# TESTGROUP: dom.save
newdom = conn.define_domain_xml(new_dom_xml)
newdom.create
sleep 1

expect_too_many_args(newdom, "save", 1, 2)
expect_too_few_args(newdom, "save")
expect_invalid_arg_type(newdom, "save", 1)
expect_invalid_arg_type(newdom, "save", nil)
expect_fail(newdom, Libvirt::Error, "non-existent path", "save", "/this/path/does/not/exist")

expect_success(newdom, "path arg", "save", "/var/lib/libvirt/images/ruby-libvirt-test.save")

`rm -f /var/lib/libvirt/images/ruby-libvirt-test.save`
newdom.undefine

# TESTGROUP: dom.managed_save
newdom = conn.define_domain_xml(new_dom_xml)
newdom.create
sleep 1

expect_too_many_args(newdom, "managed_save", 1, 2)
expect_invalid_arg_type(newdom, "managed_save", "hello")
expect_success(newdom, "no args", "managed_save")
newdom.undefine

# TESTGROUP: dom.has_managed_save?
newdom = conn.define_domain_xml(new_dom_xml)
newdom.create
sleep 1

expect_too_many_args(newdom, "has_managed_save?", 1, 2)
expect_invalid_arg_type(newdom, "has_managed_save?", "hello")

if newdom.has_managed_save?
  puts_fail "dom.has_managed_save? reports true on a new domain"
else
  puts_ok "dom.has_managed_save? not true on new domain"
end

newdom.managed_save

if not newdom.has_managed_save?
  puts_fail "dom.has_managed_save? reports false after a managed save"
else
  puts_ok "dom.has_managed_save? reports true after a managed save"
end

newdom.undefine

# TESTGROUP: dom.managed_save_remove
newdom = conn.define_domain_xml(new_dom_xml)
newdom.create
sleep 1
newdom.managed_save

expect_too_many_args(newdom, "managed_save_remove", 1, 2)
expect_invalid_arg_type(newdom, "managed_save_remove", "hello")

if not newdom.has_managed_save?
  puts_fail "prior to dom.managed_save_remove, no managed save file"
end
expect_success(newdom, "no args", "managed_save_remove")
if newdom.has_managed_save?
  puts_fail "after dom.managed_save_remove, managed save file still exists"
else
  puts_ok "after dom.managed_save_remove, managed save file no longer exists"
end

newdom.undefine

# TESTGROUP: dom.core_dump
newdom = conn.define_domain_xml(new_dom_xml)
newdom.create
sleep 1

expect_too_many_args(newdom, "core_dump", 1, 2, 3)
expect_too_few_args(newdom, "core_dump")
expect_invalid_arg_type(newdom, "core_dump", 1, 2)
expect_invalid_arg_type(newdom, "core_dump", "/path", "foo")
expect_fail(newdom, Libvirt::Error, "invalid path", "core_dump", "/this/path/does/not/exist")

expect_success(newdom, "live with path arg", "core_dump", "/var/lib/libvirt/images/ruby-libvirt-test.core")

`rm -f /var/lib/libvirt/images/ruby-libvirt-test.core`

expect_success(newdom, "crash with path arg", "core_dump", "/var/lib/libvirt/images/ruby-libvirt-test.core", Libvirt::Domain::DUMP_CRASH)

expect_fail(newdom, Libvirt::Error, "of shut-off domain", "core_dump", "/var/lib/libvirt/images/ruby-libvirt-test.core", Libvirt::Domain::DUMP_CRASH)

`rm -f /var/lib/libvirt/images/ruby-libvirt-test.core`

newdom.undefine

# TESTGROUP: Libvirt::Domain::restore
newdom = conn.define_domain_xml(new_dom_xml)
newdom.create
sleep 1
newdom.save("/var/lib/libvirt/images/ruby-libvirt-test.save")

expect_too_many_args(Libvirt::Domain, "restore", 1, 2, 3)
expect_too_few_args(Libvirt::Domain, "restore")
expect_invalid_arg_type(Libvirt::Domain, "restore", 1, 2)
expect_invalid_arg_type(Libvirt::Domain, "restore", conn, 2)
expect_fail(Libvirt::Domain, Libvirt::Error, "invalid path", "restore", conn, "/this/path/does/not/exist")
`touch /tmp/foo`
expect_fail(Libvirt::Domain, Libvirt::Error, "invalid save file", "restore", conn, "/tmp/foo")
`rm -f /tmp/foo`

expect_success(Libvirt::Domain, "2 args", "restore", conn, "/var/lib/libvirt/images/ruby-libvirt-test.save")

`rm -f /var/lib/libvirt/images/ruby-libvirt-test.save`

newdom.destroy
newdom.undefine

# TESTGROUP: dom.info
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "info", 1)

expect_success(newdom, "no args", "info") {|x| x.state == Libvirt::Domain::RUNNING and x.max_mem == 1048576 and x.memory == 1048576 and x.nr_virt_cpu == 2}

newdom.destroy

# TESTGROUP: dom.security_label
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "security_label", 1)

expect_success(newdom, "no args", "security_label")

newdom.destroy

# TESTGROUP: dom.block_stats
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "block_stats", 1, 2)
expect_too_few_args(newdom, "block_stats")
expect_invalid_arg_type(newdom, "block_stats", 1)
expect_fail(newdom, Libvirt::RetrieveError, "invalid path", "block_stats", "foo")

expect_success(newdom, "block device arg", "block_stats", "vda")

newdom.destroy

# TESTGROUP: dom.memory_stats
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "memory_stats", 1, 2)
expect_invalid_arg_type(newdom, "memory_stats", "foo")

expect_success(newdom, "no args", "memory_stats")

newdom.destroy

# TESTGROUP: dom.blockinfo
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "blockinfo", 1, 2, 3)
expect_too_few_args(newdom, "blockinfo")
expect_invalid_arg_type(newdom, "blockinfo", 1)
expect_invalid_arg_type(newdom, "blockinfo", "foo", "bar")
expect_fail(newdom, Libvirt::RetrieveError, "invalid path", "blockinfo", "foo")

expect_success(newdom, "path arg", "blockinfo", GUEST_DISK)

newdom.destroy

# TESTGROUP: dom.block_peek
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "block_peek", 1, 2, 3, 4, 5)
expect_too_few_args(newdom, "block_peek")
expect_too_few_args(newdom, "block_peek", 1)
expect_too_few_args(newdom, "block_peek", 1, 2)
expect_invalid_arg_type(newdom, "block_peek", 1, 2, 3)
expect_invalid_arg_type(newdom, "block_peek", "foo", "bar", 3)
expect_invalid_arg_type(newdom, "block_peek", "foo", 0, "bar")
expect_invalid_arg_type(newdom, "block_peek", "foo", 0, 512, "baz")
expect_fail(newdom, Libvirt::RetrieveError, "invalid path", "block_peek", "foo", 0, 512)

blockpeek = newdom.block_peek(GUEST_DISK, 0, 512)

# 51 46 49 fb are the first 4 bytes of a qcow2 image
if blockpeek[0] != 0x51 or blockpeek[1] != 0x46 or blockpeek[2] != 0x49 or
    blockpeek[3] != 0xfb
  puts_fail "dom.block_peek read did not return valid data"
else
  puts_ok "dom.block_peek read valid data"
end

newdom.destroy

# TESTGROUP: dom.memory_peek
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "memory_peek", 1, 2, 3, 4)
expect_too_few_args(newdom, "memory_peek")
expect_too_few_args(newdom, "memory_peek", 1)
expect_invalid_arg_type(newdom, "memory_peek", "foo", 2)
expect_invalid_arg_type(newdom, "memory_peek", 0, "bar")
expect_invalid_arg_type(newdom, "memory_peek", 0, 512, "baz")

expect_success(newdom, "offset and size args", "memory_peek", 0, 512)
puts_ok "dom.memory_peek succeeded"

newdom.destroy

# TESTGROUP: dom.get_vcpus
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "get_vcpus", 1)

expect_success(newdom, "no args", "get_vcpus") {|x| x.length == 2}

newdom.destroy

# TESTGROUP: dom.active?
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "active?", 1)

expect_success(newdom, "no args", "active?") {|x| x == true}

newdom.destroy

newdom = conn.define_domain_xml(new_dom_xml)

expect_success(newdom, "no args", "active?") {|x| x == false}

newdom.create
sleep 1

expect_success(newdom, "no args", "active?") {|x| x == true}

newdom.destroy
newdom.undefine

# TESTGROUP: dom.persistent?
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "persistent?", 1)

expect_success(newdom, "no args", "persistent?") {|x| x == false}

newdom.destroy

newdom = conn.define_domain_xml(new_dom_xml)

expect_success(newdom, "no args", "persistent?") {|x| x == true}

newdom.undefine

# TESTGROUP: dom.ifinfo
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "ifinfo", 1, 2)
expect_too_few_args(newdom, "ifinfo")
expect_invalid_arg_type(newdom, "ifinfo", 1)
expect_fail(newdom, Libvirt::RetrieveError, "invalid arg", "ifinfo", "foo")

expect_success(newdom, "interface arg", "ifinfo", "rl556")

newdom.destroy

# TESTGROUP: dom.name
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "name", 1)

expect_success(newdom, "no args", "name") {|x| x == "ruby-libvirt-tester"}

newdom.destroy

# TESTGROUP: dom.id
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "id", 1)

expect_success(newdom, "no args", "id")

newdom.destroy

# TESTGROUP: dom.uuid
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "uuid", 1)

expect_success(newdom, "no args", "uuid") {|x| x == UUID}

newdom.destroy

# TESTGROUP: dom.os_type
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "os_type", 1)

expect_success(newdom, "no args", "os_type") {|x| x == "hvm"}

newdom.destroy

# TESTGROUP: dom.max_memory
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "max_memory", 1)

expect_success(newdom, "no args", "max_memory") {|x| x == 1048576}

newdom.destroy

# TESTGROUP: dom.max_memory=
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "max_memory=", 1, 2)
expect_too_few_args(newdom, "max_memory=")
expect_invalid_arg_type(newdom, "max_memory=", 'foo')

begin
  newdom.max_memory = 200000
  puts_ok "dom.max_memory= succeded"
rescue NoMethodError
  puts_skipped "dom.max_memory does not exist"
rescue Libvirt::DefinitionError => e
  # dom.max_memory is not supported by Qemu; skip
  puts_skipped "dom.max_memory not supported by connection driver"
end

newdom.undefine

# TESTGROUP: dom.memory=
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "memory=", 1, 2)
expect_too_few_args(newdom, "memory=")
expect_invalid_arg_type(newdom, "memory=", 'foo')

expect_fail(newdom, Libvirt::Error, "shutoff domain", "memory=", 2)

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_success(newdom, "number arg", "memory=", 200000)

newdom.destroy

# TESTGROUP: dom.max_vcpus
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "max_vcpus", 1)

expect_success(newdom, "no args", "max_vcpus")

newdom.destroy

# TESTGROUP: dom.vcpus=
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "vcpus=", 1, 2)
expect_too_few_args(newdom, "vcpus=")
expect_invalid_arg_type(newdom, "vcpus=", 'foo')

expect_fail(newdom, Libvirt::Error, "shutoff domain", "vcpus=", 2)

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

# FIXME: this kills the domain for some reason
#expect_success(newdom, "number arg", "vcpus=", 2)

newdom.destroy

# TESTGROUP: dom.pin_vcpu
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "pin_vcpu", 1, 2, 3)
expect_too_few_args(newdom, "pin_vcpu")
expect_invalid_arg_type(newdom, "pin_vcpu", 'foo', [0])
expect_invalid_arg_type(newdom, "pin_vcpu", 0, 1)

expect_success(newdom, "cpu args", "pin_vcpu", 0, [0])

newdom.destroy

# TESTGROUP: dom.xml_desc
newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_too_many_args(newdom, "xml_desc", 1, 2)
expect_invalid_arg_type(newdom, "xml_desc", "foo")

expect_success(newdom, "no args", "xml_desc")

newdom.destroy

# TESTGROUP: dom.undefine
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "undefine", 1)

expect_success(newdom, "no args", "undefine")

# TESTGROUP: dom.create
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "create", 1, 2)
expect_invalid_arg_type(newdom, "create", "foo")

expect_success(newdom, "no args", "create")

expect_fail(newdom, Libvirt::Error, "on already running domain", "create")

newdom.destroy
newdom.undefine

# TESTGROUP: dom.autostart?
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "autostart?", 1)

expect_success(newdom, "no args", "autostart?") {|x| x == false}

newdom.autostart = true

expect_success(newdom, "no args", "autostart?") {|x| x == true}

newdom.undefine

# TESTGROUP: dom.autostart=
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "autostart=", 1, 2)
expect_invalid_arg_type(newdom, "autostart=", 'foo')
expect_invalid_arg_type(newdom, "autostart=", nil)
expect_invalid_arg_type(newdom, "autostart=", 1234)

expect_success(newdom, "true arg", "autostart=", true)
if not newdom.autostart?
  puts_fail "dom.autostart= did not set autostart to true"
else
  puts_ok "dom.autostart= set autostart to true"
end

expect_success(newdom, "false arg", "autostart=", false)
if newdom.autostart?
  puts_fail "dom.autostart= did not set autostart to false"
else
  puts_ok "dom.autostart= set autostart to false"
end

newdom.undefine

# TESTGROUP: dom.attach_device
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "attach_device", 1, 2, 3)
expect_too_few_args(newdom, "attach_device")
expect_invalid_arg_type(newdom, "attach_device", 1)
expect_invalid_arg_type(newdom, "attach_device", 'foo', 'bar')
expect_fail(newdom, Libvirt::Error, "invalid XML", "attach_device", "hello")
expect_fail(newdom, Libvirt::Error, "shut off domain", "attach_device", new_hostdev_xml)

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

#expect_success(newdom, "hostdev XML", "attach_device", new_hostdev_xml)

newdom.destroy

# TESTGROUP: dom.detach_device
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "detach_device", 1, 2, 3)
expect_too_few_args(newdom, "detach_device")
expect_invalid_arg_type(newdom, "detach_device", 1)
expect_invalid_arg_type(newdom, "detach_device", 'foo', 'bar')
expect_fail(newdom, Libvirt::Error, "invalid XML", "detach_device", "hello")
expect_fail(newdom, Libvirt::Error, "shut off domain", "detach_device", new_hostdev_xml)

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

#expect_success(newdom, "hostdev XML", "detach_device", new_hostdev_xml)

newdom.destroy

# TESTGROUP: dom.update_device
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "update_device", 1, 2, 3)
expect_too_few_args(newdom, "update_device")
expect_invalid_arg_type(newdom, "update_device", 1)
expect_invalid_arg_type(newdom, "update_device", 'foo', 'bar')
expect_fail(newdom, Libvirt::Error, "invalid XML", "update_device", "hello")
expect_fail(newdom, Libvirt::Error, "shut off domain", "update_device", new_hostdev_xml)

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

#expect_success(newdom, "hostdev XML", "update_device", new_hostdev_xml)

newdom.destroy

# TESTGROUP: dom.free
newdom = conn.define_domain_xml(new_dom_xml)
newdom.undefine
expect_too_many_args(newdom, "free", 1)

newdom.free
puts_ok "dom.free succeeded"

# TESTGROUP: dom.snapshot_create_xml
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "snapshot_create_xml", 1, 2, 3)
expect_too_few_args(newdom, "snapshot_create_xml")
expect_invalid_arg_type(newdom, "snapshot_create_xml", 1)
expect_invalid_arg_type(newdom, "snapshot_create_xml", nil)
expect_invalid_arg_type(newdom, "snapshot_create_xml", 'foo', 'bar')

expect_success(newdom, "simple XML arg", "snapshot_create_xml", "<domainsnapshot/>")

snaps = newdom.num_of_snapshots
if snaps != 1
  puts_fail "dom.snapshot_create_xml after one snapshot has #{snaps} snapshots"
else
  puts_ok "dom.snapshot_create_xml after one snapshot has 1 snapshot"
end

newdom.undefine

# TESTGROUP: dom.num_of_snapshots
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "num_of_snapshots", 1, 2)
expect_invalid_arg_type(newdom, "num_of_snapshots", 'foo')

expect_success(newdom, "no args", "num_of_snapshots") {|x| x == 0}

newdom.snapshot_create_xml("<domainsnapshot/>")

expect_success(newdom, "no args", "num_of_snapshots") {|x| x == 1}

newdom.undefine

# TESTGROUP: dom.list_snapshots
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "list_snapshots", 1, 2)
expect_invalid_arg_type(newdom, "list_snapshots", 'foo')

expect_success(newdom, "no args", "list_snapshots") {|x| x.length == 0}

newdom.snapshot_create_xml("<domainsnapshot/>")

expect_success(newdom, "no args", "list_snapshots") {|x| x.length == 1}

newdom.undefine

# TESTGROUP: dom.lookup_snapshot_by_name
newdom = conn.define_domain_xml(new_dom_xml)
newdom.snapshot_create_xml("<domainsnapshot><name>foo</name></domainsnapshot>")

expect_too_many_args(newdom, "lookup_snapshot_by_name", 1, 2, 3)
expect_too_few_args(newdom, "lookup_snapshot_by_name")
expect_invalid_arg_type(newdom, "lookup_snapshot_by_name", 1)
expect_invalid_arg_type(newdom, "lookup_snapshot_by_name", 'foo', 'bar')

expect_success(newdom, "name arg", "lookup_snapshot_by_name", "foo")

newdom.undefine

# TESTGROUP: dom.has_current_snapshot?
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "has_current_snapshot?", 1, 2)
expect_invalid_arg_type(newdom, "has_current_snapshot?", 'foo')

expect_success(newdom, "no args", "has_current_snapshot?") {|x| x == false}

newdom.snapshot_create_xml("<domainsnapshot><name>foo</name></domainsnapshot>")

expect_success(newdom, "no args", "has_current_snapshot?") {|x| x == true}

newdom.undefine

# TESTGROUP: dom.revert_to_snapshot
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "revert_to_snapshot", 1, 2, 3)
expect_too_few_args(newdom, "revert_to_snapshot")
expect_invalid_arg_type(newdom, "revert_to_snapshot", 1)
expect_invalid_arg_type(newdom, "revert_to_snapshot", nil)
expect_invalid_arg_type(newdom, "revert_to_snapshot", 'foo')

snap = newdom.snapshot_create_xml("<domainsnapshot><name>foo</name></domainsnapshot>")
sleep 1

expect_invalid_arg_type(newdom, "revert_to_snapshot", snap, 'foo')

expect_success(newdom, "snapshot arg", "revert_to_snapshot", snap)

newdom.undefine

# TESTGROUP: dom.current_snapshot
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "current_snapshot", 1, 2)
expect_invalid_arg_type(newdom, "current_snapshot", 'foo')
expect_fail(newdom, Libvirt::RetrieveError, "with no snapshots", "current_snapshot")

newdom.snapshot_create_xml("<domainsnapshot><name>foo</name></domainsnapshot>")

expect_success(newdom, "no args", "current_snapshot")

newdom.undefine

# TESTGROUP: snapshot.xml_desc
newdom = conn.define_domain_xml(new_dom_xml)
snap = newdom.snapshot_create_xml("<domainsnapshot/>")

expect_too_many_args(snap, "xml_desc", 1, 2)
expect_invalid_arg_type(snap, "xml_desc", 'foo')

expect_success(newdom, "no args", "xml_desc")

newdom.undefine

# TESTGROUP: snapshot.delete
newdom = conn.define_domain_xml(new_dom_xml)
snap = newdom.snapshot_create_xml("<domainsnapshot/>")

expect_too_many_args(snap, "delete", 1, 2)
expect_invalid_arg_type(snap, "delete", 'foo')

expect_success(snap, "no args", "delete")

newdom.undefine

# TESTGROUP: snapshot.free
newdom = conn.define_domain_xml(new_dom_xml)
newdom.undefine
expect_too_many_args(newdom, "free", 1)

expect_success(newdom, "no args", "free")

# TESTGROUP: dom.job_info
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "job_info", 1)

expect_fail(newdom, Libvirt::RetrieveError, "shutoff domain", "job_info")

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_success(newdom, "no args", "job_info")

newdom.destroy

# TESTGROUP: dom.abort_job
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "abort_job", 1)

expect_fail(newdom, Libvirt::Error, "not running domain", "abort_job")

newdom.undefine

newdom = conn.create_domain_xml(new_dom_xml)
sleep 1

expect_fail(newdom, Libvirt::Error, "no active job", "abort_job")

# FIXME: need to start long running job here
#expect_success(newdom, "no args", "abort_job")

newdom.destroy

# TESTGROUP: dom.scheduler_type
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "scheduler_type", 1)

begin
  newdom.scheduler_type
  puts_ok "dom.scheduler_type succeeded"
rescue NoMethodError
  puts_skipped "dom.scheduler_type does not exist"
rescue Libvirt::RetrieveError
  # this may not be supported (if cgroups aren't configured), so skip it
  puts_skipped "dom.scheduler_type not supported"
end

newdom.undefine

# TESTGROUP: dom.scheduler_parameters
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "scheduler_parameters", 1)

begin
  newdom.scheduler_parameters
  puts_ok "dom.scheduler_parameters succeeded"
rescue NoMethodError
  puts_skipped "dom.scheduler_parameters does not exist"
rescue Libvirt::RetrieveError
  # this may not be supported (if cgroups aren't configured), so skip it
  puts_ok "dom.scheduler_parameters not supported"
end

newdom.undefine

# TESTGROUP: dom.scheduler_parameters=
newdom = conn.define_domain_xml(new_dom_xml)

expect_too_many_args(newdom, "scheduler_parameters=", 1, 2)
expect_too_few_args(newdom, "scheduler_parameters=")
expect_invalid_arg_type(newdom, "scheduler_parameters=", 0)

# FIXME: set scheduler_parameters here

newdom.undefine

conn.close

finish_tests
