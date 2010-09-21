#!/usr/bin/ruby

# Test the storage methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

begin
  oldpool = conn.lookup_storage_pool_by_name("ruby-libvirt-tester")
  oldpool.destroy
  oldpool.undefine
rescue
  # in case we didn't find it, don't do anything
end

# test setup
`rm -rf /tmp/ruby-libvirt-tester; mkdir /tmp/ruby-libvirt-tester`

new_storage_pool_xml = <<EOF
<pool type="dir">
  <name>ruby-libvirt-tester</name>
  <uuid>33a5c045-645a-2c00-e56b-927cdf34e17a</uuid>
  <target>
    <path>/tmp/ruby-libvirt-tester</path>
  </target>
</pool>
EOF

new_storage_vol_xml = <<EOF
<volume>
  <name>test.img</name>
  <allocation>0</allocation>
  <capacity unit="G">1</capacity>
  <target>
    <path>/tmp/ruby-libvirt-tester/test.img</path>
  </target>
</volume>
EOF

new_storage_vol_xml_2 = <<EOF
<volume>
  <name>test2.img</name>
  <allocation>0</allocation>
  <capacity unit="G">5</capacity>
  <target>
    <path>/tmp/ruby-libvirt-tester/test2.img</path>
  </target>
</volume>
EOF

# TESTGROUP: conn.list_storage_pools
expect_too_many_args(conn, "list_storage_pools", 1)
list = conn.list_storage_pools
puts_ok "conn.list_storage_pools no args = "

# TESTGROUP: conn.num_of_storage_pools
expect_too_many_args(conn, "num_of_storage_pools", 1)
num = conn.num_of_storage_pools
puts_ok "conn.num_of_storage_pools no args = #{num}"

# TESTGROUP: conn.list_defined_storage_pools
expect_too_many_args(conn, "list_defined_storage_pools", 1)
list = conn.list_defined_storage_pools
puts_ok "conn.list_defined_storage_pools no args = "

# TESTGROUP: conn.num_of_defined_storage_pools
expect_too_many_args(conn, "num_of_defined_storage_pools", 1)
num = conn.num_of_defined_storage_pools
puts_ok "conn.num_of_defined_storage_pools no args = #{num}"

# TESTGROUP: conn.lookup_storage_pool_by_name
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(conn, "lookup_storage_pool_by_name", 1, 2)
expect_too_few_args(conn, "lookup_storage_pool_by_name")
expect_invalid_arg_type(conn, "lookup_storage_pool_by_name", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent name arg", "lookup_storage_pool_by_name", "foobarbazsucker")

conn.lookup_storage_pool_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_pool_by_name running storage pool succeeded"
newpool.destroy

newpool = conn.define_storage_pool_xml(new_storage_pool_xml)
conn.lookup_storage_pool_by_name("ruby-libvirt-tester")
puts_ok "conn.lookup_storage_pool_by_name defined but off storage pool succeeded"
newpool.undefine

# TESTGROUP: conn.lookup_storage_pool_by_uuid
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(conn, "lookup_storage_pool_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_storage_pool_by_uuid")
expect_invalid_arg_type(conn, "lookup_storage_pool_by_uuid", 1)
expect_fail(conn, Libvirt::RetrieveError, "non-existent uuid arg", "lookup_storage_pool_by_uuid", "foobarbazsucker")

conn.lookup_storage_pool_by_uuid("33a5c045-645a-2c00-e56b-927cdf34e17a")
puts_ok "conn.lookup_pool_by_uuid running storage pool succeeded"
newpool.destroy

newpool = conn.define_storage_pool_xml(new_storage_pool_xml)
conn.lookup_storage_pool_by_uuid("33a5c045-645a-2c00-e56b-927cdf34e17a")
puts_ok "conn.lookup_storage_pool_by_uuid defined but off storage pool succeeded"
newpool.undefine

# TESTGROUP: vol.pool
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "pool", 1)

newvol.pool
puts_ok "vol.pool succeeded"

newvol.delete

newpool.destroy

# TESTGROUP: conn.create_storage_pool_xml
expect_too_many_args(conn, "create_storage_pool_xml", new_storage_pool_xml, 0, 1)
expect_too_few_args(conn, "create_storage_pool_xml")
expect_invalid_arg_type(conn, "create_storage_pool_xml", nil)
expect_invalid_arg_type(conn, "create_storage_pool_xml", 1)
expect_invalid_arg_type(conn, "create_storage_pool_xml", new_storage_pool_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "create_storage_pool_xml", "hello")

newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
puts_ok "conn.create_domain_xml started new pool"

expect_fail(conn, Libvirt::Error, "already existing domain", "create_storage_pool_xml", new_storage_pool_xml)

newpool.destroy

# TESTGROUP: conn.define_storage_pool_xml
expect_too_many_args(conn, "define_storage_pool_xml", new_storage_pool_xml, 0, 1)
expect_too_few_args(conn, "define_storage_pool_xml")
expect_invalid_arg_type(conn, "define_storage_pool_xml", nil)
expect_invalid_arg_type(conn, "define_storage_pool_xml", 1)
expect_invalid_arg_type(conn, "define_storage_pool_xml", new_storage_pool_xml, "foo")
expect_fail(conn, Libvirt::Error, "invalid xml", "define_storage_pool_xml", "hello")

newpool = conn.define_storage_pool_xml(new_storage_pool_xml)
puts_ok "conn.define_domain_xml define new pool"

newpool.undefine

# TESTGROUP: conn.discover_storage_pool_sources
expect_too_many_args(conn, "discover_storage_pool_sources", 1, 2, 3, 4)
expect_too_few_args(conn, "discover_storage_pool_sources")
expect_invalid_arg_type(conn, "discover_storage_pool_sources", 1)
expect_invalid_arg_type(conn, "discover_storage_pool_sources", "foo", 1)
expect_invalid_arg_type(conn, "discover_storage_pool_sources", "foo", "bar", "baz")

expect_fail(conn, Libvirt::Error, "invalid pool type", "discover_storage_pool_sources", "foo")

conn.discover_storage_pool_sources("logical")
puts_ok "conn.discover_storage_pool_sources succeeded"

# TESTGROUP: pool.build
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "build", 1, 2)
expect_invalid_arg_type(newpool, "build", 'foo')

newpool.build
puts_ok "pool.build succeeded"

newpool.undefine

# TESTGROUP: pool.undefine
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "undefine", 1)

newpool.undefine
puts_ok "pool.undefine succeeded"

# TESTGROUP: pool.create
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "create", 1, 2)
expect_invalid_arg_type(newpool, "create", 'foo')

newpool.create
puts_ok "pool.create succeeded"

newpool.destroy
newpool.undefine

# TESTGROUP: pool.destroy
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "destroy", 1)

newpool.destroy
puts_ok "pool.destroy succeeded"

# TESTGROUP: pool.delete
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "delete", 1, 2)
expect_invalid_arg_type(newpool, "delete", 'foo')

newpool.delete
puts_ok "pool.delete succeeded"

`mkdir /tmp/ruby-libvirt-tester`

newpool.undefine

# TESTGROUP: pool.refresh
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "refresh", 1, 2)
expect_invalid_arg_type(newpool, "refresh", 'foo')

newpool.refresh
puts_ok "pool.refresh succeeded"

newpool.destroy

# TESTGROUP: pool.name
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "name", 1)

name = newpool.name
puts_ok "pool.name no args = #{name}"

newpool.destroy

# TESTGROUP: pool.uuid
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "uuid", 1)

uuid = newpool.uuid
puts_ok "pool.uuid no args = #{uuid}"

newpool.destroy

# TESTGROUP: pool.info
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "info", 1)

info = newpool.info
puts_ok "pool.info no args = State: #{info.state}, Capacity: #{info.capacity}, Allocation: #{info.allocation}, Available: #{info.available}"

newpool.destroy

# TESTGROUP: pool.xml_desc
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "xml_desc", 1, 2)
expect_invalid_arg_type(newpool, "xml_desc", "foo")

newpool.xml_desc
puts_ok "pool.xml_desc succeeded"

newpool.destroy

# TESTGROUP: pool.autostart?
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "autostart?", 1)

if newpool.autostart?
  puts_fail "pool.autostart? on new pool returned true"
else
  puts_ok "pool.autostart? on new pool returned false"
end

newpool.autostart = true

if not newpool.autostart?
  puts_fail "pool.autostart? after setting autostart returned False"
else
  puts_ok "pool.autostart? after setting autostart returned True"
end

newpool.undefine

# TESTGROUP: pool.autostart=
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "autostart=", 1, 2)
expect_invalid_arg_type(newpool, "autostart=", 'foo')
expect_invalid_arg_type(newpool, "autostart=", nil)
expect_invalid_arg_type(newpool, "autostart=", 1234)

newpool.autostart=true
if not newpool.autostart?
  puts_fail "pool.autostart= did not set autostart to true"
else
  puts_ok "pool.autostart= set autostart to true"
end

newpool.autostart=false

if newpool.autostart?
  puts_fail "pool.autostart= did not set autostart to false"
else
  puts_ok "pool.autostart= set autostart to false"
end

newpool.undefine

# TESTGROUP: pool.num_of_volumes
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "num_of_volumes", 1)
num = newpool.num_of_volumes
puts_ok "pool.num_of_volumes no args = #{num}"

newpool.destroy

# TESTGROUP: pool.list_volumes
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "list_volumes", 1)
list = newpool.list_volumes
puts_ok "pool.list_volumes no args = "

newpool.destroy

# TESTGROUP: pool.free
newpool = conn.define_storage_pool_xml(new_storage_pool_xml)
newpool.undefine
expect_too_many_args(newpool, "free", 1)

newpool.free
puts_ok "newpool.free succeeded"

# TESTGROUP: pool.lookup_volume_by_name
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newpool, "lookup_volume_by_name", 1, 2)
expect_too_few_args(newpool, "lookup_volume_by_name")
expect_invalid_arg_type(newpool, "lookup_volume_by_name", 1);
expect_invalid_arg_type(newpool, "lookup_volume_by_name", nil);
expect_fail(newpool, Libvirt::RetrieveError, "non-existent name arg", "lookup_volume_by_name", "foobarbazsucker")

newpool.lookup_volume_by_name("test.img")
puts_ok "pool.lookup_volume_by_name succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: pool.lookup_volume_by_key
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newpool, "lookup_volume_by_key", 1, 2)
expect_too_few_args(newpool, "lookup_volume_by_key")
expect_invalid_arg_type(newpool, "lookup_volume_by_key", 1);
expect_invalid_arg_type(newpool, "lookup_volume_by_key", nil);
expect_fail(newpool, Libvirt::RetrieveError, "non-existent key arg", "lookup_volume_by_key", "foobarbazsucker")

newpool.lookup_volume_by_key(newvol.key)
puts_ok "pool.lookup_volume_by_key succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: pool.lookup_volume_by_path
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newpool, "lookup_volume_by_path", 1, 2)
expect_too_few_args(newpool, "lookup_volume_by_path")
expect_invalid_arg_type(newpool, "lookup_volume_by_path", 1);
expect_invalid_arg_type(newpool, "lookup_volume_by_path", nil);
expect_fail(newpool, Libvirt::RetrieveError, "non-existent path arg", "lookup_volume_by_path", "foobarbazsucker")

newpool.lookup_volume_by_path(newvol.path)
puts_ok "pool.lookup_volume_by_path succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: vol.name
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "name", 1)

newvol.name
puts_ok "vol.name succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: vol.key
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "key", 1)

newvol.key
puts_ok "vol.key succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: pool.create_volume_xml
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "create_volume_xml", new_storage_vol_xml, 0, 1)
expect_too_few_args(newpool, "create_volume_xml")
expect_invalid_arg_type(newpool, "create_volume_xml", nil)
expect_invalid_arg_type(newpool, "create_volume_xml", 1)
expect_invalid_arg_type(newpool, "create_volume_xml", new_storage_vol_xml, "foo")
expect_fail(newpool, Libvirt::Error, "invalid xml", "create_volume_xml", "hello")

newvol = newpool.create_volume_xml(new_storage_vol_xml)
puts_ok "newpool.create_domain_xml started new pool"

expect_fail(newpool, Libvirt::Error, "already existing domain", "create_volume_xml", new_storage_vol_xml)

newvol.delete
newpool.destroy

# TESTGROUP: pool.create_volume_xml_from
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newpool, "create_volume_xml_from", new_storage_vol_xml_2, 0, 1, 2)
expect_too_few_args(newpool, "create_volume_xml_from")
expect_invalid_arg_type(newpool, "create_volume_xml_from", 1, 2)
expect_invalid_arg_type(newpool, "create_volume_xml_from", "foo", 2)
expect_invalid_arg_type(newpool, "create_volume_xml_from", "foo", newvol, "bar")
expect_fail(newpool, Libvirt::Error, "invalid xml", "create_volume_xml_from", "hello", newvol)

newvol2 = newpool.create_volume_xml_from(new_storage_vol_xml_2, newvol)
puts_ok "newpool.create_domain_xml started new pool"

expect_fail(newpool, Libvirt::Error, "already existing domain", "create_volume_xml_from", new_storage_vol_xml_2, newvol)

newvol2.delete
newvol.delete
newpool.destroy

# TESTGROUP: pool.active?
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)

expect_too_many_args(newpool, "active?", 1)

active = newpool.active?
if not active
  puts_fail "pool.active? on running pool was false"
else
  puts_ok "pool.active? on running pool was true"
end

newpool.destroy

newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

active = newpool.active?
if active
  puts_fail "pool.active? on shutoff pool was true"
else
  puts_ok "pool.active? on shutoff pool was false"
end

newpool.create

active = newpool.active?
if not active
  puts_fail "pool.active? on running pool was false"
else
  puts_ok "pool.active? on running pool was true"
end

newpool.destroy
newpool.undefine

# TESTGROUP: pool.persistent?
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
sleep 1

expect_too_many_args(newpool, "persistent?", 1)

per = newpool.persistent?
if per
  puts_fail "pool.persistent? on transient pool was true"
else
  puts_ok "pool.persistent? on transient pool was false"
end

newpool.destroy

newpool = conn.define_storage_pool_xml(new_storage_pool_xml)

per = newpool.persistent?
if not per
  puts_fail "pool.persisent? on permanent pool was false"
else
  puts_ok "pool.persistent? on permanent pool was true"
end

newpool.undefine

# TESTGROUP: vol.delete
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "delete", 1, 2)
expect_invalid_arg_type(newvol, "delete", 'foo')

newvol.delete
puts_ok "vol.delete succeeded"

newpool.destroy

# TESTGROUP: vol.wipe
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "wipe", 1, 2)
expect_invalid_arg_type(newvol, "wipe", 'foo')

newvol.wipe
puts_ok "vol.wipe succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: vol.info
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "info", 1)

info = newvol.info
puts_ok "vol.info no args = Type: #{info.type}, Capacity: #{info.capacity}, Allocation: #{info.allocation}"

newvol.delete
newpool.destroy

# TESTGROUP: vol.xml_desc
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "xml_desc", 1, 2)
expect_invalid_arg_type(newvol, "xml_desc", "foo")

newvol.xml_desc
puts_ok "vol.xml_desc succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: vol.path
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)

expect_too_many_args(newvol, "path", 1)

newvol.path
puts_ok "vol.path succeeded"

newvol.delete
newpool.destroy

# TESTGROUP: vol.free
newpool = conn.create_storage_pool_xml(new_storage_pool_xml)
newvol = newpool.create_volume_xml(new_storage_vol_xml)
newvol.delete

expect_too_many_args(newvol, "free", 1)
newvol.free
puts_ok "newvol.free succeeded"

newpool.destroy

conn.close

finish_tests
