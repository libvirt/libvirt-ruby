#!/usr/bin/ruby

# Test the secret methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

new_secret_xml = <<EOF
<secret ephemeral='no' private='no'>
  <description>test secret</description>
  <uuid>bd339530-134c-6d07-4410-17fb90dad805</uuid>
  <usage type='volume'>
    <volume>/var/lib/libvirt/images/mail.img</volume>
  </usage>
</secret>
EOF

# TESTGROUP: conn.num_of_secrets
expect_too_many_args(conn, "num_of_secrets", 1)
secrets = conn.num_of_secrets
puts_ok "conn.num_of_secrets no args = #{secrets}"

# TESTGROUP: conn.list_secrets
expect_too_many_args(conn, "list_secrets", 1)
secrets = conn.list_secrets
puts_ok "conn.list_secrets no args = "

# TESTGROUP: conn.lookup_secret_by_uuid
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(conn, "lookup_secret_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_secret_by_uuid")
expect_invalid_arg_type(conn, "lookup_secret_by_uuid", 1)

sec = conn.lookup_secret_by_uuid("bd339530-134c-6d07-4410-17fb90dad805")
puts_ok "conn.lookup_secret_by_uuid succeeded"

newsecret.undefine

# TESTGROUP: conn.lookup_secret_by_usage
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(conn, "lookup_secret_by_usage", 1, 2, 3)
expect_too_few_args(conn, "lookup_secret_by_usage")
expect_invalid_arg_type(conn, "lookup_secret_by_usage", 'foo', 1)
expect_invalid_arg_type(conn, "lookup_secret_by_usage", 1, 2)
expect_fail(conn, Libvirt::RetrieveError, "invalid secret", "lookup_secret_by_usage", Libvirt::Secret::USAGE_TYPE_VOLUME, "foo")

conn.lookup_secret_by_usage(Libvirt::Secret::USAGE_TYPE_VOLUME, "/var/lib/libvirt/images/mail.img")
puts_ok "conn.lookup_secret_by_usage succeeded"

newsecret.undefine

# TESTGROUP: conn.define_secret_xml
expect_too_many_args(conn, "define_secret_xml", 1, 2, 3)
expect_too_few_args(conn, "define_secret_xml")
expect_invalid_arg_type(conn, "define_secret_xml", 1)
expect_invalid_arg_type(conn, "define_secret_xml", nil)
expect_invalid_arg_type(conn, "define_secret_xml", "hello", 'foo')
expect_fail(conn, Libvirt::DefinitionError, "invalid XML", "define_secret_xml", "hello")

newsecret = conn.define_secret_xml(new_secret_xml)
puts_ok "conn.define_secret_xml succeeded"
newsecret.undefine

# TESTGROUP: secret.uuid
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "uuid", 1)
uuid = newsecret.uuid
if uuid != "bd339530-134c-6d07-4410-17fb90dad805"
  puts_fail "nwfilter.uuid expected to be bd339530-134c-6d07-4410-17fb90dad805, but was #{uuid}"
else
  puts_ok "secret.uuid succeeded"
end

newsecret.undefine

# TESTGROUP: secret.usagetype
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "usagetype", 1)
usagetype = newsecret.usagetype
if usagetype != Libvirt::Secret::USAGE_TYPE_VOLUME
  puts_fail "secret.usagetype expected to be 0, but was #{usagetype}"
else
  puts_ok "secret.usagetype no args = #{usagetype}"
end

newsecret.undefine

# TESTGROUP: secret.usageid
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "usageid", 1)
usageid = newsecret.usageid
puts_ok "secret.usageid no args = #{usageid}"

newsecret.undefine

# TESTGROUP: secret.xml_desc
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "xml_desc", 1, 2)
expect_invalid_arg_type(newsecret, "xml_desc", "foo")

newsecret.xml_desc
puts_ok "secret.xml_desc succeeded"

newsecret.undefine

# TESTGROUP: secret.set_value
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "set_value", 1, 2, 3)
expect_too_few_args(newsecret, "set_value")
expect_invalid_arg_type(newsecret, "set_value", 1)
expect_invalid_arg_type(newsecret, "set_value", "foo", "bar")

newsecret.set_value("foo")
puts_ok "secret.set_value succeeded"

newsecret.undefine

# TESTGROUP: secret.get_value
newsecret = conn.define_secret_xml(new_secret_xml)
newsecret.set_value("foo")

expect_too_many_args(newsecret, "get_value", 1, 2)
expect_invalid_arg_type(newsecret, "get_value", 'foo')

val = newsecret.get_value
if val != 'foo'
  puts_fail "secret.get_value expected to get foo, but instead got #{val}"
else
  puts_ok "secret.get_value succeeded"
end

newsecret.undefine

# TESTGROUP: secret.undefine
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "undefine", 1)

newsecret.undefine
puts_ok "secret.undefine succeeded"

# TESTGROUP: secret.free
newsecret = conn.define_secret_xml(new_secret_xml)
newsecret.undefine

expect_too_many_args(newsecret, "free", 1)

puts_ok "secret.free succeeded"

conn.close

finish_tests
