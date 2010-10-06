#!/usr/bin/ruby

# Test the secret methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

UUID = "bd339530-134c-6d07-4410-17fb90dad805"

conn = Libvirt::open("qemu:///system")

new_secret_xml = <<EOF
<secret ephemeral='no' private='no'>
  <description>test secret</description>
  <uuid>#{UUID}</uuid>
  <usage type='volume'>
    <volume>/var/lib/libvirt/images/mail.img</volume>
  </usage>
</secret>
EOF

# TESTGROUP: conn.num_of_secrets
expect_too_many_args(conn, "num_of_secrets", 1)
expect_success(conn, "no args", "num_of_secrets")

# TESTGROUP: conn.list_secrets
expect_too_many_args(conn, "list_secrets", 1)
expect_success(conn, "no args", "list_secrets")

# TESTGROUP: conn.lookup_secret_by_uuid
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(conn, "lookup_secret_by_uuid", 1, 2)
expect_too_few_args(conn, "lookup_secret_by_uuid")
expect_invalid_arg_type(conn, "lookup_secret_by_uuid", 1)

expect_success(conn, "uuid arg", "lookup_secret_by_uuid", UUID) {|x| x.uuid == UUID}

newsecret.undefine

# TESTGROUP: conn.lookup_secret_by_usage
newsecret = conn.define_secret_xml(new_secret_xml)

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

expect_success(conn, "secret XML", "define_secret_xml", new_secret_xml)

newsecret.undefine

# TESTGROUP: secret.uuid
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "uuid", 1)

expect_success(newsecret, "no args", "uuid") {|x| x == UUID}

newsecret.undefine

# TESTGROUP: secret.usagetype
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "usagetype", 1)

expect_success(newsecret, "no args", "usagetype") {|x| x == Libvirt::Secret::USAGE_TYPE_VOLUME}

newsecret.undefine

# TESTGROUP: secret.usageid
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "usageid", 1)

expect_success(newsecret, "no args", "usageid")

newsecret.undefine

# TESTGROUP: secret.xml_desc
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "xml_desc", 1, 2)
expect_invalid_arg_type(newsecret, "xml_desc", "foo")

expect_success(newsecret, "no args", "xml_desc")

newsecret.undefine

# TESTGROUP: secret.set_value
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "set_value", 1, 2, 3)
expect_too_few_args(newsecret, "set_value")
expect_invalid_arg_type(newsecret, "set_value", 1)
expect_invalid_arg_type(newsecret, "set_value", "foo", "bar")

expect_success(newsecret, "value arg", "set_value", "foo")

newsecret.undefine

# TESTGROUP: secret.get_value
newsecret = conn.define_secret_xml(new_secret_xml)
newsecret.set_value("foo")

expect_too_many_args(newsecret, "get_value", 1, 2)
expect_invalid_arg_type(newsecret, "get_value", 'foo')

expect_success(newsecret, "no args", "get_value") {|x| x == 'foo'}

newsecret.undefine

# TESTGROUP: secret.undefine
newsecret = conn.define_secret_xml(new_secret_xml)

expect_too_many_args(newsecret, "undefine", 1)

expect_success(newsecret, "no args", "undefine")

# TESTGROUP: secret.free
newsecret = conn.define_secret_xml(new_secret_xml)
newsecret.undefine

expect_too_many_args(newsecret, "free", 1)

expect_success(newsecret, "no args", "free")

conn.close

finish_tests
