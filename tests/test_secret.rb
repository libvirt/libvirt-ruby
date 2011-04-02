#!/usr/bin/ruby

# Test the secret methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

# TESTGROUP: secret.uuid
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(newsecret, "uuid", 1)

expect_success(newsecret, "no args", "uuid") {|x| x == $SECRET_UUID}

newsecret.undefine

# TESTGROUP: secret.usagetype
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(newsecret, "usagetype", 1)

expect_success(newsecret, "no args", "usagetype") {|x| x == Libvirt::Secret::USAGE_TYPE_VOLUME}

newsecret.undefine

# TESTGROUP: secret.usageid
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(newsecret, "usageid", 1)

expect_success(newsecret, "no args", "usageid")

newsecret.undefine

# TESTGROUP: secret.xml_desc
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(newsecret, "xml_desc", 1, 2)
expect_invalid_arg_type(newsecret, "xml_desc", "foo")

expect_success(newsecret, "no args", "xml_desc")

newsecret.undefine

# TESTGROUP: secret.set_value
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(newsecret, "set_value", 1, 2, 3)
expect_too_few_args(newsecret, "set_value")
expect_invalid_arg_type(newsecret, "set_value", 1)
expect_invalid_arg_type(newsecret, "set_value", "foo", "bar")

expect_success(newsecret, "value arg", "set_value", "foo")

newsecret.undefine

# TESTGROUP: secret.get_value
newsecret = conn.define_secret_xml($new_secret_xml)
newsecret.set_value("foo")

expect_too_many_args(newsecret, "get_value", 1, 2)
expect_invalid_arg_type(newsecret, "get_value", 'foo')

expect_success(newsecret, "no args", "get_value") {|x| x == 'foo'}

newsecret.undefine

# TESTGROUP: secret.undefine
newsecret = conn.define_secret_xml($new_secret_xml)

expect_too_many_args(newsecret, "undefine", 1)

expect_success(newsecret, "no args", "undefine")

# TESTGROUP: secret.free
newsecret = conn.define_secret_xml($new_secret_xml)
newsecret.undefine

expect_too_many_args(newsecret, "free", 1)

expect_success(newsecret, "no args", "free")

conn.close

finish_tests
