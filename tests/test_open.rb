#!/usr/bin/ruby

# Test the open calls that the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

def expect_connect_error(func, args)
  expect_fail(Libvirt, Libvirt::ConnectionError, "invalid driver", func, *args)
end

# TESTGROUP: Libvirt::version
expect_too_many_args(Libvirt, "version", "test", 1)
expect_invalid_arg_type(Libvirt, "version", 1)
expect_success(Libvirt, "no args", "version") {|x| x.class == Array and x.length == 2}
expect_success(Libvirt, "nil arg", "version", nil) {|x| x.class == Array and x.length == 2}
expect_success(Libvirt, "Test arg", "version", "Test") {|x| x.class == Array and x.length == 2}

# TESTGROUP: Libvirt::open
expect_too_many_args(Libvirt, "open", "qemu:///system", 1)
expect_connect_error("open", "foo:///system")
conn = expect_success(Libvirt, "no args", "open") {|x| x.class == Libvirt::Connect }
conn.close
conn = expect_success(Libvirt, "qemu:///system", "open", "qemu:///system") {|x| x.class == Libvirt::Connect }
conn.close
conn = expect_success(Libvirt, "nil arg", "open", nil) {|x| x.class == Libvirt::Connect }
conn.close

# TESTGROUP: Libvirt::open_read_only
expect_too_many_args(Libvirt, "open_read_only", "qemu:///system", 1)
expect_connect_error("open_read_only", "foo:///system")
conn = expect_success(Libvirt, "no args", "open_read_only") {|x| x.class == Libvirt::Connect }
conn.close
conn = expect_success(Libvirt, "qemu:///system", "open_read_only", "qemu:///system") {|x| x.class == Libvirt::Connect }
conn.close
conn = expect_success(Libvirt, "nil arg", "open_read_only", nil) {|x| x.class == Libvirt::Connect }
conn.close

# TESTGROUP: Libvirt::open_auth
expect_too_many_args(Libvirt, "open_auth", "qemu:///system", 'hello', 1, 2)
expect_connect_error("open_auth", "foo:///system")
expect_invalid_arg_type(Libvirt, "open_auth", 1)
expect_invalid_arg_type(Libvirt, "open_auth", "qemu:///system", [1, 2, 3], 'foo')
expect_invalid_arg_type(Libvirt, "open_auth", "qemu:///system", [1, 2, 3])
expect_invalid_arg_type(Libvirt, "open_auth", "qemu:///system", [['hello'], 2, 3])
expect_too_few_args(Libvirt, "open_auth", "qemu:///system", [])
expect_too_many_args(Libvirt, "open_auth", "qemu:///system", [1, 2, 3, 4])
conn = expect_success(Libvirt, "no args", "open_auth") {|x| x.class == Libvirt::Connect }
conn.close
conn = expect_success(Libvirt, "uri arg", "open_auth", "qemu:///system") {|x| x.class == Libvirt::Connect }

def my_auth(creds, userdata)
  if not userdata.nil?
    puts "userdata is #{userdata}"
  end
  creds.each do |cred|
    if cred["type"] == Libvirt::CRED_AUTHNAME
      puts "#{cred['prompt']}: "
      res = gets
      # strip off the \n
      cred["result"] = res[0..-2]
    elsif cred["type"] == Libvirt::CRED_PASSPHRASE
      puts "#{cred['prompt']}: "
      res = gets
      cred["result"] = res[0..-2]
    else
      raise "Unsupported credential #{cred['type']}"
    end
  end
end

conn = expect_success(Libvirt, "credentials", "open_auth", "qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, nil])
conn.close

conn = expect_success(Libvirt, "R/O credentials", "open_auth", "qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, nil], Libvirt::CONNECT_RO)
conn.close

conn = expect_success(Libvirt, "R/O credentials user-data", "open_auth", "qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, "wowee"], Libvirt::CONNECT_RO)
conn.close

finish_tests
