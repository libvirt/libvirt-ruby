#!/usr/bin/ruby

# Test the open calls that the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

def expect_connect_error(func, args)
  expect_fail(Libvirt, Libvirt::ConnectionError, "invalid driver", func, *args)
end

# TESTGROUP: Libvirt::version
version = Libvirt::version
puts_ok "Libvirt::version no args: #{version[0]}, type_version: #{version[1]}"

version = Libvirt::version(nil)
puts_ok "Libvirt::version nil arg: #{version[0]}, type_version: #{version[1]}"

expect_invalid_arg_type(Libvirt, "version", 1)

version = Libvirt::version("Test")
puts_ok "Libvirt::version Test arg #{version[0]}, type_version: #{version[1]}"

expect_too_many_args(Libvirt, "version", "test", 1)

# TESTGROUP: Libvirt::open
conn = Libvirt::open
puts_ok "Libvirt::open no args succeeded"
conn.close

conn = Libvirt::open("qemu:///system")
puts_ok "Libvirt::open qemu:///system succeeded"
conn.close

conn = Libvirt::open(nil)
puts_ok "Libvirt::open nil arg succeeded"
conn.close

expect_too_many_args(Libvirt, "open", "qemu:///system", 1)
expect_connect_error("open", "foo:///system")

# TESTGROUP: Libvirt::open_read_only
conn = Libvirt::open_read_only
puts_ok "Libvirt::open_read_only no args succeeded"
conn.close

conn = Libvirt::open_read_only("qemu:///system")
puts_ok "Libvirt::open_read_only qemu:///system succeeded"
conn.close

conn = Libvirt::open_read_only(nil)
puts_ok "Libvirt::open_read_only nil arg succeeded"
conn.close

expect_too_many_args(Libvirt, "open_read_only", "qemu:///system", 1)
expect_connect_error("open_read_only", "foo:///system")

# TESTGROUP: Libvirt::open_auth
conn = Libvirt::open_auth
puts_ok "Libvirt::open_auth no args succeeded"
conn.close

conn = Libvirt::open_auth("qemu:///system")
puts_ok "Libvirt::open_auth uri arg succeeded"
conn.close

expect_too_many_args(Libvirt, "open_auth", "qemu:///system", 'hello', 1, 2)
expect_connect_error("open_auth", "foo:///system")
expect_fail(Libvirt, TypeError, "invalid auth", "open_auth", "qemu:///system", 1)
expect_fail(Libvirt, ArgumentError, "invalid number auth", "open_auth", "qemu:///system", [])
expect_fail(Libvirt, TypeError, "invalid auth type", "open_auth", "qemu:///system", [1,2,3])
expect_fail(Libvirt, TypeError, "invalid flag", "open_auth", "qemu:///system", [1, 2, 3], 'foo')
expect_fail(Libvirt, TypeError, "invalid credential type", "open_auth", "qemu:///system", [['hello'], 2, 3])

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

conn = Libvirt::open_auth("qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, nil])
puts_ok "Libvirt::open_auth credentials succeeded"
conn.close

conn = Libvirt::open_auth("qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, nil], Libvirt::CONNECT_RO)
puts_ok "Libvirt::open_auth R/O credentials succeeded"
conn.close

conn = Libvirt::open_auth("qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, "wowee"], Libvirt::CONNECT_RO)
puts_ok "Libvirt::open_auth R/O credentials user-data succeeded"
conn.close

finish_tests
