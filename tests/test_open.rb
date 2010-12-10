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
expect_too_many_args(Libvirt, "open_auth", "qemu:///system", [], "hello there", 1, 2)
expect_connect_error("open_auth", "foo:///system")
expect_invalid_arg_type(Libvirt, "open_auth", 1)
expect_invalid_arg_type(Libvirt, "open_auth", "qemu:///system", [], "hello", "foo")

conn = expect_success(Libvirt, "no args", "open_auth")  {|x| x.class == Libvirt::Connect }
conn.close

conn = expect_success(Libvirt, "uri arg", "open_auth", "qemu:///system") {|x| x.class == Libvirt::Connect }
conn.close

conn = expect_success(Libvirt, "uri and empty cred args", "open_auth", "qemu:///system", []) {|x| x.class == Libvirt::Connect }
conn.close

conn = expect_success(Libvirt, "uri and full cred args", "open_auth", "qemu:///system", [Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE]) {|x| x.class == Libvirt::Connect }
conn.close

conn = expect_success(Libvirt, "uri, full cred, and user args", "open_auth", "qemu:///system", [Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], "hello") {|x| x.class == Libvirt::Connect }
conn.close

# equivalent to "expect_success"
begin
  conn = Libvirt::open_auth("qemu:///system", [Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], "hello") do |cred|
    if not cred["userdata"].nil?
      puts "userdata is #{cred["userdata"]}"
    end
    if cred["type"] == Libvirt::CRED_AUTHNAME
      print "#{cred['prompt']}: "
      res = gets
      # strip off the \n
      res = res[0..-2]
    elsif cred["type"] == Libvirt::CRED_PASSPHRASE
      print "#{cred['prompt']}: "
      res = gets
      res = res[0..-2]
    else
      raise "Unsupported credential #{cred['type']}"
    end
    res
  end

  puts "OK: open_auth uri, creds, userdata, auth block succeeded"
  $SUCCESS = $SUCCESS + 1
  conn.close
rescue NoMethodError
  puts "SKIPPED: open_auth does not exist"
  $SKIPPED = $SKIPPED + 1
rescue => e
  puts "FAIL: open_auth uri, creds, userdata, auth block expected to succeed, threw #{e.class.to_s}: #{e.to_s}"
  $FAIL = $FAIL + 1
end

# equivalent to "expect_success"
begin
  conn = Libvirt::open_auth("qemu:///system", [Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], "hello", Libvirt::CONNECT_RO) do |cred|
    if not cred["userdata"].nil?
      puts "userdata is #{cred["userdata"]}"
    end
    if cred["type"] == Libvirt::CRED_AUTHNAME
      print "#{cred['prompt']}: "
      res = gets
      # strip off the \n
      res = res[0..-2]
    elsif cred["type"] == Libvirt::CRED_PASSPHRASE
      print "#{cred['prompt']}: "
      res = gets
      res = res[0..-2]
    else
      raise "Unsupported credential #{cred['type']}"
    end
    res
  end

  puts "OK: open_auth uri, creds, userdata, R/O flag, auth block succeeded"
  $SUCCESS = $SUCCESS + 1
  conn.close
rescue NoMethodError
  puts "SKIPPED: open_auth does not exist"
  $SKIPPED = $SKIPPED + 1
rescue => e
  puts "FAIL: open_auth uri, creds, userdata, R/O flag, auth block expected to succeed, threw #{e.class.to_s}: #{e.to_s}"
  $FAIL = $FAIL + 1
end

finish_tests
