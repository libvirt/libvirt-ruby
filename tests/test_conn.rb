#!/usr/bin/ruby

# Test the conn methods the bindings support

$: << File.dirname(__FILE__)

require 'libvirt'
require 'test_utils.rb'

conn = Libvirt::open("qemu:///system")

# TESTGROUP: conn.close
conn2 = Libvirt::open("qemu:///system")
expect_too_many_args(conn2, "close", 1)
conn2.close

# TESTGROUP: conn.closed?
expect_too_many_args(conn, "closed?", 1)

closed = conn.closed?
if closed
  puts_fail "conn.closed? true after successful connection"
else
  puts_ok "conn.closed? no args = #{closed}"
end

# TESTGROUP: conn.type
expect_too_many_args(conn, "type", 1)

type = conn.type
puts_ok "conn.type no args = #{type}"

# TESTGROUP: conn.version
expect_too_many_args(conn, "version", 1)

version = conn.version
puts_ok "conn.version no args = #{version}"

# TESTGROUP: conn.libversion
expect_too_many_args(conn, "libversion", 1)

libversion = conn.libversion
puts_ok "conn.libversion no args = #{libversion}"

# TESTGROUP: conn.hostname
expect_too_many_args(conn, "hostname", 1)

hostname = conn.hostname
puts_ok "conn.hostname no args = #{hostname}"

# TESTGROUP: conn.uri
expect_too_many_args(conn, "uri", 1)

uri = conn.uri
puts_ok "conn.uri no args = #{uri}"

# TESTGROUP: conn.max_vcpus
expect_too_many_args(conn, "max_vcpus", 'kvm', 1)
expect_fail(conn, Libvirt::RetrieveError, "invalid arg", "max_vcpus", "foo")

max_vcpus = conn.max_vcpus
puts_ok "conn.max_vcpus no args = #{max_vcpus}"
max_vcpus = conn.max_vcpus(nil)
puts_ok "conn.max_vcpus nil arg = #{max_vcpus}"
max_vcpus = conn.max_vcpus('kvm')
puts_ok "conn.max_vcpus kvm arg = #{max_vcpus}"
max_vcpus = conn.max_vcpus('qemu')
puts_ok "conn.max_vcpus qemu arg = #{max_vcpus}"

# TESTGROUP: conn.node_get_info
expect_too_many_args(conn, "node_get_info", 1)
info = conn.node_get_info
puts_ok "conn.node_get_info no args = Model: #{info.model}, Memory: #{info.memory}, CPUs: #{info.cpus}, MHz: #{info.mhz}, Nodes: #{info.nodes}, Sockets: #{info.sockets}, Cores: #{info.cores}, Threads: #{info.threads}"

begin
  # TESTGROUP: conn.node_free_memory
  expect_too_many_args(conn, "node_free_memory", 1)
  freemem = conn.node_free_memory
  puts_ok "conn.node_free_memory no args = #{max_vcpus}"

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
rescue Libvirt::RetrieveError => e
  # these can fail on machines with no NUMA.  Just ignore the failure
end

# TESTGROUP: conn.node_get_security_model
expect_too_many_args(conn, "node_get_security_model", 1)
secmodel = conn.node_get_security_model
puts_ok "conn.node_get_security_model no args = Model: #{secmodel.model}, DOI: #{secmodel.doi}"

# TESTGROUP: conn.encrypted?
expect_too_many_args(conn, "encrypted?", 1)
encrypted = conn.encrypted?
puts_ok "conn.encrypted? no args = #{encrypted}"

# TESTGROUP: conn.secure?
expect_too_many_args(conn, "secure?", 1)
secure = conn.secure?
puts_ok "conn.secure? no args = #{secure}"

# TESTGROUP: conn.capabilities
expect_too_many_args(conn, "capabilities", 1)
capabilities = conn.capabilities
puts_ok "conn.capabilities no args succeeded"

conn.close
closed = conn.closed?
if not closed
  puts_fail "after close, connection is still open"
else
  puts_ok "after close, conn closed? = #{closed}"
end

finish_tests
