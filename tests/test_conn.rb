#!/usr/bin/ruby

# Test the conn methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Connection:"
puts " Closed?:          #{conn.closed?}"
puts " Type:             #{conn.type}"
puts " Version:          #{conn.version}"
puts " Libversion:       #{conn.libversion}"
puts " Hostname:         #{conn.hostname}"
puts " URI:              #{conn.uri}"
puts " Max VCPUs:        #{conn.max_vcpus}"
puts " Max VCPUs (kvm):  #{conn.max_vcpus("kvm")}"
puts " Max VCPUs (qemu): #{conn.max_vcpus("qemu")}"
puts " Node Free Memory: #{conn.node_free_memory}kb"
puts " Node Cells Free Memory:"
cell_free_mem = conn.node_cells_free_memory
cell_free_mem.each_index do |cell|
  puts "  Cell: #{cell}, Free Memory: #{cell_free_mem[cell]}kb"
end
puts " Node Cells Free Memory (0-):"
cell_free_mem = conn.node_cells_free_memory(0)
cell_free_mem.each_index do |cell|
  puts "  Cell: #{cell}, Free Memory: #{cell_free_mem[cell]}kb"
end
puts " Node Cells Free Memory (0-1):"
cell_free_mem = conn.node_cells_free_memory(0, 1)
cell_free_mem.each_index do |cell|
  puts "  Cell: #{cell}, Free Memory: #{cell_free_mem[cell]}kb"
end
secmodel = conn.node_get_security_model
puts " Node Security Model:"
puts "  Model: #{secmodel.model}"
puts "  DOI:   #{secmodel.doi}"
puts " Encrypted?: #{conn.encrypted?}"
puts " Secure?: #{conn.secure?}"
info = conn.node_get_info
puts " Node Info:"
puts "  Model:   #{info.model}"
puts "  Memory:  #{info.memory}"
puts "  CPUs:    #{info.cpus}"
puts "  MHz:     #{info.mhz}"
puts "  Nodes:   #{info.nodes}"
puts "  Sockets: #{info.sockets}"
puts "  Cores:   #{info.cores}"
puts "  Threads: #{info.threads}"
puts " Capabilities:"
puts conn.capabilities
conn.close
puts "After close, conn closed? = #{conn.closed?}"
