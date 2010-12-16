# this program demonstrates getting various information about the hypervisor.
# not all of these calls work on all hypervisors.
require 'libvirt'

conn = Libvirt::open('qemu:///system')

# check if the connection is closed
puts "Hypervisor connection closed?: #{conn.closed?}"

# retrieve basic information about the hypervisor.  See the libvirt
# documentation for more information about what each of these fields mean.
nodeinfo = conn.node_get_info
puts "Hypervisor Nodeinfo:"
puts " Model:         #{nodeinfo.model}"
puts " Memory:        #{nodeinfo.memory}"
puts " CPUs:          #{nodeinfo.cpus}"
puts " MHz:           #{nodeinfo.mhz}"
puts " (NUMA) Nodes:  #{nodeinfo.nodes}"
puts " Sockets:       #{nodeinfo.sockets}"
puts " Cores:         #{nodeinfo.cores}"
puts " Threads:       #{nodeinfo.threads}"

# print the amount of free memory in every NUMA node on the hypervisor
begin
  cellsmem = conn.node_cells_free_memory
  puts "Hypervisor NUMA node free memory:"
  cellsmem.each_with_index do |cell,index|
    puts " Node #{index}: #{cell}"
  end
rescue
  # this call may not be supported; if so, just ignore
end

# print the type of the connection.  This will be "QEMU" for qemu, "XEN" for
# xen, etc.
puts "Hypervisor Type: #{conn.type}"
# print the hypervisor version
puts "Hypervisor Version: #{conn.version}"
# print the libvirt version on the hypervisor
puts "Hypervisor Libvirt version: #{conn.libversion}"
# print the hypervisor hostname (deprecated)
puts "Hypervisor Hostname: #{conn.hostname}"
# print the URI in use on this connection.  Note that this may be different
# from the one passed into Libvirt::open, since libvirt may decide to
# canonicalize the URI
puts "Hypervisor URI: #{conn.uri}"
# print the amount of free memory on the hypervisor
begin
  puts "Hypervisor Free Memory: #{conn.node_free_memory}"
rescue
  # this call may not be supported; if so, just ignore
end

# print the security model in use on the hypervisor
secmodel = conn.node_get_security_model
puts "Hypervisor Security Model:"
puts " Model: #{secmodel.model}"
puts " DOI:   #{secmodel.doi}"

# print whether the connection to the hypervisor is encrypted
puts "Hypervisor connection encrypted?: #{conn.encrypted?}"
# print whether the connection to the hypervisor is secure
puts "Hypervisor connection secure?: #{conn.secure?}"
# print the capabilities XML for the hypervisor.  A detailed explanation of
# the XML format can be found in the libvirt documentation.
puts "Hypervisor capabilities XML:"
puts conn.capabilities

conn.close
