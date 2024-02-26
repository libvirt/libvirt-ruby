# this program demonstrates a few of the connection methods; in particular
# it shows getting information about the connection and listing certain
# types of objects returned by libvirt

require 'libvirt'

# open up a connection to the qemu driver
conn = Libvirt::open('qemu:///system')

# query some basic information about the connection
puts "Connection closed?: #{conn.closed?}"
puts "Connection type: #{conn.type}"
puts "Connection hypervisor version: #{conn.version}"
puts "Connection libvirt version: #{conn.libversion}"
puts "Connection hostname: #{conn.hostname}"
puts "Connection canonical URI: #{conn.uri}"
puts "Connection Maximum VCPUs: #{conn.max_vcpus}"

begin
  # check if the connection to the remote hypervisor is encrypted
  puts "Connection Encrypted: #{conn.encrypted?}"
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

begin
  # check if the connection to the remove hypervisor is secure
  puts "Connection Secure: #{conn.secure?}"
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

# get the number of active (running) domains and list them; the full domain
# list is available through a combination of the list returned from
# conn.list_domains and the list returned from conn.list_defined_domains
puts "Connection number of active domains: #{conn.num_of_domains}"
puts "Connection active domains:"
conn.list_domains.each do |domid|
  dom = conn.lookup_domain_by_id(domid)
  puts " Domain #{dom.name}"
end

# get the number of inactive (shut off) domains and list them
puts "Connection number of inactive domains: #{conn.num_of_defined_domains}"
puts "Connection inactive domains:"
conn.list_defined_domains.each do |domname|
  puts " Domain #{domname}"
end

begin
  # get the number of active and inactive interfaces and list them
  puts "Connection number of active interfaces: #{conn.num_of_interfaces}"
  puts "Connection number of inactive interfaces: #{conn.num_of_defined_interfaces}"
  puts "Connection interfaces:"
  active = conn.list_interfaces
  inactive = conn.list_defined_interfaces
  (active+inactive).each do |intname|
    puts " Interface #{intname}"
  end
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

# get the number of active and inactive networks and list them
puts "Connection number of active networks: #{conn.num_of_networks}"
puts "Connection number of inactive networks: #{conn.num_of_defined_networks}"
puts "Connection networks:"
active = conn.list_networks
inactive = conn.list_defined_networks
(active+inactive).each do |netname|
  puts " Network #{netname}"
end

begin
  # get the number of node devices and list them
  puts "Connection number of nodedevices: #{conn.num_of_nodedevices}"
  conn.list_nodedevices.each do |nodename|
    puts " Node Device #{nodename}"
  end
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

begin
  # get the number of network filters and list them
  puts "Connection number of nwfilters: #{conn.num_of_nwfilters}"
  conn.list_nwfilters.each do |nwfname|
    pust " NWFilter #{nwfname}"
  end
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

begin
  # get the number of secrets and list them
  puts "Connection number of secrets: #{conn.num_of_secrets}"
  conn.list_secrets.each do |secretuuid|
    puts " Secret #{secretuuid}"
  end
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

begin
  # get the number of active and inactive storage pools and list them
  puts "Connection number of active storage pools: #{conn.num_of_storage_pools}"
  puts "Connection number of inactive storage pools: #{conn.num_of_defined_storage_pools}"
  active = conn.list_storage_pools
  inactive = conn.list_defined_storage_pools
  (active+inactive).each do |poolname|
    puts " Pool #{poolname}"
  end
rescue NoMethodError
  # skip this completely, since this compiled version of ruby-libvirt doesn't
  # support this method
rescue Libvirt::Error => e
  if e.libvirt_code == 3
    # this compiled version of ruby-libvirt supports the method, but the
    # libvirt that we are connecting to does not
  else
    raise
  end
end

conn.close
