#!/usr/bin/ruby

# Test the storage methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of Storage Pools: #{conn.num_of_storage_pools}"
puts "Number of Defined Storage Pools: #{conn.num_of_defined_storage_pools}"

defined = conn.list_defined_storage_pools
running = conn.list_storage_pools

(defined+running).each do |storagename|
  storagepool = conn.lookup_storage_pool_by_name(storagename)
  store2 = conn.lookup_storage_pool_by_uuid(storagepool.uuid)
  storagepool.refresh
  puts "StoragePool #{storagepool.name}:"
  puts " UUID: #{storagepool.uuid}"
  puts " Autostart?: #{storagepool.autostart?}"
  puts " Active?: #{storagepool.active?}"
  puts " Persistent?: #{storagepool.persistent?}"
  info = storagepool.info
  puts " Info:"
  puts "  State:      #{info.state}"
  puts "  Capacity:   #{info.capacity}"
  puts "  Allocation: #{info.allocation}"
  puts "  Available:  #{info.available}"
  puts " XML:"
  puts storagepool.xml_desc
  puts " Number of Volumes: #{storagepool.num_of_volumes}"
  puts " Volumes:"
  storagepool.list_volumes.each do |volname|
    storagevolume = storagepool.lookup_volume_by_name(volname)
    vol2 = storagepool.lookup_volume_by_key(storagevolume.key)
    vol3 = storagepool.lookup_volume_by_path(storagevolume.path)
    puts "  Volume #{storagevolume.name}:"
    puts "   Pool: #{storagevolume.pool.name}"
    puts "   Key:  #{storagevolume.key}"
    puts "   Path: #{storagevolume.path}"
    info = storagevolume.info
    puts "   Info:"
    puts "    Type:       #{info.type}"
    puts "    Capacity:   #{info.capacity}"
    puts "    Allocation: #{info.allocation}"
  end
end

conn.close
