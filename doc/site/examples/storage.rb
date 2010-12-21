# this program demonstrates the use of the libvirt storage APIs.  In particular
# it demonstrates directory pool creation, volume creation, and teardown.
# libvirt supports many other kinds of storage pools, including iSCSI, NFS,
# etc.  See http://libvirt.org/formatstorage.html for more details

require 'libvirt'

# a directory storage pool.  This will be a pool with the name
# 'ruby-libvirt-tester' with the pool itself in /tmp/ruby-libvirt-tester
storage_pool_xml = <<EOF
<pool type="dir">
  <name>ruby-libvirt-tester</name>
  <uuid>33a5c045-645a-2c00-e56b-927cdf34e17a</uuid>
  <target>
    <path>/tmp/ruby-libvirt-tester</path>
  </target>
</pool>
EOF

# a storage volume.  This will have name test.img, with capacity of 1GB
# and allocation of 0.  The difference between allocation and capacity is the
# maximum allowed for a volume (capacity) versus how much is currently
# allocated (allocation).  If allocation < capacity, then this is a
# thinly-provisioned volume (think of a sparse file)
storage_vol_xml = <<EOF
<volume>
  <name>test.img</name>
  <allocation>0</allocation>
  <capacity unit="G">1</capacity>
  <target>
    <path>/tmp/ruby-libvirt-tester/test.img</path>
  </target>
</volume>
EOF

# open up the connection to libvirt
conn = Libvirt::open('qemu:///system')

# print out how many storage pools are currently active
puts "Number of storage pools: #{conn.num_of_storage_pools}"

# create our new storage pool
pool = conn.define_storage_pool_xml(storage_pool_xml)

# build the storage pool.  The operation that this performs is pool-specific;
# in the case of a directory pool, it does the equivalent of mkdir to create
# the directory
pool.build

# start up the pool
pool.create

# print out how many active storage pools are now there; this should be one
# more than before
puts "Number of storage pools: #{conn.num_of_storage_pools}"

# print out some information about the pool.  Note that allocation can be
# much less than capacity; see the discussion for the storage volume XML for
# more details
puts "Storage Pool:"
puts " Name: #{pool.name}"
puts " UUID: #{pool.uuid}"
puts " Autostart?: #{pool.autostart?}"
poolinfo = pool.info
puts " Info:"
puts "  State: #{poolinfo.state}"
puts "  Capacity: #{poolinfo.capacity / 1024}kb"
puts "  Allocation: #{poolinfo.allocation / 1024}kb"
puts "  Available: #{poolinfo.available / 1024}kb"
puts " Number of volumes: #{pool.num_of_volumes}"

# create a new volume in the storage pool.  What happens on volume creation
# is pool-type specific.  In the case of a directory pool, this creates the
# file
vol = pool.create_volume_xml(storage_vol_xml)

# refresh the pool, which rescans the pool for any changes to the pool including
# new or deleted volumes.  While this isn't strictly necessary
# (create_volume_xml already does this), it is a good habit to get into when
# making changes to a pool
pool.refresh

# print out how many volumes are in our pool; there should now be 1
puts " Number of volumes: #{pool.num_of_volumes}"

# print out some information about the volume.  Again, see the discussion
# for the storage volume XML to understand the differences between allocation
# and capacity
puts "Storage Volume:"
puts " Name: #{vol.name}"
puts " Key: #{vol.key}"
puts " Path: #{vol.path}"
puts " Pool: #{vol.pool.name}"
volinfo = vol.info
puts " Info:"
puts "  Type: #{volinfo.type}"
puts "  Capacity: #{volinfo.capacity / 1024}kb"
puts "  Allocation: #{volinfo.allocation / 1024}kb"

# delete the volume.  What happens here is pool-type specific; for a directory
# pool, the file is erased
vol.delete

# destroy the pool
pool.destroy

# undefine the pool
pool.undefine

conn.close
