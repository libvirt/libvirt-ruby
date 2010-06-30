#!/usr/bin/ruby

# Test the open calls that the bindings support

require 'libvirt'

conn = Libvirt::open
conn.close

conn = Libvirt::open("qemu:///system")
conn.close

conn = Libvirt::open(nil)
conn.close

conn = Libvirt::open_read_only
conn.close

conn = Libvirt::open_read_only("qemu:///system")
conn.close

conn = Libvirt::open_read_only(nil)
conn.close
