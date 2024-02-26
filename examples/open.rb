# this simple program demonstrates opening a libvirt connection with the
# bindings and then closing it out

require 'libvirt'

# the open method is a module method.  It can take 0 or 1 parameters; with 0
# parameters, libvirt attempts to auto-connect to a hypervisor for you (not
# recommended).  If a parameter is passed, it must be a valid libvirt URI
conn = Libvirt::open("qemu:///system")

# check to see if the connection is closed (it shouldn't be)
puts "After open, connection closed?: #{conn.closed?}"

# close the connection
conn.close

# after close, the closed? should return true
puts "After close, connection closed?: #{conn.closed?}"
