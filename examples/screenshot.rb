# this simple program demonstrates taking a screenshot of a libvirt domain

require 'libvirt'

# make sure we get the required command-line arguments
if ARGV.length != 2
  puts "Usage: screenshot.rb <domainname> <filename>"
  exit 1
end

domname = ARGV[0]
filename = ARGV[1]

# open the connection to libvirt
conn = Libvirt::open("qemu:///system")

# lookup the domain object
dom = conn.lookup_domain_by_name(domname)

# create a new stream
stream = conn.stream

# start the screenshot
mimetype = dom.screenshot(stream, 0)

# open up the output file
f = File.open(filename, 'w')

# receive all of the data from the stream (the screenshot).  stream.recvall
# takes one parameter, which is the opaque userdata to pass into the block.
# It then yields a bunch of data, and that userdata to the block as many times
# as necessary.  The block is expected to return the number of bytes consumed
# during this iteration.
stream.recvall(f) do |data, opaque|
  opaque.write(data)
  data.length
end

# close out the output file
f.close

# close out the stream
stream.finish

# close the connection
conn.close
