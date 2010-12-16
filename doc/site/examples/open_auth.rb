# this program demonstrates opening a libvirt connection with the bindings
# using Libvirt::open_auth.  Libvirt::open_auth has the ability to request
# additional information from the user (via a callback mechanism) to complete
# the connection.

require 'libvirt'

# open a connection to libvirt using Libvirt::open_auth.  The first argument
# is the libvirt URI to connect to.  The second argument is the list of
# credentials the block is willing to accept. The third argument is any
# user-specific data that should be passed into the block.  The block itself
# receives a single parameter which is a hash containing the fields necessary
# to retrieve information from the user.  The block will be called once for
# each credential that needs to be resolved to connect.  The last expression of
# the block must contain the result necessary to resolve this credential.
conn = Libvirt::open_auth("qemu+tcp://localhost/system",
                          [Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE],
                          "my data") do |cred|
  puts "Credential information:"
  puts "  Type: #{cred["type"]}"
  puts "  Prompt: #{cred["prompt"]}"
  puts "  Challenge: #{cred["challenge"]}"
  puts "  Default result: #{cred["defresult"]}"
  puts "  User data: #{cred["userdata"]}\n\n"

  print "#{cred['prompt']}: "

  if cred["type"] == Libvirt::CRED_AUTHNAME
    res = gets
    # strip off the \n
    res = res[0..-2]
  elsif cred["type"] == Libvirt::CRED_PASSPHRASE
    res = gets
    res = res[0..-2]
  else
    raise "Unsupported credential #{cred['type']}"
  end

  res
end

conn.close
