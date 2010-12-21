# this example shows how to use the secret API to store and then retrieve
# binary data from a secret

require 'libvirt'

# generate some example secret XML.  http://libvirt.org/formatsecret.html has
# more details about the XML format, but essentially:
# ephemeral='no' means to keep this secret on-disk
# private='no' means make this secret available to callers
# usage type of 'volume' is the only one currently defined
new_secret_xml = <<EOF
<secret ephemeral='no' private='no'>
  <description>test secret</description>
  <uuid>bd339530-134c-6d07-4410-17fb90dad805</uuid>
  <usage type='volume'>
    <volume>/var/lib/libvirt/images/mail.img</volume>
  </usage>
</secret>
EOF

# open the connection to libvirt
conn = Libvirt::open('qemu:///system')

# start out by showing how many current secrets there are
puts "Number of secrets to start: #{conn.num_of_secrets}"

# define our new secret
secret = conn.define_secret_xml(new_secret_xml)

# there now should be one more secret than before
puts "Number of secrets now: #{conn.num_of_secrets}"

# set the value of the secret to a binary string.  The secret can be any
# kind of string
secret.set_value("\x3a\x3c\x3b\x5a")

# fetch the secret that we just stored, and print it out byte-by-byte
val = secret.get_value
val.unpack("c#{val.length}").each do |byte|
  puts "byte is #{byte}"
end

# undefine the secret
secret.undefine

conn.close
