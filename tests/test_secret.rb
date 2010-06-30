#!/usr/bin/ruby

# Test the secret methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of Secrets: #{conn.num_of_secrets}"

new_secret_xml = <<EOF
<secret ephemeral='no' private='no'>
  <description>test secret</description>
</secret>
EOF

newsecret = conn.define_secret_xml(new_secret_xml)
newsecret.set_value("hello")
puts newsecret.get_value
newsecret.set_value("bob", 0)
puts newsecret.get_value

conn.list_secrets.each do |secuuid|
  secret = conn.lookup_secret_by_uuid(secuuid)
  puts "Secret #{secret.uuid}:"
  puts " UsageType: #{secret.usagetype}"
  puts " UsageId:   #{secret.usageid}"
  puts " XML:"
  puts secret.xml_desc
end

newsecret.undefine

conn.close
