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

conn = Libvirt::open_auth
conn.close

conn = Libvirt::open_auth("qemu:///system")
conn.close

def my_auth(creds, userdata)
  if not userdata.nil?
    puts "userdata is #{userdata}"
  end
  creds.each do |cred|
    if cred["type"] == Libvirt::CRED_AUTHNAME
      puts "#{cred['prompt']}: "
      res = gets
      # strip off the \n
      cred["result"] = res[0..-2]
    elsif cred["type"] == Libvirt::CRED_PASSPHRASE
      puts "#{cred['prompt']}: "
      res = gets
      cred["result"] = res[0..-2]
    else
      raise "Unsupported credential #{cred['type']}"
    end
  end
end

conn = Libvirt::open_auth("qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, nil])
conn.close

conn = Libvirt::open_auth("qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, nil], Libvirt::CONNECT_RO)
conn.close

conn = Libvirt::open_auth("qemu:///system", [[Libvirt::CRED_AUTHNAME, Libvirt::CRED_PASSPHRASE], :my_auth, "wowee"], Libvirt::CONNECT_RO)
conn.close
