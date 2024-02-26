# this program demonstrates various methods that can be used to create and
# remove libvirt domains

require 'libvirt'

GUEST_DISK = '/var/lib/libvirt/images/example.qcow2'
# create the guest disk
`rm -f #{GUEST_DISK} ; qemu-img create -f qcow2 #{GUEST_DISK} 5G`

UUID = "93a5c045-6457-2c09-e5ff-927cdf34e17b"

# the XML that describes our guest; note that this is a KVM guest.  For
# additional information about the guest XML, please see the libvirt
# documentation
new_dom_xml = <<EOF
<domain type='kvm'>
  <name>ruby-libvirt-tester</name>
  <uuid>#{UUID}</uuid>
  <memory>1048576</memory>
  <currentMemory>1048576</currentMemory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <pae/>
  </features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>restart</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='#{GUEST_DISK}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:01:60:3c:95'/>
      <source bridge='virbr0'/>
      <model type='virtio'/>
      <target dev='rl556'/>
    </interface>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'>
      <target port='0'/>
    </console>
    <input type='mouse' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' keymap='en-us'/>
    <video>
      <model type='cirrus' vram='9216' heads='1'/>
    </video>
  </devices>
</domain>
EOF

puts "Connecting to libvirt"
conn = Libvirt::open('qemu:///system')

# create the domain from the XML above.  This actually defines the domain
# and starts it at the same time.  Domains created this way are transient;
# once they are stopped, libvirt forgets about them.
puts "Creating transient domain ruby-libvirt-tester"
dom = conn.create_domain_xml(new_dom_xml)

# stop the domain.  Because this is a transient domain, libvirt will no longer
# remember this domain after this call
puts "Destroying transient domain ruby-libvirt-tester"
dom.destroy

# define the domain from the XML above.  Note that defining a domain just
# makes libvirt aware of the domain as a persistent entity; it does not start
# or otherwise change the domain
puts "Defining permanent domain ruby-libvirt-tester"
dom = conn.define_domain_xml(new_dom_xml)

# start the domain
puts "Starting permanent domain ruby-libvirt-tester"
dom.create

sleep 2

begin
  # undefine the domain.  Oops!  This raises an exception since it is not legal
  # to undefine a running domain
  puts "Trying to undefine running domain ruby-libvirt-tester"
  dom.undefine
rescue => e
  puts e
end

# stop the domain.  Because this is a permanent domain, libvirt will stop the
# execution of the domain, but will remember the domain for next time
puts "Destroying running domain ruby-libvirt-tester"
dom.destroy

# undefine the domain; the dom object is no longer valid after this operation
puts "Undefining permanent domain ruby-libvirt-tester"
dom.undefine

conn.close
