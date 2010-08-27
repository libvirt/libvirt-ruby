#!/usr/bin/ruby

# Test the domain methods the bindings support

require 'libvirt'

conn = Libvirt::open
puts "Number of Domains: #{conn.num_of_domains}"
puts "Number of Defined Domains: #{conn.num_of_defined_domains}"
puts "Domain Create:"
new_dom_xml = <<EOF
<domain type='kvm'>
  <name>ruby-libvirt-tester</name>
  <uuid>93a5c045-6457-2c09-e56f-927cdf34e17a</uuid>
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
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/libvirt/images/ruby-libvirt-test.dsk'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:00:60:3c:95'/>
      <source bridge='br0'/>
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

newdom = conn.define_domain_xml(new_dom_xml)
newdom.undefine

`dd if=/dev/zero of=/var/lib/libvirt/images/ruby-libvirt-test.dsk bs=1 count=1 seek=5G`

newdom = conn.create_domain_linux(new_dom_xml)
info = newdom.info
if info.state != Libvirt::Domain::RUNNING
  raise "Failed to start new domain"
end
sleep 2
newdom.destroy

newdom = conn.define_domain_xml(new_dom_xml)
info = newdom.info
newdom.create
sleep 2
newdom.suspend
sleep 2
newdom.resume
sleep 2
#newdom.save('/var/lib/libvirt/images/ruby-libvirt-test.save')
#sleep 2
#newdom.restore
ifinfo = newdom.ifinfo('rl556')
puts "New Domain Interface Information rl556:"
puts " rx_bytes:   #{ifinfo.rx_bytes}"
puts " rx_packets: #{ifinfo.rx_packets}"
puts " rx_errs:    #{ifinfo.rx_errs}"
puts " rx_drop:    #{ifinfo.rx_drop}"
puts " tx_bytes:   #{ifinfo.tx_bytes}"
puts " tx_packets: #{ifinfo.tx_packets}"
puts " tx_errs:    #{ifinfo.tx_errs}"
puts " tx_drop:    #{ifinfo.tx_drop}"
seclabel = newdom.security_label
puts "New Domain Security Label:"
puts " Label:     #{seclabel.label}"
puts " Enforcing: #{seclabel.enforcing}"
blockstat = newdom.block_stats('vda')
puts "New Domain Block Stats vda:"
puts " rd_req: #{blockstat.rd_req}"
puts " rd_bytes: #{blockstat.rd_bytes}"
puts " wr_req: #{blockstat.wr_req}"
puts " wr_bytes: #{blockstat.wr_bytes}"
puts " errs: #{blockstat.errs}"
memstat = newdom.memory_stats
memstat = newdom.memory_stats(0)
puts "New Domain Memory Stats:"
memstat.each do |stat|
  puts " #{stat.tag}: #{stat.val}"
end
blockinfo = newdom.blockinfo('/var/lib/libvirt/images/ruby-libvirt-test.dsk')
blockinfo = newdom.blockinfo('/var/lib/libvirt/images/ruby-libvirt-test.dsk', 0)
puts "New Domain Block Info vda:"
puts " Capacity:   #{blockinfo.capacity}"
puts " Allocation: #{blockinfo.allocation}"
puts " Physical:   #{blockinfo.physical}"
blockpeek = newdom.block_peek('/var/lib/libvirt/images/ruby-libvirt-test.dsk',
                              0, 512)
blockpeek = newdom.block_peek('/var/lib/libvirt/images/ruby-libvirt-test.dsk',
                              0, 512, 0)
# 2010-06-30: memory_peek is broken on RHEL-6 libvirt; fixed in upstream
#mempeek = newdom.memory_peek(0, 512, Libvirt::Domain::MEMORY_VIRTUAL)
type = newdom.scheduler_type
params = newdom.scheduler_parameters
puts "New Domain Scheduler:"
puts " Type:          #{type[0]}"
puts " Number Params: #{type[1]}"
puts " Params:"
params.each_pair do |k,v|
  puts "  #{k}: #{v}"
end


defined = conn.list_defined_domains
running = conn.list_domains

(defined+running).each do |dom|
  if defined.include? dom
    domain = conn.lookup_domain_by_name(dom)
  elsif running.include? dom
    domain = conn.lookup_domain_by_id(dom)
  end
  dom2 = conn.lookup_domain_by_uuid(domain.uuid)
  puts "Domain #{domain.name}:"
  puts " UUID:        #{domain.uuid}"
  puts " ID:          #{domain.id}"
  puts " OS Type:     #{domain.os_type}"
  puts " Max Memory:  #{domain.max_memory}"
  puts " Max VCPUs:   #{domain.max_vcpus}"
  puts " Persistent?: #{domain.persistent?}"
  puts " Active?:     #{domain.active?}"
  info = domain.info
  puts " Info:"
  puts "  State:        #{info.state}"
  puts "  Max Memory:   #{info.max_mem}"
  puts "  Memory:       #{info.memory}"
  puts "  Number VCPUs: #{info.nr_virt_cpu}"
  puts "  CPU Time:     #{info.cpu_time}"
  puts " Snapshots:"
  puts "  Number: #{domain.num_of_snapshots}"
  puts "  Has Current?: #{domain.has_current_snapshot?}"
  domain.list_snapshots.each do |snapname|
    snap = domain.lookup_snapshot_by_name(snapname)
    puts "  Snapshot #{snapname}"
    puts snap.xml_desc
  end
  domain.xml_desc
  puts " XML:"
  puts domain.xml_desc(0)
end

newdom.destroy
newdom.undefine

conn.close
