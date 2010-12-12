require 'mkmf'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']

def have_libvirt_funcs(funcs)
    funcs.each { |f| have_func(f, "libvirt/libvirt.h") }
end

def have_libvirt_types(types)
    types.each { |t| have_type(t, "libvirt/libvirt.h") }
end

def libvirt_checking_message(target, place = nil, opt = nil)
  [["in", place], ["with", opt]].inject("#{target}") do |msg, (pre, noun)|
    if noun
      [[:to_str], [:join, ","], [:to_s]].each do |meth, *args|
        if noun.respond_to?(meth)
          break noun = noun.send(meth, *args)
        end
      end
      msg << " #{pre} #{noun}" unless noun.empty?
    end
    msg
  end
end

def have_const(const, headers = nil, opt = "", &b)
  checking_for libvirt_checking_message(const, headers, opt) do
    headers = cpp_include(headers)
    if try_compile(<<"SRC", opt, &b)
#{COMMON_HEADERS}
#{headers}
/*top*/
static int t = #{const};
SRC
      $defs.push(format("-DHAVE_CONST_%s", const.strip.upcase.tr_s("^A-Z0-9_", "_")))
      true
    else
      false
    end
  end
end

def have_libvirt_consts(consts)
  consts.each { |c| have_const(c, "libvirt/libvirt.h") }
end

extension_name = '_libvirt'

dir_config(extension_name)

unless pkg_config("libvirt")
    raise "libvirt not found"
end

libvirt_types = [ 'virNetworkPtr',
                  'virStoragePoolPtr',
                  'virStorageVolPtr',
                  'virSecretPtr',
                  'virNWFilterPtr',
                  'virInterfacePtr',
                  'virDomainBlockInfoPtr',
                  'virDomainMemoryStatPtr',
                  'virDomainSnapshotPtr',
                  'virDomainJobInfoPtr',
                  'virNodeDevicePtr',
                ]

libvirt_funcs = [ 'virStorageVolWipe',
                  'virStoragePoolIsActive',
                  'virStoragePoolIsPersistent',
                  'virStorageVolCreateXMLFrom',
                  'virConnectGetLibVersion',
                  'virConnectIsEncrypted',
                  'virConnectIsSecure',
                  'virNetworkIsActive',
                  'virNetworkIsPersistent',
                  'virNodeDeviceCreateXML',
                  'virNodeDeviceDestroy',
                  'virInterfaceIsActive',
                  'virDomainMigrateToURI',
                  'virDomainMigrateSetMaxDowntime',
                  'virDomainManagedSave',
                  'virDomainIsActive',
                  'virDomainIsPersistent',
                  'virConnectDomainXMLFromNative',
                  'virConnectDomainXMLToNative',
                  'virDomainCreateWithFlags',
                  'virDomainAttachDeviceFlags',
                  'virDomainDetachDeviceFlags',
                  'virDomainUpdateDeviceFlags',
                  'virNodeGetSecurityModel',
                  'virDomainCreateXML',
                  'virDomainGetSecurityLabel',
                  'virConnectCompareCPU',
                  'virConnectBaselineCPU',
                ]

libvirt_consts = [ 'VIR_MIGRATE_LIVE',
                   'VIR_MIGRATE_PEER2PEER',
                   'VIR_MIGRATE_TUNNELLED',
                   'VIR_MIGRATE_PERSIST_DEST',
                   'VIR_MIGRATE_UNDEFINE_SOURCE',
                   'VIR_MIGRATE_PAUSED',
                   'VIR_MIGRATE_NON_SHARED_DISK',
                   'VIR_MIGRATE_NON_SHARED_INC',
                   'VIR_DOMAIN_XML_UPDATE_CPU',
                   'VIR_MEMORY_PHYSICAL',
                   'VIR_DOMAIN_START_PAUSED',
                   'VIR_DUMP_CRASH',
                   'VIR_DUMP_LIVE',
                   'VIR_DOMAIN_DEVICE_MODIFY_CURRENT',
                   'VIR_DOMAIN_DEVICE_MODIFY_CONFIG',
                   'VIR_DOMAIN_DEVICE_MODIFY_FORCE',
                   'VIR_INTERFACE_XML_INACTIVE',
                   'VIR_STORAGE_POOL_INACCESSIBLE',
                 ]

have_libvirt_types(libvirt_types)
have_libvirt_funcs(libvirt_funcs)
if find_header("libvirt/libvirt-qemu.h")
    have_func("virDomainQemuMonitorCommand", "libvirt/libvirt-qemu.h")
end

have_libvirt_consts(libvirt_consts)

create_header
create_makefile(extension_name)
