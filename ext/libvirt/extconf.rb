require 'mkmf'

def have_libvirt_funcs(funcs)
    funcs.each { |f| have_func(f, "libvirt/libvirt.h") }
end

def have_libvirt_types(types)
    types.each { |t| have_type(t, "libvirt/libvirt.h") }
end

def have_const(const, headers = nil, opt = "", &b)
  checking_for checking_message(const, headers, opt) do
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
                ]

have_libvirt_types(libvirt_types)
have_libvirt_funcs(libvirt_funcs)

have_const('VIR_MIGRATE_LIVE', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_PEER2PEER', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_TUNNELLED', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_PERSIST_DEST', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_UNDEFINE_SOURCE', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_PAUSED', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_NON_SHARED_DISK', "libvirt/libvirt.h")
have_const('VIR_MIGRATE_NON_SHARED_INC', "libvirt/libvirt.h")
have_const('VIR_DOMAIN_XML_UPDATE_CPU', "libvirt/libvirt.h")
have_const('VIR_MEMORY_PHYSICAL', "libvirt/libvirt.h")
have_const('VIR_DOMAIN_START_PAUSED', "libvirt/libvirt.h")
have_const('VIR_DUMP_CRASH', "libvirt/libvirt.h")
have_const('VIR_DUMP_LIVE', "libvirt/libvirt.h")
have_const('VIR_DOMAIN_DEVICE_MODIFY_CURRENT', "libvirt/libvirt.h")
have_const('VIR_DOMAIN_DEVICE_MODIFY_CONFIG', "libvirt/libvirt.h")
have_const('VIR_INTERFACE_XML_INACTIVE', "libvirt/libvirt.h")
have_const('VIR_STORAGE_POOL_INACCESSIBLE', "libvirt/libvirt.h")

create_header
create_makefile(extension_name)
