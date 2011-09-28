require 'mkmf'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']

def have_libvirt_funcs(funcs)
    funcs.each { |f| have_func(f, "libvirt/libvirt.h") }
end

def have_libvirt_types(types)
    types.each { |t| have_type(t, "libvirt/libvirt.h") }
end

# older mkmf does not have checking_message, so implement our own here
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
  consts.each { |c| have_const(c, ["libvirt/libvirt.h", "libvirt/virterror.h"]) }
end

extension_name = '_libvirt'

# this is a poor-man's dir_config, but is a bit more flexible.  In particular,
# it allows you to specify the exact location of the libvirt.so, as opposed
# to requiring a lib/ subdirectory.  Note that due to the way include files
# are done within ruby-libvirt, the libvirt header file(s) must be in a libvirt/
# subdirectory.  Also note that if specifying the include directory, the
# location of the library must also be specified.  Finally, note that if neither
# the include nor the library are specified, the build will attempt to use
# pkg-config to discover this information.
#
# Taking all of the above rules into account, the valid options are either:
#   $ ruby extconf.rb --with-libvirt-include=/home/clalance/libvirt/include \
#          --with-libvirt-lib=/home/clalance/libvirt/src/.libs
#
# To specify the location of the include files and the library, or:
#   $ ruby extconf.rb
#
# to attempt to use pkg-config to do it automatically from the system files.
include = with_config("libvirt-include")
lib = with_config("libvirt-lib")
if include and lib
  $LIBPATH = [lib] | $LIBPATH
  $CPPFLAGS += "-I" + include
  have_library("virt", "virConnectOpen", "libvirt/libvirt.h")

  # if we are using custom libvirt libraries, we have to suppress the default
  # library path so have_func() only picks up the custom ones, not the installed
  # ones
  $DEFLIBPATH = []
elsif (include and not lib) or (not include and lib)
  raise "Must specify both --with-libvirt-include and --with-libvirt-lib, or neither"
else
  unless pkg_config("libvirt")
    raise "libvirt library not found in default locations"
  end
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
                  'virStreamPtr',
                  'virTypedParameterPtr',
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
                  'virDomainSetVcpusFlags',
                  'virDomainGetVcpusFlags',
                  'virConnectDomainEventRegisterAny',
                  'virConnectDomainEventRegister',
                  'virDomainBlockPeek',
                  'virDomainMemoryPeek',
                  'virConnectOpenAuth',
                  'virEventRegisterImpl',
                  'virDomainIsUpdated',
                  'virDomainSetMemoryParameters',
                  'virConnectGetSysinfo',
                  'virDomainSetBlkioParameters',
                  'virDomainSetMemoryFlags',
                  'virDomainGetState',
                  'virDomainOpenConsole',
                  'virDomainMigrate2',
                  'virDomainScreenshot',
                  'virInterfaceChangeBegin',
                  'virStorageVolDownload',
                  'virDomainInjectNMI',
                  'virDomainGetControlInfo',
                  'virDomainMigrateGetMaxSpeed',
                  'virNodeGetCPUStats',
                  'virNodeGetMemoryStats',
                  'virDomainDestroyFlags',
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
                   'VIR_DOMAIN_DEVICE_MODIFY_LIVE',
                   'VIR_DOMAIN_DEVICE_MODIFY_CONFIG',
                   'VIR_DOMAIN_DEVICE_MODIFY_FORCE',
                   'VIR_INTERFACE_XML_INACTIVE',
                   'VIR_STORAGE_POOL_INACCESSIBLE',
                   'VIR_DOMAIN_EVENT_DEFINED',
                   'VIR_DOMAIN_EVENT_STARTED',
                   'VIR_DOMAIN_EVENT_SUSPENDED_IOERROR',
                   'VIR_DOMAIN_EVENT_ID_WATCHDOG',
                   'VIR_DOMAIN_EVENT_ID_IO_ERROR',
                   'VIR_DOMAIN_EVENT_ID_GRAPHICS',
                   'VIR_DOMAIN_EVENT_ID_REBOOT',
                   'VIR_DOMAIN_EVENT_ID_RTC_CHANGE',
                   'VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON',
                   'VIR_FROM_VMWARE',
                   'VIR_FROM_AUDIT',
                   'VIR_FROM_SYSINFO',
                   'VIR_FROM_STREAMS',
                   'VIR_FROM_XENAPI',
                   'VIR_FROM_HOOK',
                   'VIR_ERR_HOOK_SCRIPT_FAILED',
                   'VIR_ERR_MIGRATE_PERSIST_FAILED',
                   'VIR_ERR_OPERATION_TIMEOUT',
                   'VIR_ERR_CONFIG_UNSUPPORTED',
                   'VIR_FROM_XENXM',
                   'VIR_ERR_OPERATION_INVALID',
                   'VIR_ERR_NO_SECURITY_MODEL',
                   'VIR_ERR_AUTH_FAILED',
                   'VIR_FROM_PHYP',
                   'VIR_FROM_ESX',
                   'VIR_FROM_ONE',
                   'VIR_FROM_VBOX',
                   'VIR_FROM_LXC',
                   'VIR_FROM_UML',
                   'VIR_FROM_NETWORK',
                   'VIR_FROM_DOMAIN',
                   'VIR_FROM_STATS_LINUX',
                   'VIR_FROM_XEN_INOTIFY',
                   'VIR_FROM_SECURITY',
                   'VIR_DOMAIN_AFFECT_CURRENT',
                   'VIR_DOMAIN_MEM_CURRENT',
                   'VIR_DOMAIN_EVENT_ID_CONTROL_ERROR',
                   'VIR_DOMAIN_PAUSED_SHUTTING_DOWN',
                   'VIR_DOMAIN_START_AUTODESTROY',
                   'VIR_DOMAIN_START_BYPASS_CACHE',
                   'VIR_DOMAIN_START_FORCE_BOOT',
                   'VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON',
                   'VIR_DUMP_BYPASS_CACHE',
                   'VIR_MIGRATE_CHANGE_PROTECTION',
                 ]

have_libvirt_types(libvirt_types)
have_libvirt_funcs(libvirt_funcs)
if find_header("libvirt/libvirt-qemu.h")
  have_library("virt-qemu", "virDomainQemuMonitorCommand")
  have_func("virDomainQemuMonitorCommand", "libvirt/libvirt-qemu.h")
end

have_libvirt_consts(libvirt_consts)

create_header
create_makefile(extension_name)
