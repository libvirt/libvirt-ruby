require 'mkmf'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']
RbConfig::MAKEFILE_CONFIG['CCDLFLAGS'] = ENV['CFLAGS'] if ENV['CFLAGS']
RbConfig::MAKEFILE_CONFIG['EXTDLDFLAGS'] = ENV['CFLAGS'] if ENV['CFLAGS']

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
  $CPPFLAGS += " -I" + include
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
                  'virDomainBlockJobInfoPtr',
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
                  'virDomainSaveFlags',
                  'virDomainSaveImageGetXMLDesc',
                  'virDomainSendKey',
                  'virNetworkUpdate',
                  'virNodeSuspendForDuration',
                  'virNodeGetMemoryParameters',
                  'virNodeGetCPUMap',
                  'virDomainUndefineFlags',
                  'virDomainPinVcpuFlags',
                  'virDomainGetVcpuPinInfo',
                  'virDomainSnapshotGetName',
                  'virConnectSetKeepAlive',
                  'virDomainReset',
                  'virDomainShutdownFlags',
                  'virDomainGetHostname',
                  'virDomainGetMetadata',
                  'virDomainSetMetadata',
                  'virConnectListAllDomains',
                  'virConnectListAllNetworks',
                  'virConnectListAllInterfaces',
                  'virConnectListAllSecrets',
                  'virConnectListAllNodeDevices',
                  'virConnectListAllStoragePools',
                  'virConnectListAllNWFilters',
                  'virConnectIsAlive',
                  'virNodeDeviceDetachFlags',
                  'virDomainSendProcessSignal',
                  'virDomainListAllSnapshots',
                  'virDomainSnapshotNumChildren',
                  'virDomainSnapshotListChildrenNames',
                  'virDomainSnapshotListAllChildren',
                  'virDomainSnapshotGetParent',
                  'virDomainSnapshotIsCurrent',
                  'virDomainSnapshotHasMetadata',
                  'virDomainSetMemoryStatsPeriod',
                  'virDomainFSTrim',
                  'virDomainBlockRebase',
                  'virDomainOpenChannel',
                  'virNodeDeviceLookupSCSIHostByWWN',
                  'virStorageVolWipePattern',
                  'virStoragePoolListAllVolumes',
                  'virDomainCreateWithFiles',
                  'virDomainCreateXMLWithFiles',
                  'virDomainOpenGraphics',
                  'virStorageVolResize',
                  'virDomainPMWakeup',
                  'virDomainBlockResize',
                  'virDomainPMSuspendForDuration',
                  'virDomainMigrateGetCompressionCache',
                  'virDomainMigrateSetCompressionCache',
                  'virDomainGetDiskErrors',
                  'virDomainGetEmulatorPinInfo',
                  'virDomainPinEmulator',
                  'virDomainGetSecurityLabelList',
                  'virDomainGetJobStats',
                  'virDomainGetBlockIoTune',
                  'virDomainSetBlockIoTune',
                  'virDomainBlockCommit',
                  'virDomainBlockPull',
                  'virDomainBlockJobSetSpeed',
                  'virDomainGetBlockJobInfo',
                  'virDomainBlockJobAbort',
                  'virDomainGetInterfaceParameters',
                  'virDomainBlockStatsFlags',
                  'virDomainGetNumaParameters',
                  'virConnectGetCPUModelNames',
                  'virDomainMigrate3',
                  'virDomainGetCPUStats',
                  'virNetworkGetDHCPLeases',
                  'virNodeAllocPages',
                  'virDomainGetTime',
                  'virDomainSetTime',
                  'virConnectGetDomainCapabilities',
                  'virDomainCoreDumpWithFormat',
                  'virDomainFSFreeze',
                  'virDomainFSThaw',
                  'virDomainGetFSInfo',
                  'virNodeGetFreePages',
                  'virDomainDefineXMLFlags',
                  'virDomainRename',
                  'virDomainSetUserPassword',
                ]

libvirt_qemu_funcs = [ 'virDomainQemuMonitorCommand',
                       'virDomainQemuAttach',
                       'virDomainQemuAgentCommand'
                     ]

libvirt_lxc_funcs = [
                     'virDomainLxcOpenNamespace',
                     'virDomainLxcEnterNamespace',
                     'virDomainLxcEnterSecurityLabel',
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
                   'VIR_DOMAIN_SAVE_BYPASS_CACHE',
                   'VIR_DOMAIN_SAVE_RUNNING',
                   'VIR_DOMAIN_SAVE_PAUSED',
                   'VIR_NETWORK_UPDATE_COMMAND_NONE',
                   'VIR_NETWORK_UPDATE_COMMAND_MODIFY',
                   'VIR_NETWORK_UPDATE_COMMAND_DELETE',
                   'VIR_NETWORK_UPDATE_COMMAND_ADD_LAST',
                   'VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST',
                   'VIR_NETWORK_SECTION_NONE',
                   'VIR_NETWORK_SECTION_BRIDGE',
                   'VIR_NETWORK_SECTION_DOMAIN',
                   'VIR_NETWORK_SECTION_IP',
                   'VIR_NETWORK_SECTION_IP_DHCP_HOST',
                   'VIR_NETWORK_SECTION_IP_DHCP_RANGE',
                   'VIR_NETWORK_SECTION_FORWARD',
                   'VIR_NETWORK_SECTION_FORWARD_INTERFACE',
                   'VIR_NETWORK_SECTION_FORWARD_PF',
                   'VIR_NETWORK_SECTION_PORTGROUP',
                   'VIR_NETWORK_SECTION_DNS_HOST',
                   'VIR_NETWORK_SECTION_DNS_TXT',
                   'VIR_NETWORK_SECTION_DNS_SRV',
                   'VIR_NETWORK_UPDATE_AFFECT_CURRENT',
                   'VIR_NETWORK_UPDATE_AFFECT_LIVE',
                   'VIR_NETWORK_UPDATE_AFFECT_CONFIG',
                   'VIR_DOMAIN_PMSUSPENDED',
                   'VIR_DOMAIN_RUNNING_WAKEUP',
                   'VIR_DOMAIN_PMSUSPENDED_UNKNOWN',
                   'VIR_DOMAIN_UNDEFINE_MANAGED_SAVE',
                   'VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA',
                   'VIR_DOMAIN_PAUSED_SNAPSHOT',
                   'VIR_DOMAIN_PMSUSPENDED_DISK_UNKNOWN',
                   'VIR_DUMP_RESET',
                   'VIR_DUMP_MEMORY_ONLY',
                   'VIR_DOMAIN_SHUTDOWN_DEFAULT',
                   'VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN',
                   'VIR_DOMAIN_SHUTDOWN_GUEST_AGENT',
                   'VIR_DOMAIN_SHUTDOWN_INITCTL',
                   'VIR_DOMAIN_SHUTDOWN_SIGNAL',
                   'VIR_DOMAIN_REBOOT_DEFAULT',
                   'VIR_DOMAIN_REBOOT_ACPI_POWER_BTN',
                   'VIR_DOMAIN_REBOOT_GUEST_AGENT',
                   'VIR_DOMAIN_REBOOT_INITCTL',
                   'VIR_DOMAIN_REBOOT_SIGNAL',
                   'VIR_DOMAIN_DESTROY_DEFAULT',
                   'VIR_DOMAIN_DESTROY_GRACEFUL',
                   'VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST',
                   'VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE',
                   'VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE',
                   'VIR_DOMAIN_SNAPSHOT_CREATE_LIVE',
                   'VIR_DOMAIN_BLOCK_REBASE_SHALLOW',
                   'VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT',
                   'VIR_DOMAIN_BLOCK_REBASE_COPY_RAW',
                   'VIR_DOMAIN_BLOCK_REBASE_COPY',
                   'VIR_DOMAIN_CHANNEL_FORCE',
                   'VIR_DOMAIN_CONSOLE_FORCE',
                   'VIR_DOMAIN_CONSOLE_SAFE',
                   'VIR_STORAGE_VOL_WIPE_ALG_ZERO',
                   'VIR_STORAGE_VOL_WIPE_ALG_NNSA',
                   'VIR_STORAGE_VOL_WIPE_ALG_DOD',
                   'VIR_STORAGE_VOL_WIPE_ALG_BSI',
                   'VIR_STORAGE_VOL_WIPE_ALG_GUTMANN',
                   'VIR_STORAGE_VOL_WIPE_ALG_SCHNEIER',
                   'VIR_STORAGE_VOL_WIPE_ALG_PFITZNER7',
                   'VIR_STORAGE_VOL_WIPE_ALG_PFITZNER33',
                   'VIR_STORAGE_VOL_WIPE_ALG_RANDOM',
                   'VIR_DOMAIN_BLOCK_RESIZE_BYTES',
                   'VIR_DOMAIN_MEMORY_STAT_RSS',
                   'VIR_MIGRATE_UNSAFE',
                   'VIR_MIGRATE_OFFLINE',
                   'VIR_MIGRATE_COMPRESSED',
                   'VIR_MIGRATE_ABORT_ON_ERROR',
                   'VIR_CONNECT_NO_ALIASES',
                   'VIR_DOMAIN_XML_MIGRATABLE',
                   'VIR_NETWORK_XML_INACTIVE',
                   'VIR_STORAGE_VOL_DIR',
                   'VIR_STORAGE_VOL_NETWORK',
                   'VIR_STORAGE_XML_INACTIVE',
                   'VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA',
                   'VIR_SECRET_USAGE_TYPE_CEPH',
                   'VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING',
                   'VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED',
                   'VIR_DOMAIN_SNAPSHOT_REVERT_FORCE',
                   'VIR_SECRET_USAGE_TYPE_ISCSI',
                   'VIR_DOMAIN_NOSTATE_UNKNOWN',
                   'VIR_DOMAIN_RUNNING_CRASHED',
                   'VIR_DOMAIN_PAUSED_CRASHED',
                   'VIR_DOMAIN_CRASHED_PANICKED',
                   'VIR_NODE_CPU_STATS_ALL_CPUS',
                   'VIR_NODE_MEMORY_STATS_ALL_CELLS',
                   'VIR_DOMAIN_VCPU_CURRENT',
                   'VIR_DOMAIN_VCPU_GUEST',
                   'VIR_NETWORK_UPDATE_COMMAND_DELETE',
                   'VIR_STORAGE_POOL_BUILD_NO_OVERWRITE',
                   'VIR_STORAGE_POOL_BUILD_OVERWRITE',
                   'VIR_KEYCODE_SET_LINUX',
                   'VIR_KEYCODE_SET_XT',
                   'VIR_KEYCODE_SET_ATSET1',
                   'VIR_KEYCODE_SET_ATSET2',
                   'VIR_KEYCODE_SET_ATSET3',
                   'VIR_KEYCODE_SET_OSX',
                   'VIR_KEYCODE_SET_XT_KBD',
                   'VIR_KEYCODE_SET_USB',
                   'VIR_KEYCODE_SET_WIN32',
                   'VIR_KEYCODE_SET_RFB',
                   'VIR_DOMAIN_EVENT_SHUTDOWN',
                   'VIR_DOMAIN_EVENT_PMSUSPENDED',
                   'VIR_DOMAIN_EVENT_CRASHED',
                   'VIR_DOMAIN_EVENT_STARTED_WAKEUP',
                   'VIR_DOMAIN_EVENT_SUSPENDED_RESTORED',
                   'VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT',
                   'VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR',
                   'VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT',
                   'VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED',
                   'VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY',
                   'VIR_DOMAIN_EVENT_PMSUSPENDED_DISK',
                   'VIR_DOMAIN_EVENT_CRASHED_PANICKED',
                   'VIR_SECRET_USAGE_TYPE_NONE',
                   'VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES',
                   'VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY',
                   'VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY',
                   'VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_UNIX',
                   'VIR_DOMAIN_BLOCK_COMMIT_SHALLOW',
                   'VIR_DOMAIN_BLOCK_COMMIT_DELETE',
                   'VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN',
                   'VIR_DOMAIN_BLOCK_JOB_TYPE_PULL',
                   'VIR_DOMAIN_BLOCK_JOB_TYPE_COPY',
                   'VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT',
                   'VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC',
                   'VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT',
                   'VIR_DOMAIN_BLOCK_JOB_COMPLETED',
                   'VIR_DOMAIN_BLOCK_JOB_FAILED',
                   'VIR_DOMAIN_BLOCK_JOB_CANCELED',
                   'VIR_DOMAIN_BLOCK_JOB_READY',
                   'VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES',
                   'VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC',
                   'VIR_MIGRATE_PARAM_LISTEN_ADDRESS',
                   'VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD',
                   'VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA',
                   'VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT',
                   'VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE',
                   'VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC',
                   'VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER',
                   'VIR_CONNECT_LIST_STORAGE_POOLS_ZFS',
                   'VIR_STORAGE_VOL_NETDIR',
                   'VIR_IP_ADDR_TYPE_IPV4',
                   'VIR_IP_ADDR_TYPE_IPV6',
                   'VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE',
                   'VIR_DOMAIN_UNDEFINE_NVRAM',
                   'VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT',
                   'VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES',
                   'VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES',
                   'VIR_DOMAIN_BLOCK_COMMIT_ACTIVE',
                   'VIR_DOMAIN_BLOCK_COMMIT_RELATIVE',
                   'VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES',
                   'VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC',
                   'VIR_STORAGE_POOL_CREATE_NORMAL',
                   'VIR_STORAGE_POOL_CREATE_WITH_BUILD',
                   'VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE',
                   'VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE',
                   'VIR_STORAGE_VOL_CREATE_REFLINK',
                   'VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS',
                   'VIR_DOMAIN_QEMU_AGENT_COMMAND_SHUTDOWN',
                   'VIR_DOMAIN_DEFINE_VALIDATE',
                   'VIR_DOMAIN_PASSWORD_ENCRYPTED',
                   'VIR_DOMAIN_TIME_SYNC',
                 ]

virterror_consts = [
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
                    'VIR_DOMAIN_CORE_DUMP_FORMAT_RAW',
                    'VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_ZLIB',
                    'VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_LZO',
                    'VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_SNAPPY',
                    'VIR_MIGRATE_AUTO_CONVERGE',
                    'VIR_MIGRATE_RDMA_PIN_ALL',
                    'VIR_DOMAIN_SHUTDOWN_PARAVIRT',
                    'VIR_DOMAIN_REBOOT_PARAVIRT',
                   ]

libvirt_qemu_consts = [
                       'VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK',
                       'VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT',
                       'VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT',
                       'VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT',
                       'VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP',
                      ]

libvirt_types.each { |t| have_type(t, "libvirt/libvirt.h") }
libvirt_funcs.each { |f| have_func(f, "libvirt/libvirt.h") }
libvirt_consts.each { |c| have_const(c, ["libvirt/libvirt.h"]) }
virterror_consts.each { |c| have_const(c, ["libvirt/virterror.h"]) }
if find_header("libvirt/libvirt-qemu.h")
  have_library("virt-qemu", "virDomainQemuMonitorCommand")
  libvirt_qemu_funcs.each { |f| have_func(f, "libvirt/libvirt-qemu.h") }
  libvirt_qemu_consts.each { |c| have_const(c, ["libvirt/libvirt-qemu.h"]) }
end

if find_header("libvirt/libvirt-lxc.h")
  have_library("virt-lxc", "virDomainLxcOpenNamespace")
  libvirt_lxc_funcs.each{ |f| have_func(f, "libvirt/libvirt-lxc.h") }
end

create_header
create_makefile(extension_name)
