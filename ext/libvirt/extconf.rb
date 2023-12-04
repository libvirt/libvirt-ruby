require 'mkmf'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']
RbConfig::MAKEFILE_CONFIG['CCDLFLAGS'] = ENV['CFLAGS'] if ENV['CFLAGS']
RbConfig::MAKEFILE_CONFIG['EXTDLDFLAGS'] = ENV['CFLAGS'] if ENV['CFLAGS']

extension_name = '_libvirt'

unless pkg_config("libvirt")
  raise "libvirt library not found in default locations"
end

unless pkg_config("libvirt-qemu")
  raise "libvirt library not found in default locations"
end

unless pkg_config("libvirt-lxc")
  raise "libvirt library not found in default locations"
end

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

libvirt_funcs.each { |f| have_func(f, "libvirt/libvirt.h") }
libvirt_qemu_funcs.each { |f| have_func(f, "libvirt/libvirt-qemu.h") }
libvirt_lxc_funcs.each{ |f| have_func(f, "libvirt/libvirt-lxc.h") }

create_header
create_makefile(extension_name)
