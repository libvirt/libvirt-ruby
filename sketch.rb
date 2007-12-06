module Libvirt

    #
    # Version info
    #
    VERSION = "0.3.2"

    # int virGetVersion	(unsigned long *libVer,
    #    const char *type,
    # unsigned long *typeVer);
    def version(type)
        return [:libVer, :typeVer]
    end

    # virConnectPtr virConnectOpen(const char *name);
    def open(name)
        Connect.new(name)
    end
       
    # virConnectPtr virConnectOpenReadOnly (const char *name);
    def openReadOnly(name)
        Connect.new(name)
    end

    # typedef struct _virConnect virConnect;
    class Connect
        # Connection and disconnections to the Hypervisor

        # int virConnectClose(virConnectPtr conn);
        def close
            true
        end

        # const char *virConnectGetType(virConnectPtr conn);
        def type
            return "xen"
        end

        # int virConnectGetVersion(virConnectPtr conn,
	#                          unsigned long *hvVer);
        def version
            "x.y.z"
        end
        
        # char *virConnectGetHostname(virConnectPtr conn);
        def hostname
            "hv.example.com"
        end
        
        # char *virConnectGetURI(virConnectPtr conn);
        def uri
            "qemu:///system"
        end

        # Capabilities of the connection / driver.
        # int virConnectGetMaxVcpus(virConnectPtr conn,
	#                           const char *type);
        def max_vcpus(type)
            5
        end
        
        # int virNodeGetInfo(virConnectPtr conn,
        #                    virNodeInfoPtr info);
        def node_info
            NodeInfo.new()
        end

        # char *virConnectGetCapabilities(virConnectPtr conn);
        def capabilities
            "<capabilities> .. </capabilities>"
        end

        # int virConnectListDomains(virConnectPtr conn,
        #       int *ids, int maxids);
        def list_domains
            [3, 4, 5]
        end

        # int virConnectNumOfDomains(virConnectPtr conn);
        def num_of_domains
            3
        end

        # int virConnectNumOfDefinedDomains(virConnectPtr conn);
        def num_of_defined_domains; 10; end

        # int virConnectListDefinedDomains (virConnectPtr conn,
        #                                   char **const names,
        #                                   int maxnames);
        def list_defined_domains; [ "dom1", "dom2", "domN" ]; end

        # int virConnectNumOfNetworks(virConnectPtr conn);
        def num_of_networks; 10; end

        # int virConnectListNetworks(virConnectPtr conn,
        #                            char **const names,
        #                            int maxnames);
        def list_networks; [ "net1", "net2", "net3" ]; end

        # int virConnectNumOfDefinedNetworks(virConnectPtr conn);
        def num_of_defined_networks; 20; end

        # int virConnectListDefinedNetworks(virConnectPtr conn,
        #                                   char **const names,
        #                                   int maxnames);
        def list_defined_networks; [ "net1", "net2", "net3" ]; end

        #
        # Domain creation and destruction
        #

        # virDomainPtr virDomainCreateLinux(virConnectPtr conn,
        #                                   const char *xmlDesc,
        #                                   unsigned int flags);
        def create_domain_linux(xml_desc, flags)
            Domain.new()
        end

        # virDomainPtr virDomainLookupByName(virConnectPtr conn,
        #                                    const char *name);
        def lookup_domain_by_name(name)
            Domain.new()
        end

        # virDomainPtr virDomainLookupByID(virConnectPtr conn,
        #                                  int id);
        def lookup_domain_by_id(id)
            Domain.new()
        end

        # virDomainPtr virDomainLookupByUUID(virConnectPtr conn,
        #                                    const unsigned char *uuid);
        # Not implemented
        # virDomainPtr virDomainLookupByUUIDString(virConnectPtr conn,
        #                                          const char *uuid);
        def lookup_domain_by_uuid(uuid)
            Domain.new()
        end

        #
        # defined but not running domains
        #
        
        # virDomainPtr virDomainDefineXML(virConnectPtr conn,
        #                                 const char *xml);
        def define_domain_xml(xml); Domain.new(); end

        #
        # Lookup network by name or uuid
        #
        # virNetworkPtr	virNetworkLookupByName(virConnectPtr conn,
        #                                      const char *name);
        def lookup_network_by_name(conn, name); Network.new(); end

        # virNetworkPtr	virNetworkLookupByUUID(virConnectPtr conn,
        #                                      const unsigned char *uuid);
        # virNetworkPtr	virNetworkLookupByUUIDString(virConnectPtr conn,
        #                                      const char *uuid);
        def lookup_network_by_uuid(conn, uuid); Network.new(); end

        # virNetworkPtr	virNetworkCreateXML(virConnectPtr conn,
        #                                   const char *xmlDesc);
        def create_network_xml(conn, xml_desc); Netowrk.new(); end

        # virNetworkPtr	virNetworkDefineXML(virConnectPtr conn,
        #                                   const char *xmlDesc);
        def define_network_xml(conn, xml_desc); Network.new(); end

    end

    # typedef struct _virDomain virDomain;
    class Domain
        # typedef enum virDomainState
        # Maybe in a separate module ?
        NOSTATE	= 0
        RUNNING	= 1
        BLOCKED	= 2
        PAUSED	= 3
        SHUTDOWN= 4
        SHUTOFF	= 5
        CRASHED = 6

        # typedef enum virDomainRestart
        DESTROY	= 1
        RESTART	= 2
        PRESERVE= 3
        RENAME_RESTART= 4

        # typedef struct _virDomainInfo virDomainInfo;
        class Info
            attr :state, :maxMem, :memory, :nrVirtCpu, :cpuTime
        end

        # typedef enum virDomainCreateFlags
        NONE = 0
        
        # virDomainPtr virDomainMigrate (virDomainPtr domain, 
        #                      virConnectPtr dconn,
	#		       unsigned long flags, const char *dname,
	#		       const char *uri, unsigned long bandwidth);
        def migrate(dconn, flags, dname, uri, bandwidth)
        end

        # virConnectPtr	virDomainGetConnect(virDomainPtr domain);
        # Stored internally, not through the C API
        def connection; Connect.new(); end

        #
        # Lifecycle management
        #
        # int virDomainShutdown(virDomainPtr domain);
        def shutdown; true; end

        # int virDomainReboot(virDomainPtr domain,
        #                     unsigned int flags);
        def reboot; true; end

        # int virDomainDestroy(virDomainPtr domain);
        def destroy; true; end

        # int virDomainFree(virDomainPtr domain);
        # no method, implicit

        # int virDomainSuspend(virDomainPtr domain);
        def suspend; true; end

        # int virDomainResume(virDomainPtr domain);
        def resume; true; end

        # int virDomainSave(virDomainPtr domain,
	#                   const char *to);
        def save(fname); true; end

        # int virDomainRestore(virConnectPtr conn,
        #                      const char *from);
        def self.restore(conn, fname); Domain.new() end

        # int virDomainCoreDump(virDomainPtr domain,
        #                       const char *to,
        # int flags);
        def core_dump(fname, flags); true; end

        # int virDomainGetInfo(virDomainPtr domain,
        #                      virDomainInfoPtr info);
        def info
            Domain::Info.new(self)
        end

        # char * virDomainGetSchedulerType(virDomainPtr domain,
        #                                  int *nparams);
        # FIXME: Deal with schedinfo later

        #
        # Dynamic control of domains
        #
        # const char * virDomainGetName(virDomainPtr domain);
        def name; "foo"; end

        # unsigned int virDomainGetID(virDomainPtr domain);
        def id; 3; end

        # int virDomainGetUUID(virDomainPtr domain,
        #                      unsigned char *uuid);
        # int virDomainGetUUIDString(virDomainPtr domain, 
        #                            char *buf);
        def uuid; "xyz-bla-bla"; end

        # char *virDomainGetOSType(virDomainPtr domain);
        def os_type; "linux"; end

        # unsigned long	virDomainGetMaxMemory(virDomainPtr domain);
        def max_memory; 256*1024; end

        # int virDomainSetMaxMemory(virDomainPtr domain,
        #                           unsigned long memory);
        def max_memory=(v); @max_memory=v; end

        # int virDomainSetMemory(virDomainPtr domain,
        #                        unsigned long memory);
        def memory=(v); @memory=v; end

        # int virDomainGetMaxVcpus(virDomainPtr domain);
        def max_vcpus; 32; end

        #
        # XML domain description
        #

        # char *virDomainGetXMLDesc(virDomainPtr domain,
        #                           int flags);
        def xml_desc; "<domain>..</domain>"; end

        # int virDomainBlockStats(virDomainPtr dom,
        #                         const char *path,
        #                         virDomainBlockStatsPtr stats,
        #                         size_t size);
        # FIXME: Later

        # int virDomainInterfaceStats(virDomainPtr dom,
        #                             const char *path,
        #                             virDomainInterfaceStatsPtr stats,
        #                             size_t size);
        # FIXME: Later

        #
        # defined but not running domains
        #
        
        # int virDomainUndefine(virDomainPtr domain);
        def undefine; true; end

        # int virDomainCreate(virDomainPtr domain);
        def create; true; end

        # int virDomainGetAutostart(virDomainPtr domain,
        #                           int *autostart);
        def autostart; @autostart; end

        # int virDomainSetAutostart(virDomainPtr domain,
        #                           int autostart);
        def autostart=(v); @autostart=v; end
    end

    class NodeInfo
        attr :model, :memory, :cpus, :mhz, :nodes, :sockets, :cores, :threads
    end

    # FIXME: Worry about schedParamter later

    # typedef struct _virNetwork virNetwork;
    class Network
        # virConnectPtr	virNetworkGetConnect(virNetworkPtr network);
        def connection; Connect.new(); end

        # int virNetworkUndefine(virNetworkPtr network);
        def undefine; true; end

        # int virNetworkCreate(virNetworkPtr network);
        def create; true; end

        # int virNetworkDestroy(virNetworkPtr network);
        def destroy; true; end
        
        # int virNetworkFree(virNetworkPtr network);
        # Implicit

        #
        # Network informations
        #

        # const char*virNetworkGetName(virNetworkPtr network);
        def name; "network"; end

        # int virNetworkGetUUID(virNetworkPtr network,
        #                       unsigned char *uuid);
        # int virNetworkGetUUIDString(virNetworkPtr network,
        #                             char *buf);
        def uuid; "xxx"; end

        # char *virNetworkGetXMLDesc(virNetworkPtr network,
        #                            int flags);
        def xml_desc(flags); "<network>..</network>"; end

        # char *virNetworkGetBridgeName (virNetworkPtr network);
        def bridge_name; "br0"; end

        # int virNetworkGetAutostart(virNetworkPtr network,
        #                            int *autostart);
        def autostart; @autostart; end

        # int virNetworkSetAutostart(virNetworkPtr network,
        #                            int autostart);
        def autostart=(v); @autostart=v; end
    end

end

/**
 * virVcpuInfo: structure for information about a virtual CPU in a domain.
 */

typedef enum {
    VIR_VCPU_OFFLINE	= 0,	/* the virtual CPU is offline */
    VIR_VCPU_RUNNING	= 1,	/* the virtual CPU is running */
    VIR_VCPU_BLOCKED	= 2,	/* the virtual CPU is blocked on resource */
} virVcpuState;

typedef struct _virVcpuInfo virVcpuInfo;
struct _virVcpuInfo {
    unsigned int number;	/* virtual CPU number */
    int state;			/* value from virVcpuState */
    unsigned long long cpuTime; /* CPU time used, in nanoseconds */
    int cpu;			/* real CPU number, or -1 if offline */
};
typedef virVcpuInfo *virVcpuInfoPtr;

int			virDomainSetVcpus	(virDomainPtr domain,
						 unsigned int nvcpus);

int			virDomainPinVcpu	(virDomainPtr domain,
						 unsigned int vcpu,
						 unsigned char *cpumap,
						 int maplen);

/**
 * VIR_USE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjonction with virDomainPinVcpu() API.
 * USE_CPU macro set the bit (CPU usable) of the related cpu in cpumap.
 */

#define VIR_USE_CPU(cpumap,cpu)	(cpumap[(cpu)/8] |= (1<<((cpu)%8)))

/**
 * VIR_UNUSE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjonction with virDomainPinVcpu() API.
 * USE_CPU macro reset the bit (CPU not usable) of the related cpu in cpumap.
 */

#define VIR_UNUSE_CPU(cpumap,cpu)	(cpumap[(cpu)/8] &= ~(1<<((cpu)%8)))

/**
 * VIR_CPU_MAPLEN:
 * @cpu: number of physical CPUs
 *
 * This macro is to be used in conjonction with virDomainPinVcpu() API.
 * It returns the length (in bytes) required to store the complete
 * CPU map between a single virtual & all physical CPUs of a domain.
 */

#define VIR_CPU_MAPLEN(cpu)      (((cpu)+7)/8)


int			virDomainGetVcpus	(virDomainPtr domain,
						 virVcpuInfoPtr info,
						 int maxinfo,
						 unsigned char *cpumaps,
						 int maplen);

/**
 * VIR_CPU_USABLE:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjonction with virDomainGetVcpus() API.
 * VIR_CPU_USABLE macro returns a non zero value (true) if the cpu
 * is usable by the vcpu, and 0 otherwise.
 */

#define VIR_CPU_USABLE(cpumaps,maplen,vcpu,cpu) \
	(cpumaps[((vcpu)*(maplen))+((cpu)/8)] & (1<<((cpu)%8)))

/**
 * VIR_COPY_CPUMAP:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 * @cpumap: pointer to a cpumap (in 8-bit bytes) (OUT)
 *	This cpumap must be previously allocated by the caller
 *      (ie: malloc(maplen))
 *
 * This macro is to be used in conjonction with virDomainGetVcpus() and
 * virDomainPinVcpu() APIs. VIR_COPY_CPUMAP macro extract the cpumap of
 * the specified vcpu from cpumaps array and copy it into cpumap to be used
 * later by virDomainPinVcpu() API.
 */
#define VIR_COPY_CPUMAP(cpumaps,maplen,vcpu,cpumap) \
	memcpy(cpumap, &(cpumaps[(vcpu)*(maplen)]), (maplen))


/**
 * VIR_GET_CPUMAP:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 *
 * This macro is to be used in conjonction with virDomainGetVcpus() and
 * virDomainPinVcpu() APIs. VIR_GET_CPUMAP macro returns a pointer to the
 * cpumap of the specified vcpu from cpumaps array.
 */
#define VIR_GET_CPUMAP(cpumaps,maplen,vcpu)	&(cpumaps[(vcpu)*(maplen)])

int virDomainAttachDevice(virDomainPtr domain, char *xml);
int virDomainDetachDevice(virDomainPtr domain, char *xml);


#ifdef __cplusplus
}
#endif

#endif /* __VIR_VIRLIB_H__ */
