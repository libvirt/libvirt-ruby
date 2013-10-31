#
# libvirt.rb: main module for the ruby-libvirt bindings
#
# Copyright (C) 2007 Red Hat, Inc.
# Copyright (c) 2013 Chris Lalancette <clalancette@gmail.com>
#
# Distributed under the GNU Lesser General Public License v2.1 or later.
# See COPYING for details
#
# David Lutterkort <dlutter@redhat.com>

require '_libvirt'

# Most of this module is a compatibility layer, to retain backwards
# compatibility with earlier versions of the library.  Some of the methods
# actually end up being compound methods that call multiple libvirt methods.
module Libvirt

  def self.version(type=nil)
    get_version(type)
  end

    # A version in Libvirt's representation
  class Version
    attr_reader :version, :type

    def initialize(type, version)
      @type = type
      @version = version
    end

    def major
      version / 1000000
    end

    def minor
      version % 1000000 / 1000
    end

    def release
      version % 1000
    end

    def to_s
      "#{major}.#{minor}.#{release}"
    end
  end

  class Connect
    alias type get_type
    alias version get_version
    alias libversion get_lib_version
    alias hostname get_hostname
    alias uri get_uri
    alias max_vcpus get_max_vcpus
    alias node_info node_get_info
    alias node_free_memory node_get_free_memory
    alias node_security_model node_get_security_model
    alias capabilities get_capabilities
    alias create_domain_xml domain_create_xml
    alias lookup_domain_by_name domain_lookup_by_name
    alias lookup_domain_by_id domain_lookup_by_id
    alias lookup_domain_by_uuid domain_lookup_by_uuid_string
    alias define_domain_xml domain_define_xml
    alias lookup_interface_by_name interface_lookup_by_name
    alias lookup_interface_by_mac interface_lookup_by_mac
    alias define_interface_xml interface_define_xml
    alias lookup_network_by_name network_lookup_by_name
    alias lookup_network_by_uuid network_lookup_by_uuid_string
    alias create_network_xml network_create_xml
    alias define_network_xml network_define_xml
    alias num_of_nodedevices node_num_of_devices
    alias lookup_nodedevice_by_name node_device_lookup_by_name
    alias create_nodedevice_xml node_device_create_xml
    alias lookup_nwfilter_by_name nwfilter_lookup_by_name
    alias lookup_nwfilter_by_uuid nwfilter_lookup_by_uuid_string
    alias define_nwfilter_xml nwfilter_define_xml
    alias lookup_secret_by_uuid secret_lookup_by_uuid_string
    alias lookup_secret_by_usage secret_lookup_by_usage
    alias define_secret_xml secret_define_xml
    alias lookup_storage_pool_by_name storage_pool_lookup_by_name
    alias lookup_storage_pool_by_uuid storage_pool_lookup_by_uuid_string
    alias create_storage_pool_xml storage_pool_create_xml
    alias define_storage_pool_xml storage_pool_define_xml
    alias discover_storage_pool_sources find_storage_pool_sources
    alias sys_info get_sys_info
    alias cpu_model_names get_cpu_model_names
    alias save_image_xml_desc save_image_get_xml_desc
    alias define_save_image_xml save_image_define_xml
    alias node_cpu_map node_get_cpu_map
    alias alive? is_alive
    alias create_domain_xml_with_files domain_create_xml_with_files

    def keepalive=(parms)
      if parms.class == Array
        if parms.length == 2
          set_keepalive(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Array)"
      end
    end

    def node_memory_parameters(flags=0)
      node_get_memory_parameters(node_get_memory_parameters(0, flags).length,
                                 flags)
    end

    def node_memory_parameters=(parms)
      if parms.class == Hash
        node_set_memory_parameters(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          node_set_memory_parameters(parms[0], 0)
        elsif parms.length == 2
          node_set_memory_parameters(parms[0], parms[1])
        else
          raise ArgumentError, "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Hash or Array)"
      end
    end

    def list_nodedevices(cap=nil, flags=0)
      node_list_devices(num_of_nodedevices(cap, flags), cap, flags)
    end

    def node_cells_free_memory(startCell=0, maxCells=nil)
      if maxCells.nil?
        info = node_get_info
        maxCells = info['nodes']
      end

      node_get_cells_free_memory(maxCells, startCell)
    end

    def node_cpu_stats(cpuNum=-1, flags=0)
      node_get_cpu_stats(cpuNum, node_get_cpu_stats(cpuNum, 0, flags).length,
                         flags)
    end

    def node_memory_stats(cellNum=-1, flags=0)
      node_get_memory_stats(cellNum,
                            node_get_memory_stats(cellNum, 0, flags).length,
                            flags)
    end

    # FIXME: fix up backwards compatibility
    #def list_domains
    #  list_domains(num_of_domains)
    #end

    # FIXME: fix up backwards compatibility
    #def list_defined_domains
    #  list_defined_domains(num_of_defined_domains)
    #end

    # FIXME: fix up backwards compatibility
    #def list_interfaces
    #  list_interfaces(num_of_interfaces)
    #end

    # FIXME: fix up backwards compatibility
    #def list_defined_interfaces
    #  list_defined_interfaces(num_of_defined_interfaces)
    #end

    # FIXME: fix up backwards compatibility
    #def list_networks
    #  list_networks(num_of_networks)
    #end

    # FIXME: fix up backwards compatibility
    #def list_defined_networks
    #  list_defined_networks(num_of_defined_networks)
    #end

    # FIXME: fix up backwards compatibility
    #def list_nwfilters
    #  list_nwfilters(num_of_nwfilters)
    #end

    # FIXME: fix up backwards compatibility
    #def list_secrets
    #  list_secrets(num_of_secrets)
    #end

    # FIXME: fix up backwards compatibility
    #def list_storage_pools
    #  list_storage_pools(num_of_storage_pools)
    #end

    # FIXME: fix up backwards compatibility
    #def list_defined_storage_pools
    #  list_defined_storage_pools(num_of_defined_storage_pools)
    #end
  end

  class Domain
    alias has_managed_save? has_managed_save_image
    alias info get_info
    alias security_label get_security_label
    alias blockinfo get_block_info
    alias active? is_active
    alias persistent? is_persistent
    alias ifinfo interface_stats
    alias name get_name
    alias id get_id
    alias uuid get_uuid_string
    alias os_type get_os_type
    alias max_memory get_max_memory
    alias max_vcpus get_max_vcpus
    alias num_vcpus get_vcpus_flags
    alias xml_desc get_xml_desc
    alias autostart get_autostart
    alias update_device update_device_flags
    alias lookup_snapshot_by_name snapshot_lookup_by_name
    alias has_current_snapshot? has_current_snapshot
    alias job_info get_job_info
    alias scheduler_type get_scheduler_type
    alias updated? is_updated
    alias state get_state
    alias control_info get_control_info
    alias migrate_max_speed migrate_get_max_speed
    alias metadata get_metadata
    alias fstrim fs_trim
    alias pmwakeup pm_wakeup
    alias pmsuspend_for_duration pm_suspend_for_duration
    alias migrate_compression_cache migrate_get_compression_cache
    alias security_label_list get_security_label_list
    alias job_stats get_job_stats
    alias block_job_info get_block_job_info

    def node_maxcpus
      begin
        maxcpus = node_get_cpu_map(self.conn).length
      rescue NoMethodError
        nodeinfo = node_get_info
        maxcpus = nodeinfo['nodes'] * nodeinfo['sockets'] * nodeinfo['cores'] * nodeinfo['threads']
      end

      maxcpus
    end

    def block_iotune(disk=nil, flags=0)
      get_block_io_tune(disk, get_block_io_tune(disk, 0, flags).length, flags)
    end

    def block_iotune=(parms)
      if parms.class != Array
        raise TypeError, "wrong parameter (expected Array)"
      end

      if parms.length == 2
        set_block_io_tune(parms[0], parms[1], 0)
      elsif parms.length == 3
        set_block_io_tune(parms[0], parms[1], parms[2])
      else
        raise ArgumentError, "wrong number of arguments (#{parms.length} for 2 or 3)"
        end
    end

    def block_job_speed=(parms)
      if parms.class == String
        block_job_set_speed(parms, 0, 0)
      elsif parms.class == Array
        if parms.length == 1
          block_job_set_speed(parms[0], 0, 0)
        elsif parms.length == 2
          block_job_set_speed(parms[0], parms[1], 0)
        elsif parms.length == 3
          block_job_set_speed(parms[0], parms[1], parms[2])
        else
          raise ArgumentError, "wrong number of arguments (#{parms.length} for 1, 2, or 3)"
        end
      else
        raise TypeError, "wrong parameter (expected String or Array)"
      end
    end

    def interface_parameters(interface, flags=0)
      get_interface_parameters(interface,
                               get_interface_parameters(interface, 0,
                                                        flags).length,
                               flags)
    end

    def interface_parameters=(parms)
      if parms.class != Array
        raise TypeError, "wrong parameter (expected Hash or Array)"
      end
      if parms.length == 2
        set_interface_parameters(parms[0], parms[1], 0)
      elsif parms.length == 3
        set_interface_parameters(parms[0], parms[1], parms[2])
      else
        raise ArgumentError, "wrong number of arguments (#{parms.length} for 2 or 3)"
      end
    end

    def numa_parameters(flags=0)
      get_numa_parameters(get_numa_parameters(flags).length, flags)
    end

    def numa_parameters=(parms)
      if parms.class == Hash
        set_numa_parameters(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          set_numa_parameters(parms[0], 0)
        elsif parms.length == 2
          set_numa_parameters(parms[0], parms[1])
        else
          raise ArgumentError, "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Hash or Array)"
      end
    end

    #def block_stats_flags(disk, flags=0)
    # FIXME: how do we deal with backwards compatibility?
    #end

    #def pin_emulator(cpulist, flags=0)
    # FIXME: how do we deal with backwards compatibility?
    #end

    def emulator_pin_info(flags=0)
      get_emulator_pin_info(node_maxcpus, flags)
    end

    def disk_errors(flags=0)
      get_disk_errors(get_disk_errors(0, flags), flags)
    end

    def migrate_compression_cache=(parms)
      if parms.class == Fixnum
        migrate_set_compression_cache(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          migrate_set_compression_cache(parms[0], 0)
        elsif parms.length == 2
          migrate_set_compression_cache(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Fixnum or Array)"
      end
    end

    def memory_stats_period=(parms)
      if parms.class == Fixnum
        set_memory_stats_period(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          set_memory_stats_period(parms[0], 0)
        elsif parms.length == 2
          set_memory_stats_period(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Fixnum or Array)"
      end
    end

    def metadata=(parms)
      if parms.class != Array
        raise TypeError, "wrong parameter (expected Array)"
      end

      if parms.length == 2
        set_metadata(parms[0], parms[1], nil, nil, 0)
      elsif parms.length == 3
        set_metadata(parms[0], parms[1], parms[2], nil, 0)
      elsif parms.length == 4
        set_metadata(parms[0], parms[1], parms[2], parms[3], 0)
      elsif parms.length == 5
        set_metadata(parms[0], parms[1], parms[2], parms[3], parms[4])
      else
        raise ArgumentError, "wrong number of arguments (#{parms.length} for 2, 3, 4, or 5)"
      end
    end

    def scheduler_parameters
      get_scheduler_parameters(get_scheduler_type[1])
    end

    def scheduler_parameters=(parms)
      if parms.class != Hash
        raise TypeError, "wrong parameter (expected Hash)"
      end

      set_scheduler_parameters(parms)
    end

    def memory_parameters(flags=0)
      get_memory_parameters(get_memory_parameters.length, flags)
    end

    def memory_parameters=(parms)
      if parms.class == Hash
        set_memory_parameters(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          set_memory_parameters(parms[0], 0)
        elsif parms.length == 2
          set_memory_parameters(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Hash or Array)"
      end
    end

    def blkio_parameters(flags=0)
      get_blkio_parameters(get_blkio_parameters.length, flags)
    end

    def blkio_parameters=(parms)
      if parms.class == Hash
        set_blkio_parameters(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          set_blkio_parameters(parms[0], 0)
        elsif parms.length == 2
          set_blkio_parameters(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Hash or Array)"
      end
    end

    def migrate_max_downtime=(parms)
      if parms.class == Fixnum
        migrate_set_max_downtime(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          migrate_set_max_downtime(parms[0], 0)
        elsif parms.length == 2
          migrate_set_max_downtime(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Fixnum or Array)"
      end
    end

    def migrate_max_speed=(parms)
      if parms.class == Fixnum
        migrate_set_max_speed(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          migrate_set_max_speed(parms[0], 0)
        elsif parms.length == 2
          migrate_set_max_speed(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Fixnum or Array)"
      end
    end

    # FIXME: what do we do about compatibility here?
    #def save(filename, dxml=nil, flags=0)
    #save
    #end

    def vcpus
      info = get_info

      get_vcpus(info['nr_virt_cpu'], node_maxcpus)
      # FIXME: finish implementing this
    end

    def max_memory=(parms)
      if parms.class != Fixnum
        raise TypeError, "wrong parameter (expected Fixnum)"
      end

      set_max_memory(parms)
    end

    def memory=(parms)
      if parms.class != Fixnum
        raise TypeError, "wrong parameter (expected Fixnum)"
      end

      set_memory(parms)
    end

    def vcpus=(parms)
      if parms.class != Fixnum
        raise TypeError, "wrong parameter (expected Fixnum)"
      end

      set_vcpus(parms)
    end

    def autostart=(parms)
      if parms.class != TrueClass and parms.class != FalseClass
        raise TypeError, "wrong parameter (expected TrueClass or FalseClass)"
      end

      set_autostart(parms)
    end

    def list_snapshots(flags=0)
      snapshot_list_names(snapshot_num, flags)
    end

    class Snapshot
      alias xml_desc get_xml_desc
      alias name get_name
      alias parent get_parent
      alias current? is_current
      alias has_metadata? has_metadata
      #def list_children_names(flags=0)
      #FIXME: how do we do backwards compatibility here?
      #end
    end
  end

  class Interface
    alias active? is_active
    alias name get_name
    alias mac get_mac_string
    alias xml_desc get_xml_desc
  end

  class Network
    alias name get_name
    alias uuid get_uuid_string
    alias xml_desc get_xml_desc
    alias bridge_name get_bridge_name
    alias autostart? get_autostart
    alias active? is_active
    alias persistent? is_persistent

    def autostart=(parms)
      if parms.class != Fixnum
        raise TypeError, "wrong parameter (expected Fixnum)"
      end

      set_autostart(parms)
    end
  end

  class NodeDevice
    alias name get_name
    alias parent get_parent
    alias xml_desc get_xml_desc
    alias detach dettach
  end

  class NWFilter
    alias name get_name
    alias uuid get_uuid_string
    alias xml_desc get_xml_desc
  end

  class Secret
    alias uuid get_uuid_string
    alias usagetype get_usage_type
    alias usageid get_usage_id
    alias xml_desc get_xml_desc
    alias value get_value

    def value=(parms)
      if parms.class == Fixnum
        set_value(parms, 0)
      elsif parms.class == Array
        if parms.length == 1
          set_value(parms[0], 0)
        elsif parms.length == 2
          set_value(parms[0], parms[1])
        else
          raise ArgumentError "wrong number of arguments (#{parms.length} for 1 or 2)"
        end
      else
        raise TypeError, "wrong parameter (expected Fixnum or Array)"
      end
    end
  end

  class StoragePool
    alias name get_name
    alias uuid get_uuid_string
    alias info get_info
    alias xml_desc get_xml_desc
    alias autostart? get_autostart
    alias lookup_volume_by_name vol_lookup_by_name
    alias lookup_volume_by_key vol_lookup_by_key
    alias lookup_volume_by_path vol_lookup_by_path
    alias create_volume_xml vol_create_xml
    alias create_volume_xml_from vol_create_xml_from
    alias active? is_active
    alias persistent? is_persistent
    alias info get_info
    alias xml_desc get_xml_desc
    alias path get_path

    def autostart=(parms)
      if parms.class != Fixnum
        raise TypeError, "wrong parameter (expected Fixnum)"
      end

      set_autostart(parms)
    end
  end

  class StorageVol
    alias name get_name
    alias key get_key
  end
end
