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

create_header
create_makefile(extension_name)
