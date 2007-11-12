require 'mkmf'

extension_name = '_libvirt'

dir_config(extension_name)

unless pkg_config("libvirt")
    raise "libvirt not found"
end

create_makefile(extension_name)
