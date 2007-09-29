require 'mkmf'

extension_name = 'rblibvirt'

dir_config(extension_name)

unless pkg_config("libvirt")
    raise "libvirt not found"
end

create_makefile(extension_name)



