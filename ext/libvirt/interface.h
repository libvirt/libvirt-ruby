#ifndef INTERFACE_H
#define INTERFACE_H

void ruby_libvirt_interface_init();

VALUE ruby_libvirt_interface_new(virInterfacePtr i, VALUE conn);

#endif
