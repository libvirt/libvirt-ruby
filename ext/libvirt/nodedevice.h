#ifndef NODEDEVICE_H
#define NODEDEVICE_H

void ruby_libvirt_nodedevice_init();

VALUE ruby_libvirt_nodedevice_new(virNodeDevicePtr n, VALUE conn);

#endif
