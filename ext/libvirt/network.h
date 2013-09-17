#ifndef NETWORK_H
#define NETWORK_H

void ruby_libvirt_network_init();

VALUE ruby_libvirt_network_new(virNetworkPtr n, VALUE conn);

#endif
