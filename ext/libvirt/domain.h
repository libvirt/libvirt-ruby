#ifndef DOMAIN_H
#define DOMAIN_H

void ruby_libvirt_domain_init();

VALUE ruby_libvirt_domain_new(virDomainPtr d, VALUE conn);
virDomainPtr ruby_libvirt_domain_get(VALUE s);

#endif
