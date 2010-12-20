#ifndef DOMAIN_H
#define DOMAIN_H

VALUE domain_new(virDomainPtr d, VALUE conn);
virDomainPtr domain_get(VALUE s);

void init_domain();

#endif
