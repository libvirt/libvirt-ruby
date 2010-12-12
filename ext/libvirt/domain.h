#ifndef DOMAIN_H
#define DOMAIN_H

extern VALUE c_domain;

void domain_free(void *d);
VALUE domain_new(virDomainPtr d, VALUE conn);
virDomainPtr domain_get(VALUE s);

void init_domain();

#endif
