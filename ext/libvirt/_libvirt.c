/*
 * libvirt.c: Ruby bindings for libvirt
 *
 * Copyright (C) 2007 Red Hat Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David Lutterkort <dlutter@redhat.com>
 */

#include <ruby.h>
#include <libvirt/libvirt.h>

static VALUE m_libvirt;
static VALUE c_connect;
static VALUE c_domain;
static VALUE c_domain_info;

/*
 * Internal helpers
 */
static void connect_close(void *p) {
    int r;
    
    if (!p)
        return;
    r = virConnectClose((virConnectPtr) p);
    if (r == -1)
        rb_raise(rb_eSystemCallError, "Connection close failed");
}

static VALUE connect_new(virConnectPtr p) {
    return Data_Wrap_Struct(c_connect, NULL, connect_close, p);
}

static virConnectPtr connect_get(VALUE s) {
    virConnectPtr conn;

    Data_Get_Struct(s, virConnect, conn);
    if (!conn)
        rb_raise(rb_eArgError, "Connection has been closed");

    return conn;
}

static void domain_free(void *d) {
    int r;
    r = virDomainFree((virDomainPtr) d);
    if (r == -1)
        rb_raise(rb_eSystemCallError, "Domain free failed");
}

static virDomainPtr domain_get(VALUE s) {
    virDomainPtr dom;

    Data_Get_Struct(s, virDomain, dom);
    if (!dom)
        rb_raise(rb_eArgError, "Connection has been closed");

    return dom;
}

static VALUE domain_new(virDomainPtr d, VALUE conn) {
    VALUE result;
    result = Data_Wrap_Struct(c_domain, NULL, domain_free, d);
    rb_iv_set(result, "@connection", conn);
    return result;
}

static virConnectPtr domain_conn(VALUE dom) {
    VALUE c = rb_iv_get(dom, "@connection");
    return connect_get(c);
}

/* Error handling */
#define _E(cond, conn, fn) \
    do { if (cond) vir_error(conn, fn); } while(0)

NORETURN(static void vir_error(virConnectPtr conn, const char *fn)) {
    rb_raise(rb_eSystemCallError, "libvir call %s failed", fn);
}

/* 
 * Module Libvirt 
 */
VALUE libvirt_open(VALUE m, VALUE url) {
    char *str = NULL;
    
    if (url) {
        str = StringValueCStr(url);
        if (!str)
            rb_raise(rb_eTypeError, "expected string");
    }
    virConnectPtr ptr = virConnectOpen(str);
    if (!ptr)
        rb_raise(rb_eArgError, "Failed to open %s", str);
    return connect_new(ptr);
}

VALUE libvirt_open_read_only(VALUE m, VALUE url) {
    char *str = NULL;
    
    if (url) {
        str = StringValueCStr(url);
        if (!str)
            rb_raise(rb_eTypeError, "expected string");
    }
    virConnectPtr ptr = virConnectOpenReadOnly(str);
    _E(!ptr, NULL, "virConnectOpenReadOnly");

    return connect_new(ptr);
}

/* 
 * Class Libvirt::Connect 
 */
VALUE libvirt_conn_close(VALUE s) {
    virConnectPtr conn;
    Data_Get_Struct(s, virConnect, conn);
    if (conn) {
        connect_close(conn);
        DATA_PTR(s) = NULL;
    }
    return Qnil;
}

VALUE libvirt_conn_closed_p(VALUE s) {
    virConnectPtr conn;
    Data_Get_Struct(s, virConnect, conn);
    return (conn==NULL) ? Qtrue : Qfalse;
}

VALUE libvirt_conn_type(VALUE s) {
    virConnectPtr conn = connect_get(s);
    const char *type;

    type = virConnectGetType(conn);
    _E(type == NULL, conn, "virConnectGetType");

    return rb_str_new2(type);
}

VALUE libvirt_conn_version(VALUE s) {
    int r;
    unsigned long v;
    virConnectPtr conn = connect_get(s);

    r = virConnectGetVersion(conn, &v);
    _E(r == -1, conn, "virConnectGetVersion");

    return ULONG2NUM(v);
}

VALUE libvirt_conn_hostname(VALUE s) {
    char *hostname;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    hostname = virConnectGetHostname(conn);
    _E(!hostname, conn, "virConnectGetHostname");

    result = rb_str_new2(hostname);
    free(hostname);
    
    return result;
}

VALUE libvirt_conn_uri(VALUE s) {
    char *uri;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    uri = virConnectGetURI(conn);
    _E(!uri, conn, "virConnectGetURI");

    result = rb_str_new2(uri);
    free(uri);
    
    return result;
}

VALUE libvirt_conn_max_vcpus(VALUE s, VALUE type) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectGetMaxVcpus(conn, StringValueCStr(type));
    _E(result == -1, conn, "virConnectGetMaxVcpus");

    return INT2NUM(result);
}

VALUE libvirt_conn_capabilities(VALUE s) {
    char *caps;
    VALUE result;
    virConnectPtr conn = connect_get(s);

    caps = virConnectGetCapabilities(conn);
    _E(caps == NULL, conn, "virConnectGetCapabilities");

    result = rb_str_new2(caps);
    free(caps);
    
    return result;
}

VALUE libvirt_conn_num_of_domains(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfDomains(conn);
    _E(result == -1, conn, "virConnectNumOfDomains");

    return INT2NUM(result);
}

VALUE libvirt_conn_list_domains(VALUE s) {
    int i, r, num, *ids;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    num = virConnectNumOfDomains(conn);
    _E(num == -1, conn, "virConnectNumOfDomains");
    
    ids = alloca(num * sizeof(int));
    r = virConnectListDomains(conn, ids, num);
    _E(r == -1, conn, "virConnectListDomains");

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, INT2NUM(ids[i]));
    }
    return result;
}

VALUE libvirt_conn_num_of_defined_domains(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfDefinedDomains(conn);
    _E(result == -1, conn, "virConnectNumOfDefinedDomains");

    return INT2NUM(result);
}

VALUE libvirt_conn_list_defined_domains(VALUE s) {
    int i, r, num;
    char **names;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    num = virConnectNumOfDefinedDomains(conn);
    _E(num == -1, conn, "virConnectNumOfDefinedDomains");
    
    names = alloca(num * sizeof(char*));
    r = virConnectListDefinedDomains(conn, names, num);
    _E(r == -1, conn, "virConnectListDefinedDomains");

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, rb_str_new2(names[i]));
        free(names[i]);
    }
    return result;
}

VALUE libvirt_conn_num_of_networks(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfNetworks(conn);
    _E(result == -1, conn, "virConnectNumOfNetworks");

    return INT2NUM(result);
}

VALUE libvirt_conn_list_networks(VALUE s) {
    int i, r, num;
    char **names;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    num = virConnectNumOfNetworks(conn);
    _E(num == -1, conn, "virConnectNumOfNetworks");
    
    names = alloca(num * sizeof(char *));
    r = virConnectListNetworks(conn, names, num);
    _E(r == -1, conn, "virConnectListNetworks");

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, rb_str_new2(names[i]));
        free(names[i]);
    }
    return result;
}

VALUE libvirt_conn_num_of_defined_networks(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfDefinedNetworks(conn);
    _E(result == -1, conn, "virConnectNumOfDefinedNetworks");

    return INT2NUM(result);
}

VALUE libvirt_conn_list_defined_networks(VALUE s) {
    int i, r, num;
    char **names;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    num = virConnectNumOfDefinedNetworks(conn);
    _E(num == -1, conn, "virConnectNumOfDefinedNetworks");
    
    names = alloca(num * sizeof(char*));
    r = virConnectListDefinedNetworks(conn, names, num);
    _E(r == -1, conn, "virConnectListDefinedNetworks");

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, rb_str_new2(names[i]));
        free(names[i]);
    }
    return result;
}

/* 
 * Class Libvirt::Domain 
 */
VALUE libvirt_dom_migrate(VALUE s, VALUE dconn, VALUE flags,
                           VALUE dname, VALUE uri, VALUE bandwidth) {
    rb_raise(rb_eNotImpError, "c_dom_migrate");
}

VALUE libvirt_dom_shutdown(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainShutdown(dom);
    _E(r == -1, domain_conn(s), "virDomainShutdown");

    return Qnil;
}

VALUE libvirt_dom_reboot(VALUE s, VALUE flags) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainReboot(dom, NUM2UINT(flags));
    _E(r == -1, domain_conn(s), "virDomainReboot");

    return Qnil;
}

VALUE libvirt_dom_destroy(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainDestroy(dom);
    _E(r == -1, domain_conn(s), "virDomainDestroy");

    return Qnil;
}

VALUE libvirt_dom_suspend(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainSuspend(dom);
    _E(r == -1, domain_conn(s), "virDomainSuspend");

    return Qnil;
}

VALUE libvirt_dom_resume(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainResume(dom);
    _E(r == -1, domain_conn(s), "virDomainResume");

    return Qnil;
}

VALUE libvirt_dom_save(VALUE s, VALUE to) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainSave(dom, StringValueCStr(to));
    _E(r == -1, domain_conn(s), "virDomainSave");

    return Qnil;
}

VALUE libvirt_dom_core_dump(VALUE s, VALUE to, VALUE flags) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainCoreDump(dom, StringValueCStr(to), NUM2UINT(flags));
    _E(r == -1, domain_conn(s), "virDomainCoreDump");

    return Qnil;
}

VALUE libvirt_dom_s_restore(VALUE klass, VALUE c, VALUE from) {
    virConnectPtr conn = connect_get(c);
    int r;

    r = virDomainRestore(conn, StringValueCStr(from));
    _E(r == -1, conn, "virDomainRestore");

    return Qnil;
}

VALUE libvirt_dom_info(VALUE s) {
    virDomainPtr dom = domain_get(s);
    virDomainInfo info;
    int r;
    VALUE result;

    r = virDomainGetInfo(dom, &info);
    _E(r == -1, domain_conn(s), "virDomainGetInfo");

    result = rb_class_new_instance(0, NULL, c_domain_info);
    rb_iv_set(result, "@state", CHR2FIX(info.state));
    rb_iv_set(result, "@maxMem", ULONG2NUM(info.maxMem));
    rb_iv_set(result, "@memory", ULONG2NUM(info.memory));
    rb_iv_set(result, "@nrVirtCpu", INT2FIX((int) info.nrVirtCpu));
    rb_iv_set(result, "@cpuTime", ULL2NUM(info.cpuTime));
    return result;
}

VALUE libvirt_dom_name(VALUE s) {
    virDomainPtr dom = domain_get(s);
    const char *name;

    name = virDomainGetName(dom);
    _E(name == NULL, domain_conn(s), "virDomainGetName");

    return rb_str_new2(name);
}

VALUE libvirt_dom_id(VALUE s) {
    virDomainPtr dom = domain_get(s);
    unsigned int id;

    id = virDomainGetID(dom);
    _E(id == -1, domain_conn(s), "virDomainGetID");

    return UINT2NUM(id);
}

VALUE libvirt_dom_uuid(VALUE s) {
    virDomainPtr dom = domain_get(s);
    char uuid[VIR_UUID_STRING_BUFLEN];
    int r;

    r = virDomainGetUUIDString(dom, uuid);
    _E(r == -1, domain_conn(s), "virDomainGetUUIDString");

    return rb_str_new2((char *) uuid);
}

VALUE libvirt_dom_os_type(VALUE s) {
    virDomainPtr dom = domain_get(s);
    char *os_type;
    VALUE result;

    os_type = virDomainGetOSType(dom);
    _E(os_type == NULL, domain_conn(s), "virDomainGetOSType");

    result = rb_str_new2(os_type);
    free(os_type);
    return result;
}

VALUE libvirt_dom_max_memory(VALUE s) {
    virDomainPtr dom = domain_get(s);
    unsigned long max_memory;

    max_memory = virDomainGetMaxMemory(dom);
    _E(max_memory == 0, domain_conn(s), "virDomainGetMaxMemory");

    return ULONG2NUM(max_memory);
}

VALUE libvirt_dom_max_memory_set(VALUE s, VALUE max_memory) {
    virDomainPtr dom = domain_get(s);
    int r;
    
    r = virDomainSetMaxMemory(dom, NUM2ULONG(max_memory));
    _E(r == -1, domain_conn(s), "virDomainSetMaxMemory");

    return ULONG2NUM(max_memory);
}

VALUE libvirt_dom_max_vcpus(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int vcpus;
    
    vcpus = virDomainGetMaxVcpus(dom);
    _E(vcpus == -1, domain_conn(s), "virDomainGetMaxVcpus");

    return INT2NUM(vcpus);
}

VALUE libvirt_dom_xml_desc(VALUE s) {
    virDomainPtr dom = domain_get(s);
    char *xml;
    VALUE result;

    xml = virDomainGetXMLDesc(dom, 0);
    _E(xml == NULL, domain_conn(s), "virDomainGetXMLDesc");

    result = rb_str_new2(xml);
    free(xml);
    return result;
}

VALUE libvirt_dom_undefine(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainUndefine(dom);
    _E(r == -1, domain_conn(s), "virDomainUndefine");

    return Qnil;
}

VALUE libvirt_dom_create(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainCreate(dom);
    _E(r == -1, domain_conn(s), "virDomainCreate");

    return Qnil;
}

VALUE libvirt_dom_autostart(VALUE s){
    virDomainPtr dom = domain_get(s);
    int r, autostart;

    r = virDomainGetAutostart(dom, &autostart);
    _E(r == -1, domain_conn(s), "virDomainAutostart");

    return autostart ? Qtrue : Qfalse;
}

VALUE libvirt_dom_autostart_set(VALUE s, VALUE autostart) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainSetAutostart(dom, RTEST(autostart) ? 1 : 0);
    _E(r == -1, domain_conn(s), "virDomainAutostart");

    return INT2NUM(autostart);
}

VALUE libvirt_conn_create_linux(VALUE c, VALUE xml, VALUE flags) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);
    char *xmlDesc;

    xmlDesc = StringValueCStr(xml);

    dom = virDomainCreateLinux(conn, xmlDesc, NUM2UINT(flags));
    _E(dom == NULL, conn, "virDomainCreateLinux");

    return domain_new(dom, c);
}

VALUE libvirt_conn_lookup_domain_by_name(VALUE c, VALUE name) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainLookupByName(conn, StringValueCStr(name));
    _E(dom == NULL, conn, "virDomainLookupByName");

    return domain_new(dom, c);
}

VALUE libvirt_conn_lookup_domain_by_id(VALUE c, VALUE id) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainLookupByID(conn, NUM2INT(id));
    _E(dom == NULL, conn, "virDomainLookupByID");

    return domain_new(dom, c);
}

VALUE libvirt_conn_lookup_domain_by_uuid(VALUE c, VALUE uuid) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainLookupByUUIDString(conn, StringValueCStr(uuid));
    _E(dom == NULL, conn, "virDomainLookupByUUID");

    return domain_new(dom, c);
}

VALUE libvirt_conn_define_domain_xml(VALUE c, VALUE xml) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainDefineXML(conn, StringValueCStr(xml));
    _E(dom == NULL, conn, "virDomainDefineXML");

    return domain_new(dom, c);
}

void Init__libvirt() {
    int r;

    m_libvirt = rb_define_module("Libvirt");

    /* 
     * Class Libvirt::Connect 
     */
    c_connect = rb_define_class_under(m_libvirt, "Connect", rb_cObject);

	rb_define_module_function(m_libvirt, "open", libvirt_open, 1);
	rb_define_module_function(m_libvirt, "openReadOnly", 
                              libvirt_open_read_only, 1);

    rb_define_method(c_connect, "close", libvirt_conn_close, 0);
    rb_define_method(c_connect, "closed?", libvirt_conn_closed_p, 0);
    rb_define_method(c_connect, "type", libvirt_conn_type, 0);
    rb_define_method(c_connect, "version", libvirt_conn_version, 0);
    rb_define_method(c_connect, "hostname", libvirt_conn_hostname, 0);
    rb_define_method(c_connect, "uri", libvirt_conn_uri, 0);
    rb_define_method(c_connect, "maxVcpus", libvirt_conn_max_vcpus, 1);
    // TODO: virNodeGetInfo
    rb_define_method(c_connect, "capabilities", libvirt_conn_capabilities, 0);
    rb_define_method(c_connect, "numOfDomains", libvirt_conn_num_of_domains, 0);
    rb_define_method(c_connect, "listDomains", libvirt_conn_list_domains, 0);
    rb_define_method(c_connect, "numOfDefinedDomains",
                     libvirt_conn_num_of_defined_domains, 0);
    rb_define_method(c_connect, "listDefinedDomains",
                     libvirt_conn_list_defined_domains, 0);
    rb_define_method(c_connect, "numOfNetworks",
                     libvirt_conn_num_of_networks, 0);
    rb_define_method(c_connect, "listNetworks", libvirt_conn_list_networks, 0);
    rb_define_method(c_connect, "numOfDefinedNetworks",
                     libvirt_conn_num_of_defined_networks, 0);
    rb_define_method(c_connect, "listDefinedNetworks",
                     libvirt_conn_list_defined_networks, 0);
    // Domain creation/lookup
    rb_define_method(c_connect, "createDomainLinux",
                     libvirt_conn_create_linux, 2);
    rb_define_method(c_connect, "lookupDomainByName", 
                     libvirt_conn_lookup_domain_by_name, 1);
    rb_define_method(c_connect, "lookupDomainByID",
                     libvirt_conn_lookup_domain_by_id, 1);
    rb_define_method(c_connect, "lookupDomainByUUID", 
                     libvirt_conn_lookup_domain_by_uuid, 1);
    rb_define_method(c_connect, "defineDomainXML",
                     libvirt_conn_define_domain_xml, 1);
    
    /* 
     * Class Libvirt::Domain 
     */
    c_domain = rb_define_class_under(m_libvirt, "Domain", rb_cObject);
#define DEF_DOMSTATE(name) \
    rb_define_const(c_domain, #name, INT2NUM(VIR_DOMAIN_##name))
    /* virDomainState */
    DEF_DOMSTATE(NOSTATE);
    DEF_DOMSTATE(RUNNING);
    DEF_DOMSTATE(BLOCKED);
    DEF_DOMSTATE(PAUSED);
    DEF_DOMSTATE(SHUTDOWN);
    DEF_DOMSTATE(SHUTOFF);
    DEF_DOMSTATE(CRASHED);
    /* virDomainRestart */
    DEF_DOMSTATE(DESTROY);
    DEF_DOMSTATE(RESTART);
    DEF_DOMSTATE(PRESERVE);
    DEF_DOMSTATE(RENAME_RESTART);
#undef DEF_DOMSTATE

    rb_define_method(c_domain, "migrate", libvirt_dom_migrate, 5);
    rb_define_attr(c_domain, "connection", 1, 0);
    rb_define_method(c_domain, "shutdown", libvirt_dom_shutdown, 0);
    rb_define_method(c_domain, "reboot", libvirt_dom_reboot, 1);
    rb_define_method(c_domain, "destroy", libvirt_dom_destroy, 0);
    rb_define_method(c_domain, "suspend", libvirt_dom_suspend, 0);
    rb_define_method(c_domain, "resume", libvirt_dom_resume, 0);
    rb_define_method(c_domain, "save", libvirt_dom_save, 1);
    rb_define_singleton_method(c_domain, "restore", libvirt_dom_s_restore, 2);
    rb_define_method(c_domain, "coreDump", libvirt_dom_core_dump, 2);
    rb_define_method(c_domain, "info", libvirt_dom_info, 0);
    rb_define_method(c_domain, "name", libvirt_dom_name, 0);
    rb_define_method(c_domain, "id", libvirt_dom_id, 0);
    rb_define_method(c_domain, "uuid", libvirt_dom_uuid, 0);
    rb_define_method(c_domain, "osType", libvirt_dom_os_type, 0);
    rb_define_method(c_domain, "maxMemory", libvirt_dom_max_memory, 0);
    rb_define_method(c_domain, "maxMemory=", libvirt_dom_max_memory_set, 1);
    rb_define_method(c_domain, "maxVcpus", libvirt_dom_max_vcpus, 0);
    rb_define_method(c_domain, "xmlDesc", libvirt_dom_xml_desc, 0);
    rb_define_method(c_domain, "undefine", libvirt_dom_undefine, 0);
    rb_define_method(c_domain, "create", libvirt_dom_create, 0);
    rb_define_method(c_domain, "autostart", libvirt_dom_autostart, 0);
    rb_define_method(c_domain, "autostart=", libvirt_dom_autostart_set, 1);

    /*
     * Class Libvirt::Domain::Info
     */
    c_domain_info = rb_define_class_under(c_domain, "Info", rb_cObject);
    rb_define_attr(c_domain_info, "state", 1, 0);
    rb_define_attr(c_domain_info, "maxMem", 1, 0);
    rb_define_attr(c_domain_info, "memory", 1, 0);
    rb_define_attr(c_domain_info, "nrVirtCpu", 1, 0);
    rb_define_attr(c_domain_info, "cpuTime", 1, 0);

    r = virInitialize();
    if (r == -1)
        rb_raise(rb_eSystemCallError, "virInitialize failed");
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
