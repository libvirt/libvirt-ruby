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

/* Error handling */
#define _E(cond, conn, fn) \
    do { if (cond) vir_error(conn, fn); } while(0)

NORETURN(static void vir_error(virConnectPtr conn, const char *fn)) {
    rb_raise(rb_eSystemCallError, "libvir call %s failed", fn);
}

/* Module Libvirt */
static VALUE m_open(VALUE m, VALUE url) {
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

static VALUE m_open_read_only(VALUE m, VALUE url) {
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

/* Class Libvirt::Connect */
static VALUE c_conn_close(VALUE s) {
    virConnectPtr conn;
    Data_Get_Struct(s, virConnect, conn);
    if (conn) {
        connect_close(conn);
        DATA_PTR(s) = NULL;
    }
    return Qnil;
}

static VALUE c_conn_closed_p(VALUE s) {
    virConnectPtr conn;
    Data_Get_Struct(s, virConnect, conn);
    return (conn==NULL) ? Qtrue : Qfalse;
}

static VALUE c_conn_type(VALUE s) {
    virConnectPtr conn = connect_get(s);
    const char *type;

    type = virConnectGetType(conn);
    _E(type == NULL, conn, "virConnectGetType");

    return rb_str_new2(type);
}

static VALUE c_conn_version(VALUE s) {
    int r;
    unsigned long v;
    virConnectPtr conn = connect_get(s);

    r = virConnectGetVersion(conn, &v);
    _E(r == -1, conn, "virConnectGetVersion");

    return ULONG2NUM(v);
}

static VALUE c_conn_hostname(VALUE s) {
    char *hostname;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    hostname = virConnectGetHostname(conn);
    _E(!hostname, conn, "virConnectGetHostname");

    result = rb_str_new2(hostname);
    free(hostname);
    
    return result;
}

static VALUE c_conn_uri(VALUE s) {
    char *uri;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    uri = virConnectGetURI(conn);
    _E(!uri, conn, "virConnectGetURI");

    result = rb_str_new2(uri);
    free(uri);
    
    return result;
}

static VALUE c_conn_max_vcpus(VALUE s, VALUE type) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectGetMaxVcpus(conn, StringValueCStr(type));
    _E(result == -1, conn, "virConnectGetMaxVcpus");

    return INT2NUM(result);
}

static VALUE c_conn_capabilities(VALUE s) {
    char *caps;
    VALUE result;
    virConnectPtr conn = connect_get(s);

    caps = virConnectGetCapabilities(conn);
    _E(caps == NULL, conn, "virConnectGetCapabilities");

    result = rb_str_new2(caps);
    free(caps);
    
    return result;
}

static VALUE c_conn_num_of_domains(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfDomains(conn);
    _E(result == -1, conn, "virConnectNumOfDomains");

    return INT2NUM(result);
}

static VALUE c_conn_list_domains(VALUE s) {
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

static VALUE c_conn_num_of_defined_domains(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfDefinedDomains(conn);
    _E(result == -1, conn, "virConnectNumOfDefinedDomains");

    return INT2NUM(result);
}

static VALUE c_conn_list_defined_domains(VALUE s) {
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

static VALUE c_conn_num_of_networks(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfNetworks(conn);
    _E(result == -1, conn, "virConnectNumOfNetworks");

    return INT2NUM(result);
}

static VALUE c_conn_list_networks(VALUE s) {
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

static VALUE c_conn_num_of_defined_networks(VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);

    result = virConnectNumOfDefinedNetworks(conn);
    _E(result == -1, conn, "virConnectNumOfDefinedNetworks");

    return INT2NUM(result);
}

static VALUE c_conn_list_defined_networks(VALUE s) {
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

void Init__libvirt() {
    int r;

    m_libvirt = rb_define_module("Libvirt");
    c_connect = rb_define_class_under(m_libvirt, "Connect", rb_cObject);

	rb_define_module_function(m_libvirt, "open", m_open, 1);
	rb_define_module_function(m_libvirt, "openReadOnly", m_open_read_only, 1);

    rb_define_method(c_connect, "close", c_conn_close, 0);
    rb_define_method(c_connect, "closed?", c_conn_closed_p, 0);
    rb_define_method(c_connect, "type", c_conn_type, 0);
    rb_define_method(c_connect, "version", c_conn_version, 0);
    rb_define_method(c_connect, "hostname", c_conn_hostname, 0);
    rb_define_method(c_connect, "uri", c_conn_uri, 0);
    rb_define_method(c_connect, "maxVcpus", c_conn_max_vcpus, 1);
    // TODO: virNodeGetInfo
    rb_define_method(c_connect, "capabilities", c_conn_capabilities, 0);
    rb_define_method(c_connect, "numOfDomains", c_conn_num_of_domains, 0);
    rb_define_method(c_connect, "listDomains", c_conn_list_domains, 0);
    rb_define_method(c_connect, "numOfDefinedDomains", c_conn_num_of_defined_domains, 0);
    rb_define_method(c_connect, "listDefinedDomains", c_conn_list_defined_domains, 0);
    rb_define_method(c_connect, "numOfNetworks", c_conn_num_of_networks, 0);
    rb_define_method(c_connect, "listNetworks", c_conn_list_networks, 0);
    rb_define_method(c_connect, "numOfDefinedNetworks", c_conn_num_of_defined_networks, 0);
    rb_define_method(c_connect, "listDefinedNetworks", c_conn_list_defined_networks, 0);
    
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
