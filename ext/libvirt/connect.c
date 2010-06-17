/*
 * connect.c: virConnect methods
 *
 * Copyright (C) 2007,2010 Red Hat Inc.
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
 */

#include <ruby.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include "extconf.h"
#include "common.h"

VALUE c_connect;
static VALUE c_node_security_model;
static VALUE c_node_info;

static void connect_close(void *p) {
    int r;

    if (!p)
        return;
    r = virConnectClose((virConnectPtr) p);
    _E(r < 0, create_error(rb_eSystemCallError, "connect_close",
                           "Connection close failed", p));
}

VALUE connect_new(virConnectPtr p) {
    return Data_Wrap_Struct(c_connect, NULL, connect_close, p);
}

virConnectPtr connect_get(VALUE s) {
    generic_get(Connect, s);
}

VALUE conn_attr(VALUE s) {
    if (rb_obj_is_instance_of(s, c_connect) != Qtrue) {
        s = rb_iv_get(s, "@connection");
    }
    if (rb_obj_is_instance_of(s, c_connect) != Qtrue) {
        rb_raise(rb_eArgError, "Expected Connection object");
    }
    return s;
}

virConnectPtr conn(VALUE s) {
    virConnectPtr conn;

    s = conn_attr(s);
    Data_Get_Struct(s, virConnect, conn);
    if (!conn)
        rb_raise(rb_eArgError, "Connection has been closed");
    return conn;
}

/*
 * call-seq:
 *   conn.close -> nil
 *
 * Close the connection
 */
static VALUE libvirt_conn_close(VALUE s) {
    virConnectPtr conn;
    Data_Get_Struct(s, virConnect, conn);
    if (conn) {
        connect_close(conn);
        DATA_PTR(s) = NULL;
    }
    return Qnil;
}

/*
 * call-seq:
 *   conn.closed? -> [True|False]
 *
 * Return +true+ if the connection is closed, +false+ if it is open
 */
static VALUE libvirt_conn_closed_p(VALUE s) {
    virConnectPtr conn;

    Data_Get_Struct(s, virConnect, conn);
    return (conn==NULL) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   conn.type -> string
 *
 * Call +virConnectGetType+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetType]
 */
static VALUE libvirt_conn_type(VALUE s) {
    gen_call_string(virConnectGetType, conn(s), 0, connect_get(s));
}

/*
 * call-seq:
 *   conn.version -> fixnum
 *
 * Call +virConnectGetVersion+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetVersion]
 */
static VALUE libvirt_conn_version(VALUE s) {
    int r;
    unsigned long v;
    virConnectPtr conn = connect_get(s);

    r = virConnectGetVersion(conn, &v);
    _E(r < 0, create_error(e_RetrieveError, "virConnectGetVersion", "", conn));

    return ULONG2NUM(v);
}

#if HAVE_VIRCONNECTGETLIBVERSION
/*
 * call-seq:
 *   conn.libversion -> fixnum
 *
 * Call +virConnectGetLibVersion+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetLibVersion]
 */
static VALUE libvirt_conn_libversion(VALUE s) {
    int r;
    unsigned long v;
    virConnectPtr conn = connect_get(s);

    r = virConnectGetLibVersion(conn, &v);
    _E(r < 0, create_error(e_RetrieveError, "virConnectGetLibVersion",
                           "", conn));

    return ULONG2NUM(v);
}
#endif

/*
 * call-seq:
 *   conn.hostname -> string
 *
 * Call +virConnectGetHostname+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetHostname]
 */
static VALUE libvirt_conn_hostname(VALUE s) {
    gen_call_string(virConnectGetHostname, conn(s), 1, connect_get(s));
}

/*
 * call-seq:
 *   conn.uri -> string
 *
 * Call +virConnectGetURI+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetURI]
 */
static VALUE libvirt_conn_uri(VALUE s) {
    gen_call_string(virConnectGetURI, conn(s), 1, connect_get(s));
}

/*
 * call-seq:
 *   conn.max_vcpus -> fixnum
 *
 * Call +virConnectGetMaxVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetMaxVcpus]
 */
static VALUE libvirt_conn_max_vcpus(int argc, VALUE *argv, VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);
    VALUE type;

    rb_scan_args(argc, argv, "01", &type);

    result = virConnectGetMaxVcpus(conn, get_string_or_nil(type));
    _E(result < 0, create_error(e_RetrieveError, "virConnectGetMaxVcpus",
                                "", conn));

    return INT2NUM(result);
}

/*
 * call-seq:
 *   conn.node_get_info -> Libvirt::Connect::Nodeinfo
 *
 * Call +virNodeGetInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetInfo]
 */
static VALUE libvirt_conn_node_get_info(VALUE s) {
    int r;
    virConnectPtr conn = connect_get(s);
    virNodeInfo nodeinfo;
    VALUE result;

    r = virNodeGetInfo(conn, &nodeinfo);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", "", conn));

    result = rb_class_new_instance(0, NULL, c_node_info);
    rb_iv_set(result, "@model", rb_str_new2(nodeinfo.model));
    rb_iv_set(result, "@memory", ULONG2NUM(nodeinfo.memory));
    rb_iv_set(result, "@cpus", UINT2NUM(nodeinfo.cpus));
    rb_iv_set(result, "@mhz", UINT2NUM(nodeinfo.mhz));
    rb_iv_set(result, "@nodes", UINT2NUM(nodeinfo.nodes));
    rb_iv_set(result, "@sockets", UINT2NUM(nodeinfo.sockets));
    rb_iv_set(result, "@cores", UINT2NUM(nodeinfo.cores));
    rb_iv_set(result, "@threads", UINT2NUM(nodeinfo.threads));

    return result;
}

/*
 * call-seq:
 *   conn.node_free_memory -> fixnum
 *
 * Call +virNodeGetFreeMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetFreeMemory]
 */
static VALUE libvirt_conn_node_free_memory(VALUE s) {
    virConnectPtr conn = connect_get(s);
    unsigned long long freemem;

    freemem = virNodeGetFreeMemory(conn);
    _E(freemem == 0, create_error(e_RetrieveError, "virNodeGetFreeMemory",
                                  "", conn));

    return ULL2NUM(freemem);
}

/*
 * call-seq:
 *   conn.node_cells_free_memory -> list
 *
 * Call +virNodeGetCellsFreeMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetCellsFreeMemory]
 */
static VALUE libvirt_conn_node_cells_free_memory(int argc, VALUE *argv, VALUE s) {
    int r;
    virConnectPtr conn = connect_get(s);
    VALUE cells;
    VALUE startCell, maxCells;
    unsigned long long *freeMems;
    virNodeInfo nodeinfo;
    int i;

    rb_scan_args(argc, argv, "02", &startCell, &maxCells);

    if (NIL_P(startCell))
        startCell = INT2FIX(0);
    if (NIL_P(maxCells)) {
        r = virNodeGetInfo(conn, &nodeinfo);
        _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", "", conn));
        freeMems = ALLOC_N(unsigned long long, nodeinfo.nodes);
        maxCells = INT2FIX(nodeinfo.nodes);
    }
    else
        freeMems = ALLOC_N(unsigned long long, NUM2UINT(maxCells));

    r = virNodeGetCellsFreeMemory(conn, freeMems, NUM2INT(startCell),
                                  NUM2INT(maxCells));
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetCellsFreeMemory", "", conn));

    cells = rb_ary_new2(r);
    for (i = 0; i < r; i++)
        rb_ary_push(cells, ULL2NUM(freeMems[i]));
    free(freeMems);

    return cells;
}

/*
 * call-seq:
 *   conn.node_get_security_model -> Libvirt::Connect::NodeSecurityModel
 *
 * Call +virNodeGetSecurityInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetSecurityInfo]
 */
static VALUE libvirt_conn_node_get_security_model(VALUE s) {
    virSecurityModel secmodel;
    virConnectPtr conn = connect_get(s);
    int r;
    VALUE result;

    r = virNodeGetSecurityModel(conn, &secmodel);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetSecurityModel", "", conn));

    result = rb_class_new_instance(0, NULL, c_node_security_model);
    rb_iv_set(result, "@model", rb_str_new2(secmodel.model));
    rb_iv_set(result, "@doi", rb_str_new2(secmodel.doi));

    return result;
}

#if HAVE_VIRCONNECTISENCRYPTED
/*
 * call-seq:
 *   conn.encrypted?
 *
 * Return +true+ if the connection is encrypted, +false+ if it is not
 */
static VALUE libvirt_conn_encrypted_p(VALUE s) {
    gen_call_truefalse(virConnectIsEncrypted, conn(s), connect_get(s));
}
#endif

#if HAVE_VIRCONNECTISSECURE
/*
 * call-seq:
 *   conn.secure?
 *
 * Return +true+ if the connection is secure, +false+ if it is not
 */
static VALUE libvirt_conn_secure_p(VALUE s) {
    gen_call_truefalse(virConnectIsSecure, conn(s), connect_get(s));
}
#endif

/*
 * call-seq:
 *   conn.capabilities -> string
 *
 * Call +virConnectGetCapabilities+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetCapabilities]
 */
static VALUE libvirt_conn_capabilities(VALUE s) {
    gen_call_string(virConnectGetCapabilities, conn(s), 1, connect_get(s));
}

/*
 * Class Libvirt::Connect
 */
void init_connect()
{
    c_connect = rb_define_class_under(m_libvirt, "Connect", rb_cObject);

    /*
     * Class Libvirt::Connect::Nodeinfo
     */
    c_node_info = rb_define_class_under(c_connect, "Nodeinfo", rb_cObject);
    rb_define_attr(c_node_info, "model", 1, 0);
    rb_define_attr(c_node_info, "memory", 1, 0);
    rb_define_attr(c_node_info, "cpus", 1, 0);
    rb_define_attr(c_node_info, "mhz", 1, 0);
    rb_define_attr(c_node_info, "nodes", 1, 0);
    rb_define_attr(c_node_info, "sockets", 1, 0);
    rb_define_attr(c_node_info, "cores", 1, 0);
    rb_define_attr(c_node_info, "threads", 1, 0);

    /*
     * Class Libvirt::Connect::NodeSecurityModel
     */
    c_node_security_model = rb_define_class_under(c_connect,
                                                  "NodeSecurityModel",
                                                  rb_cObject);
    rb_define_attr(c_node_security_model, "model", 1, 0);
    rb_define_attr(c_node_security_model, "doi", 1, 0);

    rb_define_method(c_connect, "close", libvirt_conn_close, 0);
    rb_define_method(c_connect, "closed?", libvirt_conn_closed_p, 0);
    rb_define_method(c_connect, "type", libvirt_conn_type, 0);
    rb_define_method(c_connect, "version", libvirt_conn_version, 0);
#if HAVE_VIRCONNECTGETLIBVERSION
    rb_define_method(c_connect, "libversion", libvirt_conn_libversion, 0);
#endif
    rb_define_method(c_connect, "hostname", libvirt_conn_hostname, 0);
    rb_define_method(c_connect, "uri", libvirt_conn_uri, 0);
    rb_define_method(c_connect, "max_vcpus", libvirt_conn_max_vcpus, -1);
    rb_define_method(c_connect, "node_get_info", libvirt_conn_node_get_info, 0);
    rb_define_method(c_connect, "node_free_memory",
                     libvirt_conn_node_free_memory, 0);
    rb_define_method(c_connect, "node_cells_free_memory",
                     libvirt_conn_node_cells_free_memory, -1);
    rb_define_method(c_connect, "node_get_security_model",
                     libvirt_conn_node_get_security_model, 0);
#if HAVE_VIRCONNECTISENCRYPTED
    rb_define_method(c_connect, "encrypted?", libvirt_conn_encrypted_p, 0);
#endif
#if HAVE_VIRCONNECTISSECURE
    rb_define_method(c_connect, "secure?", libvirt_conn_secure_p, 0);
#endif
    rb_define_method(c_connect, "capabilities", libvirt_conn_capabilities, 0);

    /* FIXME: implement these */
    //rb_define_method(c_connect, "domain_event_register",
    //                 libvirt_conn_domain_event_register", -1);
    //rb_define_method(c_connect, "Domain_event_deregister",
    //                 libvirt_conn_domain_event_deregister, -1);
    //rb_define_method(c_connect, "domain_event_register_any",
    //                 libvirt_conn_domain_event_register_any, -1);
    //rb_define_method(c_connect, "domain_event_deregister_any",
    //                 libvirt_conn_domain_event_deregister_any, -1);
    //rb_define_method(c_connect, "baseline_cpu", libvirt_conn_baseline_cpu, -1);
    //rb_define_method(c_connect, "compare_cpu", libvirt_conn_compare_cpu, -1);
    //rb_define_method(c_connect, "event_register_impl", libvirt_conn_event_register_impl, -1);
}
