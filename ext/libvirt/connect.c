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
#include "domain.h"

VALUE c_connect;
static VALUE c_node_security_model;
static VALUE c_node_info;

static void connect_close(void *p) {
    int r;

    if (!p)
        return;
    r = virConnectClose((virConnectPtr) p);
    _E(r < 0, create_error(rb_eSystemCallError, "virConnectClose", p));
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
 * Call +virConnectClose+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectClose]
 * to close the connection.
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
 * Return +true+ if the connection is closed, +false+ if it is open.
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
 * to retrieve the type of hypervisor for this connection.
 */
static VALUE libvirt_conn_type(VALUE s) {
    gen_call_string(virConnectGetType, conn(s), 0, connect_get(s));
}

/*
 * call-seq:
 *   conn.version -> fixnum
 *
 * Call +virConnectGetVersion+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetVersion]
 * to retrieve the version of the hypervisor for this connection.
 */
static VALUE libvirt_conn_version(VALUE s) {
    int r;
    unsigned long v;
    virConnectPtr conn = connect_get(s);

    r = virConnectGetVersion(conn, &v);
    _E(r < 0, create_error(e_RetrieveError, "virConnectGetVersion", conn));

    return ULONG2NUM(v);
}

#if HAVE_VIRCONNECTGETLIBVERSION
/*
 * call-seq:
 *   conn.libversion -> fixnum
 *
 * Call +virConnectGetLibVersion+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetLibVersion]
 * to retrieve the version of the libvirt library for this connection.
 */
static VALUE libvirt_conn_libversion(VALUE s) {
    int r;
    unsigned long v;
    virConnectPtr conn = connect_get(s);

    r = virConnectGetLibVersion(conn, &v);
    _E(r < 0, create_error(e_RetrieveError, "virConnectGetLibVersion", conn));

    return ULONG2NUM(v);
}
#endif

/*
 * call-seq:
 *   conn.hostname -> string
 *
 * Call +virConnectGetHostname+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetHostname]
 * to retrieve the hostname of the hypervisor for this connection.
 */
static VALUE libvirt_conn_hostname(VALUE s) {
    gen_call_string(virConnectGetHostname, conn(s), 1, connect_get(s));
}

/*
 * call-seq:
 *   conn.uri -> string
 *
 * Call +virConnectGetURI+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetURI]
 * to retrieve the canonical URI for this connection.
 */
static VALUE libvirt_conn_uri(VALUE s) {
    gen_call_string(virConnectGetURI, conn(s), 1, connect_get(s));
}

/*
 * call-seq:
 *   conn.max_vcpus(type=nil) -> fixnum
 *
 * Call +virConnectGetMaxVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetMaxVcpus]
 * to retrieve the maximum number of virtual cpus supported by the hypervisor
 * for this connection.
 */
static VALUE libvirt_conn_max_vcpus(int argc, VALUE *argv, VALUE s) {
    int result;
    virConnectPtr conn = connect_get(s);
    VALUE type;

    rb_scan_args(argc, argv, "01", &type);

    result = virConnectGetMaxVcpus(conn, get_string_or_nil(type));
    _E(result < 0, create_error(e_RetrieveError, "virConnectGetMaxVcpus",
                                conn));

    return INT2NUM(result);
}

/*
 * call-seq:
 *   conn.node_get_info -> Libvirt::Connect::Nodeinfo
 *
 * Call +virNodeGetInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetInfo]
 * to retrieve information about the node for this connection.
 */
static VALUE libvirt_conn_node_get_info(VALUE s) {
    int r;
    virConnectPtr conn = connect_get(s);
    virNodeInfo nodeinfo;
    VALUE result;

    r = virNodeGetInfo(conn, &nodeinfo);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", conn));

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
 * to retrieve the amount of free memory available on the host for this
 * connection.
 */
static VALUE libvirt_conn_node_free_memory(VALUE s) {
    virConnectPtr conn = connect_get(s);
    unsigned long long freemem;

    freemem = virNodeGetFreeMemory(conn);

    _E(freemem == 0, create_error(e_RetrieveError, "virNodeGetFreeMemory",
                                  conn));

    return ULL2NUM(freemem);
}

/*
 * call-seq:
 *   conn.node_cells_free_memory(startCell=0, maxCells=#nodeCells) -> list
 *
 * Call +virNodeGetCellsFreeMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetCellsFreeMemory]
 * to retrieve the amount of free memory in each NUMA cell on the host for
 * this connection.
 */
static VALUE libvirt_conn_node_cells_free_memory(int argc, VALUE *argv, VALUE s) {
    int r;
    virConnectPtr conn = connect_get(s);
    VALUE cells;
    VALUE start, max;
    unsigned long long *freeMems;
    virNodeInfo nodeinfo;
    int i;
    unsigned int startCell, maxCells;

    rb_scan_args(argc, argv, "02", &start, &max);

    if (NIL_P(start))
        startCell = 0;
    else
        startCell = NUM2UINT(start);

    if (NIL_P(max)) {
        r = virNodeGetInfo(conn, &nodeinfo);
        _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", conn));
        maxCells = nodeinfo.nodes;
    }
    else
        maxCells = NUM2UINT(max);

    freeMems = ALLOC_N(unsigned long long, maxCells);

    r = virNodeGetCellsFreeMemory(conn, freeMems, startCell, maxCells);
    if (r < 0) {
        xfree(freeMems);
        rb_exc_raise(create_error(e_RetrieveError, "virNodeGetCellsFreeMemory",
                                  conn));
    }

    cells = rb_ary_new2(r);
    for (i = 0; i < r; i++)
        rb_ary_push(cells, ULL2NUM(freeMems[i]));
    xfree(freeMems);

    return cells;
}

#if HAVE_VIRNODEGETSECURITYMODEL
/*
 * call-seq:
 *   conn.node_get_security_model -> Libvirt::Connect::NodeSecurityModel
 *
 * Call +virNodeGetSecurityModel+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetSecurityModel]
 * to retrieve the security model in use on the host for this connection.
 */
static VALUE libvirt_conn_node_get_security_model(VALUE s) {
    virSecurityModel secmodel;
    virConnectPtr conn = connect_get(s);
    int r;
    VALUE result;

    r = virNodeGetSecurityModel(conn, &secmodel);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetSecurityModel", conn));

    result = rb_class_new_instance(0, NULL, c_node_security_model);
    rb_iv_set(result, "@model", rb_str_new2(secmodel.model));
    rb_iv_set(result, "@doi", rb_str_new2(secmodel.doi));

    return result;
}
#endif

#if HAVE_VIRCONNECTISENCRYPTED
/*
 * call-seq:
 *   conn.encrypted? -> [True|False]
 *
 * Call +virConnectIsEncrypted+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectIsEncrypted]
 * to determine if the connection is encrypted.
 */
static VALUE libvirt_conn_encrypted_p(VALUE s) {
    gen_call_truefalse(virConnectIsEncrypted, conn(s), connect_get(s));
}
#endif

#if HAVE_VIRCONNECTISSECURE
/*
 * call-seq:
 *   conn.secure? -> [True|False]
 *
 * Call +virConnectIsSecure+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectIsSecure]
 * to determine if the connection is secure.
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
 * to retrieve the capabilities XML for this connection.
 */
static VALUE libvirt_conn_capabilities(VALUE s) {
    gen_call_string(virConnectGetCapabilities, conn(s), 1, connect_get(s));
}

#if HAVE_VIRCONNECTCOMPARECPU
/*
 * call-seq:
 *   conn.compare_cpu(xml, flags=0) -> compareflag
 *
 * Call +virConnectCompareCPU+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectCompareCPU]
 * to compare the host CPU with the XML contained in xml.  Returns one of
 * Libvirt::CPU_COMPARE_ERROR, Libvirt::CPU_COMPARE_INCOMPATIBLE,
 * Libvirt::CPU_COMPARE_IDENTICAL, or Libvirt::CPU_COMPARE_SUPERSET.
 */
static VALUE libvirt_conn_compare_cpu(int argc, VALUE *argv, VALUE s) {
    VALUE xml, flags;
    int r;
    virConnectPtr conn = connect_get(s);

    rb_scan_args(argc, argv, "11", &xml, &flags);
    if (NIL_P(flags))
        flags = INT2FIX(0);

    r = virConnectCompareCPU(conn, StringValueCStr(xml), NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virConnectCompareCPU", conn));

    return INT2NUM(r);
}
#endif


#if HAVE_VIRCONNECTBASELINECPU
/*
 * call-seq:
 *   conn.baseline_cpu([xml, xml2, ...], flags=0) -> XML
 *
 * Call +virConnectBaselineCPU+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectBaselineCPU]
 * to compare the most feature-rich CPU which is compatible with all
 * given host CPUs.
 */
static VALUE libvirt_conn_baseline_cpu(int argc, VALUE *argv, VALUE s) {
    VALUE xmlcpus, flags_val;
    virConnectPtr conn = connect_get(s);
    char *r;
    VALUE retval;
    unsigned int ncpus, flags;
    VALUE entry;
    const char **xmllist;
    int i;
    int exception = 0;
    struct rb_ary_entry_arg arg;

    rb_scan_args(argc, argv, "11", &xmlcpus, &flags_val);
    if (NIL_P(flags_val))
        flags = 0;
    else
        flags = NUM2UINT(flags_val);

    Check_Type(xmlcpus, T_ARRAY);

    if (RARRAY_LEN(xmlcpus) < 1) {
        rb_raise(rb_eArgError, "wrong number of cpu arguments (%d for 1 or more)",
                 RARRAY_LEN(xmlcpus));
        return Qnil;
    }

    ncpus = RARRAY_LEN(xmlcpus);
    xmllist = ALLOC_N(const char *, ncpus);

    for (i = 0; i < ncpus; i++) {
        arg.arr = xmlcpus;
        arg.elem = i;
        entry = rb_protect(rb_ary_entry_wrap, (VALUE)&arg, &exception);
        if (exception) {
            xfree(xmllist);
            rb_jump_tag(exception);
        }

        xmllist[i] = (char *)rb_protect(rb_string_value_cstr_wrap,
                                        (VALUE)&entry, &exception);
        if (exception) {
            xfree(xmllist);
            rb_jump_tag(exception);
        }
    }

    r = virConnectBaselineCPU(conn, xmllist, ncpus, flags);
    xfree(xmllist);
    _E(r == NULL, create_error(e_RetrieveError, "virConnectBaselineCPU", conn));

    retval = rb_protect(rb_str_new2_wrap, (VALUE)&r, &exception);
    if (exception) {
        free(r);
        rb_jump_tag(exception);
    }

    free(r);

    return retval;
}
#endif

static int domain_event_lifecycle_callback(virConnectPtr conn,
                                           virDomainPtr dom, int event,
                                           int detail, void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event lifecycle callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 5, newc,
                   domain_new(dom, newc), INT2FIX(event), INT2FIX(detail),
                   cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 5, newc, domain_new(dom, newc),
                   INT2FIX(event), INT2FIX(detail), cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event lifecycle callback (expected Symbol or Proc)");

    return 0;
}

static int domain_event_reboot_callback(virConnectPtr conn, virDomainPtr dom,
                                        void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event reboot callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 3, newc,
                   domain_new(dom, newc), cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 3, newc, domain_new(dom, newc),
                   cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event reboot callback (expected Symbol or Proc)");

    return 0;
}

static int domain_event_rtc_callback(virConnectPtr conn, virDomainPtr dom,
                                     long long utc_offset, void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event rtc callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 4, newc,
                   domain_new(dom, newc), LL2NUM(utc_offset), cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 4, newc, domain_new(dom, newc),
                   LL2NUM(utc_offset), cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event rtc callback (expected Symbol or Proc)");

    return 0;
}

static int domain_event_watchdog_callback(virConnectPtr conn, virDomainPtr dom,
                                          int action, void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event watchdog callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 4, newc,
                   domain_new(dom, newc), INT2FIX(action), cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 4, newc, domain_new(dom, newc),
                   INT2FIX(action), cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event watchdog callback (expected Symbol or Proc)");

    return 0;
}

static int domain_event_io_error_callback(virConnectPtr conn, virDomainPtr dom,
                                          const char *src_path,
                                          const char *dev_alias,
                                          int action,
                                          void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event IO error callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 6, newc,
                   domain_new(dom, newc), rb_str_new2(src_path),
                   rb_str_new2(dev_alias), INT2FIX(action), cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 6, newc, domain_new(dom, newc),
                   rb_str_new2(src_path), rb_str_new2(dev_alias),
                   INT2FIX(action), cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event IO error callback (expected Symbol or Proc)");

    return 0;
}

static int domain_event_io_error_reason_callback(virConnectPtr conn,
                                                 virDomainPtr dom,
                                                 const char *src_path,
                                                 const char *dev_alias,
                                                 int action,
                                                 const char *reason,
                                                 void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event IO error reason callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 7, newc,
                   domain_new(dom, newc), rb_str_new2(src_path),
                   rb_str_new2(dev_alias), INT2FIX(action),
                   rb_str_new2(reason), cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 7, newc, domain_new(dom, newc),
                   rb_str_new2(src_path), rb_str_new2(dev_alias),
                   INT2FIX(action), rb_str_new2(reason), cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event IO error reason callback (expected Symbol or Proc)");

    return 0;
}

static int domain_event_graphics_callback(virConnectPtr conn, virDomainPtr dom,
                                          int phase,
                                          virDomainEventGraphicsAddressPtr local,
                                          virDomainEventGraphicsAddressPtr remote,
                                          const char *authScheme,
                                          virDomainEventGraphicsSubjectPtr subject,
                                          void *opaque) {
    VALUE passthrough = (VALUE)opaque;
    VALUE cb;
    VALUE cb_opaque;
    VALUE newc;
    VALUE local_hash;
    VALUE remote_hash;
    VALUE subject_array;
    VALUE pair;
    int i;

    if (TYPE(passthrough) != T_ARRAY)
        rb_raise(rb_eTypeError,
                 "wrong domain event graphics callback argument type (expected Array)");

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    local_hash = rb_hash_new();
    rb_hash_aset(local_hash, rb_str_new2("family"), INT2FIX(local->family));
    rb_hash_aset(local_hash, rb_str_new2("node"), rb_str_new2(local->node));
    rb_hash_aset(local_hash, rb_str_new2("service"),
                 rb_str_new2(local->service));

    remote_hash = rb_hash_new();
    rb_hash_aset(remote_hash, rb_str_new2("family"), INT2FIX(remote->family));
    rb_hash_aset(remote_hash, rb_str_new2("node"), rb_str_new2(remote->node));
    rb_hash_aset(remote_hash, rb_str_new2("service"),
                 rb_str_new2(remote->service));

    subject_array = rb_ary_new();
    for (i = 0; i < subject->nidentity; i++) {
        pair = rb_ary_new();
        rb_ary_store(pair, 0, rb_str_new2(subject->identities[i].type));
        rb_ary_store(pair, 1, rb_str_new2(subject->identities[i].name));

        rb_ary_store(subject_array, i, pair);
    }

    newc = connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0)
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 8, newc,
                   domain_new(dom, newc), INT2FIX(phase), local_hash,
                   remote_hash, rb_str_new2(authScheme), subject_array,
                   cb_opaque);
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0)
        rb_funcall(cb, rb_intern("call"), 8, newc, domain_new(dom, newc),
                   INT2FIX(phase), local_hash, remote_hash,
                   rb_str_new2(authScheme), subject_array, cb_opaque);
    else
        rb_raise(rb_eTypeError,
                 "wrong domain event graphics callback (expected Symbol or Proc)");

    return 0;
}

/*
 * call-seq:
 *   conn.domain_event_register_any(eventID, callback, dom=nil, opaque=nil) -> fixnum
 *
 * Call +virConnectDomainEventRegisterAny+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventRegisterAny]
 * to register callback for eventID with libvirt.  The eventID must be one of
 * the Libvirt::Connect::DOMAIN_EVENT_ID_* constants.  The callback can either
 * by a Symbol (that is the name of a method to callback) or a Proc.  Note that
 * the callback must accept different numbers of arguments depending on the
 * eventID passed in.  The arguments are as follows:
 *
 * - DOMAIN_EVENT_ID_LIFECYCLE: Libvirt::Connect, Libvirt::Domain, event, detail, opaque
 * - DOMAIN_EVENT_ID_REBOOT: Libvirt::Connect, Libvirt::Domain, opaque
 * - DOMAIN_EVENT_ID_RTC_CHANGE: Libvirt::Connect, Libvirt::Domain, utc_offset, opaque
 * - DOMAIN_EVENT_ID_WATCHDOG: Libvirt::Connect, Libvirt::Domain, action, opaque
 * - DOMAIN_EVENT_ID_IO_ERROR: Libvirt::Connect, Libvirt::Domain, src_path, dev_alias, action, opaque
 * - DOMAIN_EVENT_ID_IO_ERROR_REASON: Libvirt::Connect, Libvirt::Domain, src_path, dev_alias, action, reason, opaque
 * - DOMAIN_EVENT_ID_GRAPHICS: Libvirt::Connect, Libvirt::Domain, phase, local, remote, auth_scheme, subject, opaque

 * If dom is a valid Libvirt::Domain object, then only events from that
 * domain will be seen.  The opaque parameter can be any valid ruby type, and
 * will be passed into callback as "opaque".  This method returns a
 * libvirt-specific handle, which must be used by the application to
 * deregister the callback later (see domain_event_deregister_any).
 */
static VALUE libvirt_conn_domain_event_register_any(int argc, VALUE *argv,
                                                    VALUE c) {
    virConnectPtr conn = connect_get(c);
    VALUE eventID, cb, dom, opaque;
    virDomainPtr domain;
    virConnectDomainEventGenericCallback internalcb = NULL;
    int ret;
    VALUE passthrough;

    rb_scan_args(argc, argv, "22", &eventID, &cb, &dom, &opaque);

    if (!is_symbol_or_proc(cb))
        rb_raise(rb_eTypeError, "wrong argument type (expected Symbol or Proc)");

    if (NIL_P(dom))
        domain = NULL;
    else
        domain = domain_get(dom);

    switch(NUM2INT(eventID)) {
    case VIR_DOMAIN_EVENT_ID_LIFECYCLE:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_lifecycle_callback);
        break;
    case VIR_DOMAIN_EVENT_ID_REBOOT:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_reboot_callback);
        break;
    case VIR_DOMAIN_EVENT_ID_RTC_CHANGE:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_rtc_callback);
        break;
    case VIR_DOMAIN_EVENT_ID_WATCHDOG:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_watchdog_callback);
        break;
    case VIR_DOMAIN_EVENT_ID_IO_ERROR:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_io_error_callback);
        break;
    case VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_io_error_reason_callback);
        break;
    case VIR_DOMAIN_EVENT_ID_GRAPHICS:
        internalcb = VIR_DOMAIN_EVENT_CALLBACK(domain_event_graphics_callback);
        break;
    default:
        rb_raise(rb_eArgError, "invalid eventID argument %d",
                 NUM2INT(eventID));
        break;
    }

    passthrough = rb_ary_new();
    rb_ary_store(passthrough, 0, cb);
    rb_ary_store(passthrough, 1, opaque);

    ret = virConnectDomainEventRegisterAny(conn, domain, NUM2INT(eventID),
                                           internalcb, (void *)passthrough,
                                           NULL);

    _E(ret < 0, create_error(e_RetrieveError,
                             "virConnectDomainEventRegisterAny", conn));

    return INT2NUM(ret);
}

/*
 * call-seq:
 *   conn.domain_event_deregister_any(callbackID) -> nil
 *
 * Call +virConnectDomainEventDeregisterAny+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventDeregisterAny]
 * to deregister a callback from libvirt.  The callbackID must be a
 * libvirt-specific handle returned by domain_event_register_any.
 */
static VALUE libvirt_conn_domain_event_deregister_any(VALUE c,
                                                      VALUE callbackID) {
    gen_call_void(virConnectDomainEventDeregisterAny, conn(c), connect_get(c),
                  NUM2INT(callbackID));
}

/*
 * this is a bit of silliness.  Because libvirt internals track the address
 * of the function pointer, trying to use domain_event_lifecycle_callback
 * for both register and register_any would mean that we could only register
 * one or the other for lifecycle callbacks.  Instead we do a simple wrapper
 * so that the addresses are different
 */
static int domain_event_callback(virConnectPtr conn,
                                 virDomainPtr dom, int event,
                                 int detail, void *opaque) {
    return domain_event_lifecycle_callback(conn, dom, event, detail, opaque);
}
/*
 * call-seq:
 *   conn.domain_event_register(callback, opaque=nil) -> nil
 *
 * Call +virConnectDomainEventRegister+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventRegister]
 * to register callback for domain lifecycle events with libvirt.  The
 * callback can either by a Symbol (that is the name of a method to callback)
 * or a Proc.  The callback must accept 5 parameters: Libvirt::Connect,
 * Libvirt::Domain, event, detail, opaque.  The opaque parameter to
 * domain_event_register can be any valid ruby type, and will be passed into
 * callback as "opaque".  This method is deprecated in favor of
 * domain_event_register_any.
 */
static VALUE libvirt_conn_domain_event_register(int argc, VALUE *argv,
                                                VALUE c) {
    VALUE cb, opaque;
    VALUE passthrough;

    rb_scan_args(argc, argv, "11", &cb, &opaque);

    if (!is_symbol_or_proc(cb))
        rb_raise(rb_eTypeError, "wrong argument type (expected Symbol or Proc)");

    passthrough = rb_ary_new();
    rb_ary_store(passthrough, 0, cb);
    rb_ary_store(passthrough, 1, opaque);

    gen_call_void(virConnectDomainEventRegister, conn(c), connect_get(c),
                  domain_event_callback, (void *)passthrough, NULL);
}

/*
 * call-seq:
 *   conn.domain_event_deregister(callback) -> nil
 *
 * Call +virConnectDomainEventDeregister+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventDeregister]
 * to deregister the event callback from libvirt.  This method is deprecated
 * in favor of domain_event_deregister_any (though they cannot be mixed; if
 * the callback was registered with domain_event_register, it must be
 * deregistered with domain_event_deregister).
 */
static VALUE libvirt_conn_domain_event_deregister(VALUE c) {
    gen_call_void(virConnectDomainEventDeregister, conn(c), connect_get(c),
                  domain_event_callback);
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
#if HAVE_VIRNODEGETSECURITYMODEL
    rb_define_method(c_connect, "node_get_security_model",
                     libvirt_conn_node_get_security_model, 0);
#endif
#if HAVE_VIRCONNECTISENCRYPTED
    rb_define_method(c_connect, "encrypted?", libvirt_conn_encrypted_p, 0);
#endif
#if HAVE_VIRCONNECTISSECURE
    rb_define_method(c_connect, "secure?", libvirt_conn_secure_p, 0);
#endif
    rb_define_method(c_connect, "capabilities", libvirt_conn_capabilities, 0);

#if HAVE_VIRCONNECTCOMPARECPU
    rb_define_const(c_connect, "CPU_COMPARE_ERROR",
                    INT2NUM(VIR_CPU_COMPARE_ERROR));
    rb_define_const(c_connect, "CPU_COMPARE_INCOMPATIBLE",
                    INT2NUM(VIR_CPU_COMPARE_INCOMPATIBLE));
    rb_define_const(c_connect, "CPU_COMPARE_IDENTICAL",
                    INT2NUM(VIR_CPU_COMPARE_IDENTICAL));
    rb_define_const(c_connect, "CPU_COMPARE_SUPERSET",
                    INT2NUM(VIR_CPU_COMPARE_SUPERSET));

    rb_define_method(c_connect, "compare_cpu", libvirt_conn_compare_cpu, -1);
#endif

#if HAVE_VIRCONNECTBASELINECPU
    rb_define_method(c_connect, "baseline_cpu", libvirt_conn_baseline_cpu, -1);
#endif

    rb_define_const(c_connect, "DOMAIN_EVENT_DEFINED",
                    INT2NUM(VIR_DOMAIN_EVENT_DEFINED));
    rb_define_const(c_connect, "DOMAIN_EVENT_DEFINED_ADDED",
                    INT2NUM(VIR_DOMAIN_EVENT_DEFINED_ADDED));
    rb_define_const(c_connect, "DOMAIN_EVENT_DEFINED_UPDATED",
                    INT2NUM(VIR_DOMAIN_EVENT_DEFINED_UPDATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_UNDEFINED",
                    INT2NUM(VIR_DOMAIN_EVENT_UNDEFINED));
    rb_define_const(c_connect, "DOMAIN_EVENT_UNDEFINED_REMOVED",
                    INT2NUM(VIR_DOMAIN_EVENT_UNDEFINED_REMOVED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_BOOTED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_BOOTED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_MIGRATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_RESTORED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_RESTORED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_PAUSED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_PAUSED));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_IOERROR",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_IOERROR));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_WATCHDOG",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG));
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED));
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED_UNPAUSED",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED_UNPAUSED));
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED_MIGRATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_SHUTDOWN",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_DESTROYED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_DESTROYED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_CRASHED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_CRASHED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_MIGRATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_SAVED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_SAVED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_FAILED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_FAILED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT));
    rb_define_const(c_connect, "DOMAIN_EVENT_WATCHDOG_NONE",
                    INT2NUM(VIR_DOMAIN_EVENT_WATCHDOG_NONE));
    rb_define_const(c_connect, "DOMAIN_EVENT_WATCHDOG_PAUSE",
                    INT2NUM(VIR_DOMAIN_EVENT_WATCHDOG_PAUSE));
    rb_define_const(c_connect, "DOMAIN_EVENT_WATCHDOG_RESET",
                    INT2NUM(VIR_DOMAIN_EVENT_WATCHDOG_RESET));
    rb_define_const(c_connect, "DOMAIN_EVENT_WATCHDOG_POWEROFF",
                    INT2NUM(VIR_DOMAIN_EVENT_WATCHDOG_POWEROFF));
    rb_define_const(c_connect, "DOMAIN_EVENT_WATCHDOG_SHUTDOWN",
                    INT2NUM(VIR_DOMAIN_EVENT_WATCHDOG_SHUTDOWN));
    rb_define_const(c_connect, "DOMAIN_EVENT_WATCHDOG_DEBUG",
                    INT2NUM(VIR_DOMAIN_EVENT_WATCHDOG_DEBUG));
    rb_define_const(c_connect, "DOMAIN_EVENT_IO_ERROR_NONE",
                    INT2NUM(VIR_DOMAIN_EVENT_IO_ERROR_NONE));
    rb_define_const(c_connect, "DOMAIN_EVENT_IO_ERROR_PAUSE",
                    INT2NUM(VIR_DOMAIN_EVENT_IO_ERROR_PAUSE));
    rb_define_const(c_connect, "DOMAIN_EVENT_IO_ERROR_REPORT",
                    INT2NUM(VIR_DOMAIN_EVENT_IO_ERROR_REPORT));
    rb_define_const(c_connect, "DOMAIN_EVENT_GRAPHICS_CONNECT",
                    INT2NUM(VIR_DOMAIN_EVENT_GRAPHICS_CONNECT));
    rb_define_const(c_connect, "DOMAIN_EVENT_GRAPHICS_INITIALIZE",
                    INT2NUM(VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE));
    rb_define_const(c_connect, "DOMAIN_EVENT_GRAPHICS_DISCONNECT",
                    INT2NUM(VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT));
    rb_define_const(c_connect, "DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4",
                    INT2NUM(VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4));
    rb_define_const(c_connect, "DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV6",
                    INT2NUM(VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV6));

    rb_define_const(c_connect, "DOMAIN_EVENT_ID_LIFECYCLE",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_LIFECYCLE));
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_REBOOT",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_REBOOT));
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_RTC_CHANGE",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_RTC_CHANGE));
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_WATCHDOG",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_WATCHDOG));
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_IO_ERROR",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_IO_ERROR));
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_IO_ERROR_REASON",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON));
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_GRAPHICS",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_GRAPHICS));

    rb_define_method(c_connect, "domain_event_register",
                     libvirt_conn_domain_event_register, -1);
    rb_define_method(c_connect, "domain_event_deregister",
                     libvirt_conn_domain_event_deregister, 0);

    rb_define_method(c_connect, "domain_event_register_any",
                     libvirt_conn_domain_event_register_any, -1);
    rb_define_method(c_connect, "domain_event_deregister_any",
                     libvirt_conn_domain_event_deregister_any, 1);
}
