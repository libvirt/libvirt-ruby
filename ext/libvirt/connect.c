/*
 * connect.c: virConnect methods
 *
 * Copyright (C) 2007,2010 Red Hat Inc.
 * Copyright (C) 2013,2014 Chris Lalancette <clalancette@gmail.com>
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
#if HAVE_VIRDOMAINQEMUATTACH
#include <libvirt/libvirt-qemu.h>
#endif
#include <libvirt/virterror.h>
#include "extconf.h"
#include "common.h"
#include "domain.h"
#include "network.h"
#include "interface.h"
#include "nodedevice.h"
#include "nwfilter.h"
#include "secret.h"
#include "stream.h"

/*
 * Generate a call to a virConnectNumOf... function. C is the Ruby VALUE
 * holding the connection and OBJS is a token indicating what objects to
 * get the number of, e.g. 'Domains'
 */
#define gen_conn_num_of(c, objs)                                        \
    do {                                                                \
        int r;                                                          \
        r = virConnectNumOf##objs(ruby_libvirt_connect_get(c));         \
        ruby_libvirt_raise_error_if(r < 0, "virConnectNumOf" # objs, ruby_libvirt_connect_get(c)); \
        return INT2NUM(r);                                              \
    } while(0)

/*
 * Generate a call to a virConnectList... function. C is the Ruby VALUE
 * holding the connection and OBJS is a token indicating what objects to
 * get the number of, e.g. 'Domains' The list function must return an array
 * of strings, which is returned as a Ruby array
 */
#define gen_conn_list_names(c, objs, num)                               \
    do {                                                                \
        int r;                                                          \
        char **names;                                                   \
        if (num == 0) {                                                 \
            /* if num is 0, don't call virConnectList* function */      \
            return rb_ary_new2(num);                                    \
        }                                                               \
        names = alloca(sizeof(char *) * num);                           \
        r = virConnectList##objs(ruby_libvirt_connect_get(c), names, num); \
        ruby_libvirt_raise_error_if(r < 0, "virConnectList" # objs, ruby_libvirt_connect_get(c)); \
        return ruby_libvirt_generate_list(r, names);                    \
    } while(0)

static VALUE c_connect;

static void connect_close(void *c)
{
    int r;

    if (!c) {
        return;
    }
    r = virConnectClose((virConnectPtr) c);
    ruby_libvirt_raise_error_if(r < 0, "virConnectClose", c);
}

VALUE ruby_libvirt_connect_new(virConnectPtr c)
{
    return Data_Wrap_Struct(c_connect, NULL, connect_close, c);
}

VALUE ruby_libvirt_conn_attr(VALUE c)
{
    if (rb_obj_is_instance_of(c, c_connect) != Qtrue) {
        c = rb_iv_get(c, "@connection");
    }
    if (rb_obj_is_instance_of(c, c_connect) != Qtrue) {
        rb_raise(rb_eArgError, "Expected Connection object");
    }
    return c;
}

virConnectPtr ruby_libvirt_connect_get(VALUE c)
{
    c = ruby_libvirt_conn_attr(c);
    ruby_libvirt_get_struct(Connect, c);
}

/*
 * call-seq:
 *   conn.close -> nil
 *
 * Call virConnectClose[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectClose]
 * to close the connection.
 */
static VALUE libvirt_connect_close(VALUE c)
{
    virConnectPtr conn;

    Data_Get_Struct(c, virConnect, conn);
    if (conn) {
        connect_close(conn);
        DATA_PTR(c) = NULL;
    }
    return Qnil;
}

/*
 * call-seq:
 *   conn.closed? -> [True|False]
 *
 * Return +true+ if the connection is closed, +false+ if it is open.
 */
static VALUE libvirt_connect_closed_p(VALUE c)
{
    virConnectPtr conn;

    Data_Get_Struct(c, virConnect, conn);
    return (conn == NULL) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   conn.get_type -> String
 *
 * Call virConnectGetType[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetType]
 * to retrieve the type of hypervisor for this connection.
 */
static VALUE libvirt_connect_get_type(VALUE c)
{
    ruby_libvirt_generate_call_string(virConnectGetType,
                                      ruby_libvirt_connect_get(c), 0,
                                      ruby_libvirt_connect_get(c));
}

/*
 * call-seq:
 *   conn.get_version -> Fixnum
 *
 * Call virConnectGetVersion[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetVersion]
 * to retrieve the version of the hypervisor for this connection.
 */
static VALUE libvirt_connect_get_version(VALUE c)
{
    int r;
    unsigned long v;

    r = virConnectGetVersion(ruby_libvirt_connect_get(c), &v);
    ruby_libvirt_raise_error_if(r < 0, "virConnectGetVersion",
                                ruby_libvirt_connect_get(c));

    return ULONG2NUM(v);
}

#if HAVE_VIRCONNECTGETLIBVERSION
/*
 * call-seq:
 *   conn.get_lib_version -> Fixnum
 *
 * Call virConnectGetLibVersion[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetLibVersion]
 * to retrieve the version of the libvirt library for this connection.
 */
static VALUE libvirt_connect_get_lib_version(VALUE c)
{
    int r;
    unsigned long v;

    r = virConnectGetLibVersion(ruby_libvirt_connect_get(c), &v);
    ruby_libvirt_raise_error_if(r < 0, "virConnectGetLibVersion",
                                ruby_libvirt_connect_get(c));

    return ULONG2NUM(v);
}
#endif

/*
 * call-seq:
 *   conn.get_hostname -> String
 *
 * Call virConnectGetHostname[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetHostname]
 * to retrieve the hostname of the hypervisor for this connection.
 */
static VALUE libvirt_connect_get_hostname(VALUE c)
{
    ruby_libvirt_generate_call_string(virConnectGetHostname,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c));
}

/*
 * call-seq:
 *   conn.get_uri -> String
 *
 * Call virConnectGetURI[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetURI]
 * to retrieve the canonical URI for this connection.
 */
static VALUE libvirt_connect_get_uri(VALUE c)
{
    ruby_libvirt_generate_call_string(virConnectGetURI,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c));
}

/*
 * call-seq:
 *   conn.get_max_vcpus(type=nil) -> Fixnum
 *
 * Call virConnectGetMaxVcpus[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetMaxVcpus]
 * to retrieve the maximum number of virtual cpus supported by the hypervisor
 * for this connection.
 */
static VALUE libvirt_connect_get_max_vcpus(int argc, VALUE *argv, VALUE c)
{
    VALUE type;

    rb_scan_args(argc, argv, "01", &type);

    ruby_libvirt_generate_call_int(virConnectGetMaxVcpus,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_get_cstring_or_null(type));
}

/*
 * call-seq:
 *   conn.node_get_info -> Hash
 *
 * Call virNodeGetInfo[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetInfo]
 * to retrieve information about the node for this connection.
 */
static VALUE libvirt_connect_node_get_info(VALUE c)
{
    int r;
    virNodeInfo nodeinfo;
    VALUE result;

    r = virNodeGetInfo(ruby_libvirt_connect_get(c), &nodeinfo);
    ruby_libvirt_raise_error_if(r < 0, "virNodeGetInfo",
                                ruby_libvirt_connect_get(c));

    result = rb_hash_new();
    rb_hash_aset(result, rb_str_new2("model"), rb_str_new2(nodeinfo.model));
    rb_hash_aset(result, rb_str_new2("memory"), ULONG2NUM(nodeinfo.memory));
    rb_hash_aset(result, rb_str_new2("cpus"), UINT2NUM(nodeinfo.cpus));
    rb_hash_aset(result, rb_str_new2("mhz"), UINT2NUM(nodeinfo.mhz));
    rb_hash_aset(result, rb_str_new2("nodes"), UINT2NUM(nodeinfo.nodes));
    rb_hash_aset(result, rb_str_new2("sockets"), UINT2NUM(nodeinfo.sockets));
    rb_hash_aset(result, rb_str_new2("cores"), UINT2NUM(nodeinfo.cores));
    rb_hash_aset(result, rb_str_new2("threads"), UINT2NUM(nodeinfo.threads));

    return result;
}

/*
 * call-seq:
 *   conn.node_get_free_memory -> Fixnum
 *
 * Call virNodeGetFreeMemory[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetFreeMemory]
 * to retrieve the amount of free memory available on the host for this
 * connection.
 */
static VALUE libvirt_connect_node_get_free_memory(VALUE c)
{
    unsigned long long freemem;

    freemem = virNodeGetFreeMemory(ruby_libvirt_connect_get(c));

    ruby_libvirt_raise_error_if(freemem == 0, "virNodeGetFreeMemory",
                                ruby_libvirt_connect_get(c));

    return ULL2NUM(freemem);
}

/*
 * call-seq:
 *   conn.node_get_cells_free_memory(maxCells, startCell=0) -> list
 *
 * Call virNodeGetCellsFreeMemory[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetCellsFreeMemory]
 * to retrieve the amount of free memory in each NUMA cell on the host for
 * this connection.
 */
static VALUE libvirt_connect_node_get_cells_free_memory(int argc, VALUE *argv,
                                                        VALUE c)
{
    int i, r;
    VALUE cells, start, max;
    unsigned long long *freeMems;
    unsigned int maxCells;

    rb_scan_args(argc, argv, "11", &max, &start);

    maxCells = NUM2UINT(max);

    freeMems = alloca(sizeof(unsigned long long) * maxCells);

    r = virNodeGetCellsFreeMemory(ruby_libvirt_connect_get(c), freeMems,
                                  ruby_libvirt_value_to_int(start), maxCells);
    ruby_libvirt_raise_error_if(r < 0, "virNodeGetCellsFreeMemory",
                                ruby_libvirt_connect_get(c));

    cells = rb_ary_new2(r);
    for (i = 0; i < r; i++) {
        rb_ary_store(cells, i, ULL2NUM(freeMems[i]));
    }

    return cells;
}

#if HAVE_VIRNODEGETSECURITYMODEL
/*
 * call-seq:
 *   conn.node_get_security_model -> Hash
 *
 * Call virNodeGetSecurityModel[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetSecurityModel]
 * to retrieve the security model in use on the host for this connection.
 */
static VALUE libvirt_connect_node_get_security_model(VALUE c)
{
    virSecurityModel secmodel;
    int r;
    VALUE result;

    r = virNodeGetSecurityModel(ruby_libvirt_connect_get(c), &secmodel);
    ruby_libvirt_raise_error_if(r < 0, "virNodeGetSecurityModel",
                                ruby_libvirt_connect_get(c));

    result = rb_hash_new();
    rb_hash_aset(result, rb_str_new2("model"), rb_str_new2(secmodel.model));
    rb_hash_aset(result, rb_str_new2("doi"), rb_str_new2(secmodel.doi));

    return result;
}
#endif

#if HAVE_VIRCONNECTISENCRYPTED
/*
 * call-seq:
 *   conn.encrypted? -> [True|False]
 *
 * Call virConnectIsEncrypted[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectIsEncrypted]
 * to determine if the connection is encrypted.
 */
static VALUE libvirt_connect_encrypted_p(VALUE c)
{
    ruby_libvirt_generate_call_truefalse(virConnectIsEncrypted,
                                         ruby_libvirt_connect_get(c),
                                         ruby_libvirt_connect_get(c));
}
#endif

#if HAVE_VIRCONNECTISSECURE
/*
 * call-seq:
 *   conn.secure? -> [True|False]
 *
 * Call virConnectIsSecure[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectIsSecure]
 * to determine if the connection is secure.
 */
static VALUE libvirt_connect_secure_p(VALUE c)
{
    ruby_libvirt_generate_call_truefalse(virConnectIsSecure,
                                         ruby_libvirt_connect_get(c),
                                         ruby_libvirt_connect_get(c));
}
#endif

/*
 * call-seq:
 *   conn.get_capabilities -> String
 *
 * Call virConnectGetCapabilities[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetCapabilities]
 * to retrieve the capabilities XML for this connection.
 */
static VALUE libvirt_connect_get_capabilities(VALUE c)
{
    ruby_libvirt_generate_call_string(virConnectGetCapabilities,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c));
}

#if HAVE_VIRCONNECTCOMPARECPU
/*
 * call-seq:
 *   conn.compare_cpu(xml, flags=0) -> compareflag
 *
 * Call virConnectCompareCPU[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectCompareCPU]
 * to compare the host CPU with the XML contained in xml.  Returns one of
 * Libvirt::CPU_COMPARE_ERROR, Libvirt::CPU_COMPARE_INCOMPATIBLE,
 * Libvirt::CPU_COMPARE_IDENTICAL, or Libvirt::CPU_COMPARE_SUPERSET.
 */
static VALUE libvirt_connect_compare_cpu(int argc, VALUE *argv, VALUE c)
{
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    ruby_libvirt_generate_call_int(virConnectCompareCPU,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   StringValueCStr(xml),
                                   ruby_libvirt_value_to_uint(flags));
}
#endif


#if HAVE_VIRCONNECTBASELINECPU
/*
 * call-seq:
 *   conn.baseline_cpu([xml, xml2, ...], flags=0) -> XML
 *
 * Call virConnectBaselineCPU[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectBaselineCPU]
 * to compare the most feature-rich CPU which is compatible with all
 * given host CPUs.
 */
static VALUE libvirt_connect_baseline_cpu(int argc, VALUE *argv, VALUE c)
{
    VALUE xmlcpus, flags, retval, entry;
    char *r;
    unsigned int ncpus;
    const char **xmllist;
    int exception = 0;
    unsigned int i;

    rb_scan_args(argc, argv, "11", &xmlcpus, &flags);

    Check_Type(xmlcpus, T_ARRAY);

    if (RARRAY_LEN(xmlcpus) < 1) {
        rb_raise(rb_eArgError,
                 "wrong number of cpu arguments (%ld for 1 or more)",
                 RARRAY_LEN(xmlcpus));
    }

    ncpus = RARRAY_LEN(xmlcpus);
    xmllist = alloca(sizeof(const char *) * ncpus);

    for (i = 0; i < ncpus; i++) {
        entry = rb_ary_entry(xmlcpus, i);
        xmllist[i] = StringValueCStr(entry);
    }

    r = virConnectBaselineCPU(ruby_libvirt_connect_get(c), xmllist, ncpus,
                              ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(r == NULL, "virConnectBaselineCPU",
                                ruby_libvirt_connect_get(c));

    retval = rb_protect(ruby_libvirt_str_new2_wrap, (VALUE)&r, &exception);
    free(r);
    if (exception) {
        rb_jump_tag(exception);
    }

    return retval;
}
#endif

#if HAVE_VIRCONNECTDOMAINEVENTREGISTERANY || HAVE_VIRCONNECTDOMAINEVENTREGISTER
static int domain_event_lifecycle_callback(virConnectPtr conn,
                                           virDomainPtr dom, int event,
                                           int detail, void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 5, newc,
                   ruby_libvirt_domain_new(dom, newc), INT2NUM(event),
                   INT2NUM(detail), cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 5, newc,
                   ruby_libvirt_domain_new(dom, newc), INT2NUM(event),
                   INT2NUM(detail), cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event lifecycle callback (expected Symbol or Proc)");
    }

    return 0;
}
#endif

#if HAVE_VIRCONNECTDOMAINEVENTREGISTERANY
static int domain_event_reboot_callback(virConnectPtr conn, virDomainPtr dom,
                                        void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 3, newc,
                   ruby_libvirt_domain_new(dom, newc), cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 3, newc,
                   ruby_libvirt_domain_new(dom, newc), cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event reboot callback (expected Symbol or Proc)");
    }

    return 0;
}

static int domain_event_rtc_callback(virConnectPtr conn, virDomainPtr dom,
                                     long long utc_offset, void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 4, newc,
                   ruby_libvirt_domain_new(dom, newc), LL2NUM(utc_offset),
                   cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 4, newc,
                   ruby_libvirt_domain_new(dom, newc), LL2NUM(utc_offset),
                   cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event rtc callback (expected Symbol or Proc)");
    }

    return 0;
}

static int domain_event_watchdog_callback(virConnectPtr conn, virDomainPtr dom,
                                          int action, void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 4, newc,
                   ruby_libvirt_domain_new(dom, newc), INT2NUM(action),
                   cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 4, newc,
                   ruby_libvirt_domain_new(dom, newc), INT2NUM(action),
                   cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event watchdog callback (expected Symbol or Proc)");
    }

    return 0;
}

static int domain_event_io_error_callback(virConnectPtr conn, virDomainPtr dom,
                                          const char *src_path,
                                          const char *dev_alias,
                                          int action,
                                          void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 6, newc,
                   ruby_libvirt_domain_new(dom, newc), rb_str_new2(src_path),
                   rb_str_new2(dev_alias), INT2NUM(action), cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 6, newc,
                   ruby_libvirt_domain_new(dom, newc),
                   rb_str_new2(src_path), rb_str_new2(dev_alias),
                   INT2NUM(action), cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event IO error callback (expected Symbol or Proc)");
    }

    return 0;
}

static int domain_event_io_error_reason_callback(virConnectPtr conn,
                                                 virDomainPtr dom,
                                                 const char *src_path,
                                                 const char *dev_alias,
                                                 int action,
                                                 const char *reason,
                                                 void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 7, newc,
                   ruby_libvirt_domain_new(dom, newc), rb_str_new2(src_path),
                   rb_str_new2(dev_alias), INT2NUM(action),
                   rb_str_new2(reason), cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 7, newc,
                   ruby_libvirt_domain_new(dom, newc),
                   rb_str_new2(src_path), rb_str_new2(dev_alias),
                   INT2NUM(action), rb_str_new2(reason), cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event IO error reason callback (expected Symbol or Proc)");
    }

    return 0;
}

static int domain_event_graphics_callback(virConnectPtr conn, virDomainPtr dom,
                                          int phase,
                                          virDomainEventGraphicsAddressPtr local,
                                          virDomainEventGraphicsAddressPtr remote,
                                          const char *authScheme,
                                          virDomainEventGraphicsSubjectPtr subject,
                                          void *opaque)
{
    VALUE passthrough = (VALUE)opaque;
    VALUE cb, cb_opaque, newc, local_hash, remote_hash, subject_array, pair;
    int i;

    Check_Type(passthrough, T_ARRAY);

    if (RARRAY_LEN(passthrough) != 2) {
        rb_raise(rb_eArgError, "wrong number of arguments (%ld for 2)",
                 RARRAY_LEN(passthrough));
    }

    cb = rb_ary_entry(passthrough, 0);
    cb_opaque = rb_ary_entry(passthrough, 1);

    local_hash = rb_hash_new();
    rb_hash_aset(local_hash, rb_str_new2("family"), INT2NUM(local->family));
    rb_hash_aset(local_hash, rb_str_new2("node"), rb_str_new2(local->node));
    rb_hash_aset(local_hash, rb_str_new2("service"),
                 rb_str_new2(local->service));

    remote_hash = rb_hash_new();
    rb_hash_aset(remote_hash, rb_str_new2("family"), INT2NUM(remote->family));
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

    newc = ruby_libvirt_connect_new(conn);
    if (strcmp(rb_obj_classname(cb), "Symbol") == 0) {
        rb_funcall(rb_class_of(cb), rb_to_id(cb), 8, newc,
                   ruby_libvirt_domain_new(dom, newc), INT2NUM(phase),
                   local_hash, remote_hash, rb_str_new2(authScheme),
                   subject_array, cb_opaque);
    }
    else if (strcmp(rb_obj_classname(cb), "Proc") == 0) {
        rb_funcall(cb, rb_intern("call"), 8, newc,
                   ruby_libvirt_domain_new(dom, newc), INT2NUM(phase),
                   local_hash, remote_hash, rb_str_new2(authScheme),
                   subject_array, cb_opaque);
    }
    else {
        rb_raise(rb_eTypeError,
                 "wrong domain event graphics callback (expected Symbol or Proc)");
    }

    return 0;
}

/*
 * call-seq:
 *   conn.domain_event_register_any(eventID, callback, dom=nil, opaque=nil) -> Fixnum
 *
 * Call virConnectDomainEventRegisterAny[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventRegisterAny]
 * to register callback for eventID with libvirt.  The eventID must be one of
 * the Libvirt::Connect::DOMAIN_EVENT_ID_* constants.  The callback can either
 * be a Symbol (that is the name of a method to callback) or a Proc.  Note that
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
static VALUE libvirt_connect_domain_event_register_any(int argc, VALUE *argv,
                                                       VALUE c)
{
    VALUE eventID, cb, dom, opaque, passthrough;
    virDomainPtr domain;
    virConnectDomainEventGenericCallback internalcb = NULL;

    rb_scan_args(argc, argv, "22", &eventID, &cb, &dom, &opaque);

    if (!ruby_libvirt_is_symbol_or_proc(cb)) {
        rb_raise(rb_eTypeError,
                 "wrong argument type (expected Symbol or Proc)");
    }

    if (NIL_P(dom)) {
        domain = NULL;
    }
    else {
        domain = ruby_libvirt_domain_get(dom);
    }

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

    ruby_libvirt_generate_call_int(virConnectDomainEventRegisterAny,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c), domain,
                                   NUM2INT(eventID), internalcb,
                                   (void *)passthrough, NULL);
}

/*
 * call-seq:
 *   conn.domain_event_deregister_any(callbackID) -> nil
 *
 * Call virConnectDomainEventDeregisterAny[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventDeregisterAny]
 * to deregister a callback from libvirt.  The callbackID must be a
 * libvirt-specific handle returned by domain_event_register_any.
 */
static VALUE libvirt_connect_domain_event_deregister_any(VALUE c,
                                                         VALUE callbackID)
{
    ruby_libvirt_generate_call_nil(virConnectDomainEventDeregisterAny,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   NUM2INT(callbackID));
}
#endif

#if HAVE_VIRCONNECTDOMAINEVENTREGISTER
/*
 * this is a bit of silliness.  Because libvirt internals track the address
 * of the function pointer, trying to use domain_event_lifecycle_callback
 * for both register and register_any would mean that we could only register
 * one or the other for lifecycle callbacks.  Instead we do a simple wrapper
 * so that the addresses are different
 */
static int domain_event_callback(virConnectPtr conn,
                                 virDomainPtr dom, int event,
                                 int detail, void *opaque)
{
    return domain_event_lifecycle_callback(conn, dom, event, detail, opaque);
}
/*
 * call-seq:
 *   conn.domain_event_register(callback, opaque=nil) -> nil
 *
 * Call virConnectDomainEventRegister[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventRegister]
 * to register callback for domain lifecycle events with libvirt.  The
 * callback can either be a Symbol (that is the name of a method to callback)
 * or a Proc.  The callback must accept 5 parameters: Libvirt::Connect,
 * Libvirt::Domain, event, detail, opaque.  The opaque parameter to
 * domain_event_register can be any valid ruby type, and will be passed into
 * callback as "opaque".  This method is deprecated in favor of
 * domain_event_register_any.
 */
static VALUE libvirt_connect_domain_event_register(int argc, VALUE *argv,
                                                   VALUE c)
{
    VALUE cb, opaque, passthrough;

    rb_scan_args(argc, argv, "11", &cb, &opaque);

    if (!ruby_libvirt_is_symbol_or_proc(cb)) {
        rb_raise(rb_eTypeError,
                 "wrong argument type (expected Symbol or Proc)");
    }

    passthrough = rb_ary_new();
    rb_ary_store(passthrough, 0, cb);
    rb_ary_store(passthrough, 1, opaque);

    ruby_libvirt_generate_call_nil(virConnectDomainEventRegister,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   domain_event_callback, (void *)passthrough,
                                   NULL);
}

/*
 * call-seq:
 *   conn.domain_event_deregister(callback) -> nil
 *
 * Call virConnectDomainEventDeregister[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainEventDeregister]
 * to deregister the event callback from libvirt.  This method is deprecated
 * in favor of domain_event_deregister_any (though they cannot be mixed; if
 * the callback was registered with domain_event_register, it must be
 * deregistered with domain_event_deregister).
 */
static VALUE libvirt_connect_domain_event_deregister(VALUE c)
{
    ruby_libvirt_generate_call_nil(virConnectDomainEventDeregister,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   domain_event_callback);
}
#endif

/*
 * call-seq:
 *   conn.num_of_domains -> Fixnum
 *
 * Call virConnectNumOfDomains[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDomains]
 * to retrieve the number of active domains on this connection.
 */
static VALUE libvirt_connect_num_of_domains(VALUE c)
{
    gen_conn_num_of(c, Domains);
}

/*
 * call-seq:
 *   conn.list_domains(num) -> list
 *
 * Call virConnectListDomains[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDomains]
 * to retrieve a list of active domain IDs on this connection.
 */
static VALUE libvirt_connect_list_domains(VALUE c, VALUE num)
{
    int i, r, *ids;
    VALUE result;
    int numd;

    numd = NUM2INT(num);
    result = rb_ary_new2(numd);

    if (numd == 0) {
        return result;
    }

    ids = alloca(sizeof(int) * numd);
    r = virConnectListDomains(ruby_libvirt_connect_get(c), ids, numd);
    ruby_libvirt_raise_error_if(r < 0, "virConnectListDomains",
                                ruby_libvirt_connect_get(c));

    for (i = 0; i < numd; i++) {
        rb_ary_store(result, i, INT2NUM(ids[i]));
    }

    return result;
}

/*
 * call-seq:
 *   conn.num_of_defined_domains -> Fixnum
 *
 * Call virConnectNumOfDefinedDomains[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDefinedDomains]
 * to retrieve the number of inactive domains on this connection.
 */
static VALUE libvirt_connect_num_of_defined_domains(VALUE c)
{
    gen_conn_num_of(c, DefinedDomains);
}

/*
 * call-seq:
 *   conn.list_defined_domains(num) -> list
 *
 * Call virConnectListDefinedDomains[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDefinedDomains]
 * to retrieve a list of inactive domain names on this connection.
 */
static VALUE libvirt_connect_list_defined_domains(VALUE c, VALUE num)
{
    gen_conn_list_names(c, DefinedDomains, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.create_domain_linux(xml, flags=0) -> Libvirt::Domain
 *
 * Call virDomainCreateLinux[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCreateLinux]
 * to start a transient domain from the given XML.  Deprecated; use
 * conn.create_domain_xml instead.
 */
static VALUE libvirt_connect_create_linux(int argc, VALUE *argv, VALUE c)
{
    virDomainPtr dom;
    VALUE flags, xml;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    dom = virDomainCreateLinux(ruby_libvirt_connect_get(c),
                               StringValueCStr(xml),
                               ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainCreateLinux",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}

#if HAVE_VIRDOMAINCREATEXML
/*
 * call-seq:
 *   conn.domain_create_xml(xml, flags=0) -> Libvirt::Domain
 *
 * Call virDomainCreateXML[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCreateXML]
 * to start a transient domain from the given XML.
 */
static VALUE libvirt_connect_domain_create_xml(int argc, VALUE *argv, VALUE c)
{
    virDomainPtr dom;
    VALUE flags, xml;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    dom = virDomainCreateXML(ruby_libvirt_connect_get(c), StringValueCStr(xml),
                             ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainCreateXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}
#endif

/*
 * call-seq:
 *   conn.domain_lookup_by_name(name) -> Libvirt::Domain
 *
 * Call virDomainLookupByName[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainLookupByName]
 * to retrieve a domain object for name.
 */
static VALUE libvirt_connect_domain_lookup_by_name(VALUE c, VALUE name)
{
    virDomainPtr dom;

    dom = virDomainLookupByName(ruby_libvirt_connect_get(c),
                                StringValueCStr(name));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainLookupByName",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.domain_lookup_by_id(id) -> Libvirt::Domain
 *
 * Call virDomainLookupByID[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainLookupByID]
 * to retrieve a domain object for id.
 */
static VALUE libvirt_connect_domain_lookup_by_id(VALUE c, VALUE id)
{
    virDomainPtr dom;

    dom = virDomainLookupByID(ruby_libvirt_connect_get(c), NUM2INT(id));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainLookupByID",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.domain_lookup_by_uuid_string(uuid) -> Libvirt::Domain
 *
 * Call virDomainLookupByUUIDString[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainLookupByUUIDString]
 * to retrieve a domain object for uuid.
 */
static VALUE libvirt_connect_domain_lookup_by_uuid_string(VALUE c, VALUE uuid)
{
    virDomainPtr dom;

    dom = virDomainLookupByUUIDString(ruby_libvirt_connect_get(c),
                                      StringValueCStr(uuid));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainLookupByUUID",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.domain_define_xml(xml) -> Libvirt::Domain
 *
 * Call virDomainDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainDefineXML]
 * to define a permanent domain on this connection.
 */
static VALUE libvirt_connect_domain_define_xml(VALUE c, VALUE xml)
{
    virDomainPtr dom;

    dom = virDomainDefineXML(ruby_libvirt_connect_get(c), StringValueCStr(xml));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainDefineXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}

#if HAVE_VIRCONNECTDOMAINXMLFROMNATIVE
/*
 * call-seq:
 *   conn.domain_xml_from_native(nativeFormat, xml, flags=0) -> String
 *
 * Call virConnectDomainXMLFromNative[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainXMLFromNative]
 * to convert a native hypervisor domain representation to libvirt XML.
 */
static VALUE libvirt_connect_domain_xml_from_native(int argc, VALUE *argv,
                                                    VALUE c)
{
    VALUE nativeFormat, xml, flags;

    rb_scan_args(argc, argv, "21", &nativeFormat, &xml, &flags);

    ruby_libvirt_generate_call_string(virConnectDomainXMLFromNative,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c),
                                      StringValueCStr(nativeFormat),
                                      StringValueCStr(xml),
                                      ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_VIRCONNECTDOMAINXMLTONATIVE
/*
 * call-seq:
 *   conn.domain_xml_to_native(nativeFormat, xml, flags=0) -> String
 *
 * Call virConnectDomainXMLToNative[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainXMLToNative]
 * to convert libvirt XML to a native domain hypervisor representation.
 */
static VALUE libvirt_connect_domain_xml_to_native(int argc, VALUE *argv,
                                                  VALUE c)
{
    VALUE nativeFormat, xml, flags;

    rb_scan_args(argc, argv, "21", &nativeFormat, &xml, &flags);

    ruby_libvirt_generate_call_string(virConnectDomainXMLToNative,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c),
                                      StringValueCStr(nativeFormat),
                                      StringValueCStr(xml),
                                      ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_TYPE_VIRINTERFACEPTR
/*
 * call-seq:
 *   conn.num_of_interfaces -> Fixnum
 *
 * Call virConnectNumOfInterfaces[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfInterfaces]
 * to retrieve the number of active interfaces on this connection.
 */
static VALUE libvirt_connect_num_of_interfaces(VALUE c)
{
    gen_conn_num_of(c, Interfaces);
}

/*
 * call-seq:
 *   conn.list_interfaces(num) -> list
 *
 * Call virConnectListInterfaces[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListInterfaces]
 * to retrieve a list of active interface names on this connection.
 */
static VALUE libvirt_connect_list_interfaces(VALUE c, VALUE num)
{
    gen_conn_list_names(c, Interfaces, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.num_of_defined_interfaces -> Fixnum
 *
 * Call virConnectNumOfDefinedInterfaces[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDefinedInterfaces]
 * to retrieve the number of inactive interfaces on this connection.
 */
static VALUE libvirt_connect_num_of_defined_interfaces(VALUE c)
{
    gen_conn_num_of(c, DefinedInterfaces);
}

/*
 * call-seq:
 *   conn.list_defined_interfaces(num) -> list
 *
 * Call virConnectListDefinedInterfaces[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDefinedInterfaces]
 * to retrieve a list of inactive interface names on this connection.
 */
static VALUE libvirt_connect_list_defined_interfaces(VALUE c, VALUE num)
{
    gen_conn_list_names(c, DefinedInterfaces, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.interface_lookup_by_name(name) -> Libvirt::Interface
 *
 * Call virInterfaceLookupByName[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceLookupByName]
 * to retrieve an interface object by name.
 */
static VALUE libvirt_connect_interface_lookup_by_name(VALUE c, VALUE name)
{
    virInterfacePtr iface;

    iface = virInterfaceLookupByName(ruby_libvirt_connect_get(c),
                                     StringValueCStr(name));
    ruby_libvirt_raise_error_if(iface == NULL, "virInterfaceLookupByName",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_interface_new(iface, c);
}

/*
 * call-seq:
 *   conn.interface_lookup_by_mac(mac) -> Libvirt::Interface
 *
 * Call virInterfaceLookupByMACString[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceLookupByMACString]
 * to retrieve an interface object by MAC address.
 */
static VALUE libvirt_connect_interface_lookup_by_mac(VALUE c, VALUE mac)
{
    virInterfacePtr iface;

    iface = virInterfaceLookupByMACString(ruby_libvirt_connect_get(c),
                                          StringValueCStr(mac));
    ruby_libvirt_raise_error_if(iface == NULL, "virInterfaceLookupByMACString",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_interface_new(iface, c);
}

/*
 * call-seq:
 *   conn.interface_define_xml(xml, flags=0) -> Libvirt::Interface
 *
 * Call virInterfaceDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceDefineXML]
 * to define a new interface from xml.
 */
static VALUE libvirt_connect_interface_define_xml(int argc, VALUE *argv,
                                                  VALUE c)
{
    virInterfacePtr iface;
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    iface = virInterfaceDefineXML(ruby_libvirt_connect_get(c),
                                  StringValueCStr(xml),
                                  ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(iface == NULL, "virInterfaceDefineXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_interface_new(iface, c);
}
#endif

/*
 * call-seq:
 *   conn.num_of_networks -> Fixnum
 *
 * Call virConnectNumOfNetworks[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfNetworks]
 * to retrieve the number of active networks on this connection.
 */
static VALUE libvirt_connect_num_of_networks(VALUE c)
{
    gen_conn_num_of(c, Networks);
}

/*
 * call-seq:
 *   conn.list_networks(num) -> list
 *
 * Call virConnectListNetworks[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListNetworks]
 * to retrieve a list of active network names on this connection.
 */
static VALUE libvirt_connect_list_networks(VALUE c, VALUE num)
{
    gen_conn_list_names(c, Networks, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.num_of_defined_networks -> Fixnum
 *
 * Call virConnectNumOfDefinedNetworks[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDefinedNetworks]
 * to retrieve the number of inactive networks on this connection.
 */
static VALUE libvirt_connect_num_of_defined_networks(VALUE c)
{
    gen_conn_num_of(c, DefinedNetworks);
}

/*
 * call-seq:
 *   conn.list_of_defined_networks(num) -> list
 *
 * Call virConnectListDefinedNetworks[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDefinedNetworks]
 * to retrieve a list of inactive network names on this connection.
 */
static VALUE libvirt_connect_list_defined_networks(VALUE c, VALUE num)
{
    gen_conn_list_names(c, DefinedNetworks, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.network_lookup_by_name(name) -> Libvirt::Network
 *
 * Call virNetworkLookupByName[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkLookupByName]
 * to retrieve a network object by name.
 */
static VALUE libvirt_connect_network_lookup_by_name(VALUE c, VALUE name)
{
    virNetworkPtr netw;

    netw = virNetworkLookupByName(ruby_libvirt_connect_get(c),
                                  StringValueCStr(name));
    ruby_libvirt_raise_error_if(netw == NULL, "virNetworkLookupByName",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_network_new(netw, c);
}

/*
 * call-seq:
 *   conn.network_lookup_by_uuid_string(uuid) -> Libvirt::Network
 *
 * Call virNetworkLookupByUUIDString[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkLookupByUUIDString]
 * to retrieve a network object by UUID.
 */
static VALUE libvirt_connect_network_lookup_by_uuid_string(VALUE c, VALUE uuid)
{
    virNetworkPtr netw;

    netw = virNetworkLookupByUUIDString(ruby_libvirt_connect_get(c),
                                        StringValueCStr(uuid));
    ruby_libvirt_raise_error_if(netw == NULL, "virNetworkLookupByUUID",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_network_new(netw, c);
}

/*
 * call-seq:
 *   conn.network_create_xml(xml) -> Libvirt::Network
 *
 * Call virNetworkCreateXML[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkCreateXML]
 * to start a new transient network from xml.
 */
static VALUE libvirt_connect_network_create_xml(VALUE c, VALUE xml)
{
    virNetworkPtr netw;

    netw = virNetworkCreateXML(ruby_libvirt_connect_get(c),
                               StringValueCStr(xml));
    ruby_libvirt_raise_error_if(netw == NULL, "virNetworkCreateXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_network_new(netw, c);
}

/*
 * call-seq:
 *   conn.network_define_xml(xml) -> Libvirt::Network
 *
 * Call virNetworkDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkDefineXML]
 * to define a new permanent network from xml.
 */
static VALUE libvirt_connect_network_define_xml(VALUE c, VALUE xml)
{
    virNetworkPtr netw;

    netw = virNetworkDefineXML(ruby_libvirt_connect_get(c),
                               StringValueCStr(xml));
    ruby_libvirt_raise_error_if(netw == NULL, "virNetworkDefineXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_network_new(netw, c);
}

#if HAVE_TYPE_VIRNODEDEVICEPTR

/*
 * call-seq:
 *   conn.node_num_of_devices(cap=nil, flags=0) -> Fixnum
 *
 * Call virNodeNumOfDevices[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeNumOfDevices]
 * to retrieve the number of node devices on this connection.
 */
static VALUE libvirt_connect_node_num_of_devices(int argc, VALUE *argv, VALUE c)
{
    VALUE cap, flags;

    rb_scan_args(argc, argv, "02", &cap, &flags);

    ruby_libvirt_generate_call_int(virNodeNumOfDevices,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_get_cstring_or_null(cap),
                                   ruby_libvirt_value_to_uint(flags));
}

/*
 * call-seq:
 *   conn.node_list_devices(num, cap=nil, flags=0) -> list
 *
 * Call virNodeListDevices[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeListDevices]
 * to retrieve a list of node device names on this connection.
 */
static VALUE libvirt_connect_node_list_devices(int argc, VALUE *argv, VALUE c)
{
    int r, numd;
    VALUE cap, flags, num;
    char **names;

    rb_scan_args(argc, argv, "12", &num, &cap, &flags);

    numd = NUM2INT(num);

    if (numd == 0) {
        /* if num is 0, don't call virNodeListDevices function */
        return rb_ary_new2(numd);
    }

    names = alloca(sizeof(char *) * numd);
    r = virNodeListDevices(ruby_libvirt_connect_get(c),
                           ruby_libvirt_get_cstring_or_null(cap), names, numd,
                           ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(r < 0, "virNodeListDevices",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_generate_list(r, names);
}

/*
 * call-seq:
 *   conn.node_device_lookup_by_name(name) -> Libvirt::NodeDevice
 *
 * Call virNodeDeviceLookupByName[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceLookupByName]
 * to retrieve a nodedevice object by name.
 */
static VALUE libvirt_connect_node_device_lookup_by_name(VALUE c, VALUE name)
{
    virNodeDevicePtr nodedev;

    nodedev = virNodeDeviceLookupByName(ruby_libvirt_connect_get(c),
                                        StringValueCStr(name));
    ruby_libvirt_raise_error_if(nodedev == NULL, "virNodeDeviceLookupByName",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_nodedevice_new(nodedev, c);

}

#if HAVE_VIRNODEDEVICECREATEXML
/*
 * call-seq:
 *   conn.node_device_create_xml(xml, flags=0) -> Libvirt::NodeDevice
 *
 * Call virNodeDeviceCreateXML[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceCreateXML]
 * to create a new node device from xml.
 */
static VALUE libvirt_connect_node_device_create_xml(int argc, VALUE *argv,
                                                    VALUE c)
{
    virNodeDevicePtr nodedev;
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    nodedev = virNodeDeviceCreateXML(ruby_libvirt_connect_get(c),
                                     StringValueCStr(xml),
                                     ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(nodedev == NULL, "virNodeDeviceCreateXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_nodedevice_new(nodedev, c);
}
#endif
#endif

#if HAVE_TYPE_VIRNWFILTERPTR

/*
 * call-seq:
 *   conn.num_of_nwfilters -> Fixnum
 *
 * Call virConnectNumOfNWFilters[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfNWFilters]
 * to retrieve the number of network filters on this connection.
 */
static VALUE libvirt_connect_num_of_nwfilters(VALUE c)
{
    gen_conn_num_of(c, NWFilters);
}

/*
 * call-seq:
 *   conn.list_nwfilters(num) -> list
 *
 * Call virConnectListNWFilters[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListNWFilters]
 * to retrieve a list of network filter names on this connection.
 */
static VALUE libvirt_connect_list_nwfilters(VALUE c, VALUE num)
{
    gen_conn_list_names(c, NWFilters, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.nwfilter_lookup_by_name(name) -> Libvirt::NWFilter
 *
 * Call virNWFilterLookupByName[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterLookupByName]
 * to retrieve a network filter object by name.
 */
static VALUE libvirt_connect_nwfilter_lookup_by_name(VALUE c, VALUE name)
{
    virNWFilterPtr nwfilter;

    nwfilter = virNWFilterLookupByName(ruby_libvirt_connect_get(c),
                                       StringValueCStr(name));
    ruby_libvirt_raise_error_if(nwfilter == NULL, "virNWFilterLookupByName",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_nwfilter_new(nwfilter, c);
}

/*
 * call-seq:
 *   conn.nwfilter_lookup_by_uuid_string(uuid) -> Libvirt::NWFilter
 *
 * Call virNWFilterLookupByUUIDString[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterLookupByUUIDString]
 * to retrieve a network filter object by UUID.
 */
static VALUE libvirt_connect_nwfilter_lookup_by_uuid_string(VALUE c, VALUE uuid)
{
    virNWFilterPtr nwfilter;

    nwfilter = virNWFilterLookupByUUIDString(ruby_libvirt_connect_get(c),
                                             StringValueCStr(uuid));
    ruby_libvirt_raise_error_if(nwfilter == NULL,
                                "virNWFilterLookupByUUIDString",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_nwfilter_new(nwfilter, c);
}

/*
 * call-seq:
 *   conn.nwfilter_define_xml(xml) -> Libvirt::NWFilter
 *
 * Call virNWFilterDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterDefineXML]
 * to define a new network filter from xml.
 */
static VALUE libvirt_connect_nwfilter_define_xml(VALUE c, VALUE xml)
{
    virNWFilterPtr nwfilter;

    nwfilter = virNWFilterDefineXML(ruby_libvirt_connect_get(c),
                                    StringValueCStr(xml));
    ruby_libvirt_raise_error_if(nwfilter == NULL, "virNWFilterDefineXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_nwfilter_new(nwfilter, c);
}
#endif

#if HAVE_TYPE_VIRSECRETPTR

/*
 * call-seq:
 *   conn.num_of_secrets -> Fixnum
 *
 * Call virConnectNumOfSecrets[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfSecrets]
 * to retrieve the number of secrets on this connection.
 */
static VALUE libvirt_connect_num_of_secrets(VALUE c)
{
    gen_conn_num_of(c, Secrets);
}

/*
 * call-seq:
 *   conn.list_secrets(num) -> list
 *
 * Call virConnectListSecrets[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListSecrets]
 * to retrieve a list of secret UUIDs on this connection.
 */
static VALUE libvirt_connect_list_secrets(VALUE c, VALUE num)
{
    gen_conn_list_names(c, Secrets, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.secret_lookup_by_uuid_string(uuid) -> Libvirt::Secret
 *
 * Call virSecretLookupByUUIDString[http://www.libvirt.org/html/libvirt-libvirt.html#virSecretLookupByUUIDString]
 * to retrieve a secret object from uuid.
 */
static VALUE libvirt_connect_secret_lookup_by_uuid_string(VALUE c, VALUE uuid)
{
    virSecretPtr secret;

    secret = virSecretLookupByUUIDString(ruby_libvirt_connect_get(c),
                                         StringValueCStr(uuid));
    ruby_libvirt_raise_error_if(secret == NULL, "virSecretLookupByUUID",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_secret_new(secret, c);
}

/*
 * call-seq:
 *   conn.secret_lookup_by_usage(usagetype, usageID) -> Libvirt::Secret
 *
 * Call virSecretLookupByUsage[http://www.libvirt.org/html/libvirt-libvirt.html#virSecretLookupByUsage]
 * to retrieve a secret by usagetype.
 */
static VALUE libvirt_connect_secret_lookup_by_usage(VALUE c, VALUE usagetype,
                                                    VALUE usageID)
{
    virSecretPtr secret;

    secret = virSecretLookupByUsage(ruby_libvirt_connect_get(c),
                                    NUM2UINT(usagetype),
                                    StringValueCStr(usageID));
    ruby_libvirt_raise_error_if(secret == NULL, "virSecretLookupByUsage",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_secret_new(secret, c);
}

/*
 * call-seq:
 *   conn.secret_define_xml(xml, flags=0) -> Libvirt::Secret
 *
 * Call virSecretDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virSecretDefineXML]
 * to define a new secret from xml.
 */
static VALUE libvirt_connect_secret_define_xml(int argc, VALUE *argv, VALUE c)
{
    virSecretPtr secret;
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    secret = virSecretDefineXML(ruby_libvirt_connect_get(c),
                                StringValueCStr(xml),
                                ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(secret == NULL, "virSecretDefineXML",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_secret_new(secret, c);
}
#endif

#if HAVE_TYPE_VIRSTORAGEPOOLPTR

VALUE pool_new(virStoragePoolPtr n, VALUE conn);

/*
 * call-seq:
 *   conn.list_storage_pools(num) -> list
 *
 * Call virConnectListStoragePools[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListStoragePools]
 * to retrieve a list of active storage pool names on this connection.
 */
static VALUE libvirt_connect_list_storage_pools(VALUE c, VALUE num)
{
    gen_conn_list_names(c, StoragePools, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.num_of_storage_pools -> Fixnum
 *
 * Call virConnectNumOfStoragePools[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfStoragePools]
 * to retrieve the number of active storage pools on this connection.
 */
static VALUE libvirt_connect_num_of_storage_pools(VALUE c)
{
    gen_conn_num_of(c, StoragePools);
}

/*
 * call-seq:
 *   conn.list_defined_storage_pools(num) -> list
 *
 * Call virConnectListDefinedStoragePools[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDefinedStoragePools]
 * to retrieve a list of inactive storage pool names on this connection.
 */
static VALUE libvirt_connect_list_defined_storage_pools(VALUE c, VALUE num)
{
    gen_conn_list_names(c, DefinedStoragePools, NUM2INT(num));
}

/*
 * call-seq:
 *   conn.num_of_defined_storage_pools -> Fixnum
 *
 * Call virConnectNumOfDefinedStoragePools[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDefinedStoragePools]
 * to retrieve the number of inactive storage pools on this connection.
 */
static VALUE libvirt_connect_num_of_defined_storage_pools(VALUE c)
{
    gen_conn_num_of(c, DefinedStoragePools);
}

/*
 * call-seq:
 *   conn.storage_pool_lookup_by_name(name) -> Libvirt::StoragePool
 *
 * Call virStoragePoolLookupByName[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolLookupByName]
 * to retrieve a storage pool object by name.
 */
static VALUE libvirt_connect_storage_pool_lookup_by_name(VALUE c, VALUE name)
{
    virStoragePoolPtr pool;

    pool = virStoragePoolLookupByName(ruby_libvirt_connect_get(c),
                                      StringValueCStr(name));
    ruby_libvirt_raise_error_if(pool == NULL, "virStoragePoolLookupByName",
                                ruby_libvirt_connect_get(c));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.storage_pool_lookup_by_uuid_string(uuid) -> Libvirt::StoragePool
 *
 * Call virStoragePoolLookupByUUIDString[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolLookupByUUIDString]
 * to retrieve a storage pool object by uuid.
 */
static VALUE libvirt_connect_storage_pool_lookup_by_uuid_string(VALUE c,
                                                                VALUE uuid)
{
    virStoragePoolPtr pool;

    pool = virStoragePoolLookupByUUIDString(ruby_libvirt_connect_get(c),
                                            StringValueCStr(uuid));
    ruby_libvirt_raise_error_if(pool == NULL, "virStoragePoolLookupByUUID",
                                ruby_libvirt_connect_get(c));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.storage_pool_create_xml(xml, flags=0) -> Libvirt::StoragePool
 *
 * Call virStoragePoolCreateXML[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolCreateXML]
 * to start a new transient storage pool from xml.
 */
static VALUE libvirt_connect_storage_pool_create_xml(int argc, VALUE *argv,
                                                     VALUE c)
{
    virStoragePoolPtr pool;
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    pool = virStoragePoolCreateXML(ruby_libvirt_connect_get(c),
                                   StringValueCStr(xml),
                                   ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(pool == NULL, "virStoragePoolCreateXML",
                                ruby_libvirt_connect_get(c));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.storage_pool_define_xml(xml, flags=0) -> Libvirt::StoragePool
 *
 * Call virStoragePoolDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolDefineXML]
 * to define a permanent storage pool from xml.
 */
static VALUE libvirt_connect_storage_pool_define_xml(int argc, VALUE *argv,
                                                     VALUE c)
{
    virStoragePoolPtr pool;
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    pool = virStoragePoolDefineXML(ruby_libvirt_connect_get(c),
                                   StringValueCStr(xml),
                                   ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(pool == NULL, "virStoragePoolDefineXML",
                                ruby_libvirt_connect_get(c));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.find_storage_pool_sources(type, srcSpec=nil, flags=0) -> String
 *
 * Call virConnectFindStoragePoolSources[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectFindStoragePoolSources]
 * to find the storage pool sources corresponding to type.
 */
static VALUE libvirt_connect_find_storage_pool_sources(int argc, VALUE *argv,
                                                       VALUE c)
{
    VALUE type, srcSpec, flags;

    rb_scan_args(argc, argv, "12", &type, &srcSpec, &flags);

    ruby_libvirt_generate_call_string(virConnectFindStoragePoolSources,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c),
                                      StringValueCStr(type),
                                      ruby_libvirt_get_cstring_or_null(srcSpec),
                                      ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_VIRCONNECTGETSYSINFO
/*
 * call-seq:
 *   conn.get_sys_info(flags=0) -> String
 *
 * Call virConnectGetSysinfo[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetSysinfo]
 * to get machine-specific information about the hypervisor.  This may include
 * data such as the host UUID, the BIOS version, etc.
 */
static VALUE libvirt_connect_get_sys_info(int argc, VALUE *argv, VALUE c)
{
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    ruby_libvirt_generate_call_string(virConnectGetSysinfo,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c),
                                      ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_TYPE_VIRSTREAMPTR

/*
 * call-seq:
 *   conn.stream(flags=0) -> Libvirt::Stream
 *
 * Call virStreamNew[http://www.libvirt.org/html/libvirt-libvirt.html#virStreamNew]
 * to create a new stream.
 */
static VALUE libvirt_connect_stream(int argc, VALUE *argv, VALUE c)
{
    VALUE flags;
    virStreamPtr stream;

    rb_scan_args(argc, argv, "01", &flags);

    stream = virStreamNew(ruby_libvirt_connect_get(c),
                          ruby_libvirt_value_to_uint(flags));

    ruby_libvirt_raise_error_if(stream == NULL, "virStreamNew",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_stream_new(stream, c);
}
#endif

#if HAVE_VIRINTERFACECHANGEBEGIN
/*
 * call-seq:
 *   conn.interface_change_begin(flags=0) -> nil
 *
 * Call virInterfaceChangeBegin[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceChangeBegin]
 * to create a restore point for interface changes.  Once changes have been
 * made, conn.interface_change_commit can be used to commit the result or
 * conn.interface_change_rollback can be used to rollback to this restore point.
 */
static VALUE libvirt_connect_interface_change_begin(int argc, VALUE *argv,
                                                    VALUE c)
{
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    ruby_libvirt_generate_call_nil(virInterfaceChangeBegin,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_value_to_uint(flags));
}

/*
 * call-seq:
 *   conn.interface_change_commit(flags=0) -> nil
 *
 * Call virInterfaceChangeCommit[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceChangeCommit]
 * to commit the interface changes since the last conn.interface_change_begin.
 */
static VALUE libvirt_connect_interface_change_commit(int argc, VALUE *argv,
                                                     VALUE c)
{
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    ruby_libvirt_generate_call_nil(virInterfaceChangeCommit,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_value_to_uint(flags));
}

/*
 * call-seq:
 *   conn.interface_change_rollback(flags=0) -> nil
 *
 * Call virInterfaceChangeRollback[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceChangeRollback]
 * to rollback to the restore point saved by conn.interface_change_begin.
 */
static VALUE libvirt_connect_interface_change_rollback(int argc, VALUE *argv,
                                                       VALUE c)
{
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    ruby_libvirt_generate_call_nil(virInterfaceChangeRollback,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_VIRNODEGETCPUSTATS
/*
 * call-seq:
 *   conn.node_get_cpu_stats(cpuNum=-1, nparams=0, flags=0) -> Hash
 *
 * Call virNodeGetCPUStats[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetCPUStats]
 * to retrieve cpu statistics from the virtualization host.
 */
static VALUE libvirt_connect_node_get_cpu_stats(int argc, VALUE *argv, VALUE c)
{
    VALUE cpuNum, flags, nparams_val, result;
    virNodeCPUStats *params = NULL;
    int nparams, i, ret, nparams_orig;

    rb_scan_args(argc, argv, "03", &cpuNum, &nparams_val, &flags);

    if (NIL_P(nparams_val)) {
        nparams = 0;
    }
    else {
        nparams = NUM2INT(nparams_val);
    }

    nparams_orig = nparams;

    if (nparams > 0) {
        params = alloca(sizeof(virNodeCPUStats) * nparams);
    }

    ret = virNodeGetCPUStats(ruby_libvirt_connect_get(c),
                             ruby_libvirt_value_to_int(cpuNum),
                             params, &nparams,
                             ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(ret < 0, "virNodeGetCPUStats",
                                ruby_libvirt_connect_get(c));

    result = rb_hash_new();
    for (i = 0; i < nparams; i++) {
        if (nparams_orig == 0) {
            rb_hash_aset(result, rb_str_new2("dummy"), rb_str_new2("dummy"));
        }
        else {
            rb_hash_aset(result, rb_str_new2(params[i].field),
                         ULL2NUM(params[i].value));
        }
    }

    return result;
}
#endif

#if HAVE_VIRNODEGETMEMORYSTATS
/*
 * call-seq:
 *   conn.node_get_memory_stats(cellNum=-1, nparams=0, flags=0) -> Hash
 *
 * Call virNodeGetMemoryStats[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetMemoryStats]
 * to retrieve memory statistics from the virtualization host.
 */
static VALUE libvirt_connect_node_get_memory_stats(int argc, VALUE *argv,
                                                   VALUE c)
{
    /* FIXME: we can probably share a lot of code with libvirt_connect_node_get_cpu_stats */
    VALUE cellNum, flags, nparams_val, result;
    virNodeMemoryStats *params = NULL;
    int nparams, i, ret, nparams_orig;

    rb_scan_args(argc, argv, "03", &cellNum, &nparams_val, &flags);

    if (NIL_P(nparams_val)) {
        nparams = 0;
    }
    else {
        nparams = NUM2INT(nparams_val);
    }

    nparams_orig = nparams;

    if (nparams > 0) {
        params = alloca(sizeof(virNodeMemoryStats) * nparams);
    }

    ret = virNodeGetMemoryStats(ruby_libvirt_connect_get(c),
                                ruby_libvirt_value_to_int(cellNum),
                                params, &nparams,
                                ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(ret < 0, "virNodeGetMemoryStats",
                                ruby_libvirt_connect_get(c));

    result = rb_hash_new();
    for (i = 0; i < nparams; i++) {
        if (nparams_orig == 0) {
            rb_hash_aset(result, rb_str_new2("dummy"), rb_str_new2("dummy"));
        }
        else {
            rb_hash_aset(result, rb_str_new2(params[i].field),
                         ULL2NUM(params[i].value));
        }
    }

    return result;
}
#endif

#if HAVE_VIRDOMAINSAVEIMAGEGETXMLDESC
/*
 * call-seq:
 *   conn.save_image_get_xml_desc(filename, flags=0) -> String
 *
 * Call virDomainSaveImageGetXMLDesc[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSaveImageGetXMLDesc]
 * to get the XML corresponding to a save file.
 */
static VALUE libvirt_connect_save_image_get_xml_desc(int argc, VALUE *argv,
                                                     VALUE c)
{
    VALUE filename, flags;

    rb_scan_args(argc, argv, "11", &filename, &flags);

    ruby_libvirt_generate_call_string(virDomainSaveImageGetXMLDesc,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c),
                                      StringValueCStr(filename),
                                      ruby_libvirt_value_to_uint(flags));
}

/*
 * call-seq:
 *   conn.save_image_define_xml(filename, newxml, flags=0) -> nil
 *
 * Call virDomainSaveImageDefineXML[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSaveImageDefineXML]
 * to define new XML for a saved image.
 */
static VALUE libvirt_connect_save_image_define_xml(int argc, VALUE *argv,
                                                   VALUE c)
{
    VALUE filename, newxml, flags;

    rb_scan_args(argc, argv, "21", &filename, &newxml, &flags);

    ruby_libvirt_generate_call_nil(virDomainSaveImageDefineXML,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   StringValueCStr(filename),
                                   StringValueCStr(newxml),
                                   ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_VIRNODESUSPENDFORDURATION
/*
 * call-seq:
 *   conn.node_suspend_for_duration(target, duration, flags=0) -> nil
 *
 * Call virNodeSuspendForDuration[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeSuspendForDuration]
 * to suspend the hypervisor for the specified duration.
 */
static VALUE libvirt_connect_node_suspend_for_duration(int argc, VALUE *argv,
                                                       VALUE c)
{
    VALUE target, duration, flags;

    rb_scan_args(argc, argv, "21", &target, &duration, &flags);

    ruby_libvirt_generate_call_nil(virNodeSuspendForDuration,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   NUM2UINT(target), NUM2ULL(duration),
                                   ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_VIRNODEGETMEMORYPARAMETERS
/*
 * call-seq:
 *   conn.node_get_memory_parameters(nparams=0, flags=0) -> Hash
 *
 * Call virNodeGetMemoryParameters[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetMemoryParameters]
 * to get information about memory on the host node.
 */
static VALUE libvirt_connect_node_get_memory_parameters(int argc, VALUE *argv,
                                                        VALUE c)
{
    /* FIXME: we can probably share a lot of code with libvirt_connect_node_get_cpu_stats */
    VALUE nparams_val, flags, result;
    virTypedParameter *params = NULL;
    int nparams, i, ret, nparams_orig;

    rb_scan_args(argc, argv, "02", &nparams_val, &flags);

    if (NIL_P(nparams_val)) {
        nparams = 0;
    }
    else {
        nparams = NUM2INT(nparams_val);
    }

    nparams_orig = nparams;

    if (nparams > 0) {
        params = alloca(sizeof(virTypedParameter) * nparams);
    }

    ret = virNodeGetMemoryParameters(ruby_libvirt_connect_get(c), params,
                                     &nparams,
                                     ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(ret < 0, "virNodeGetMemoryParameters",
                                ruby_libvirt_connect_get(c));

    result = rb_hash_new();
    for (i = 0; i < nparams; i++) {
        if (nparams_orig == 0) {
            rb_hash_aset(result, rb_str_new2("dummy"), rb_str_new2("dummy"));
        }
        else {
            ruby_libvirt_typed_params_to_hash(params, i, result);
        }
    }

    return result;
}

static struct ruby_libvirt_typed_param memory_allowed[] = {
    {VIR_NODE_MEMORY_SHARED_PAGES_TO_SCAN, VIR_TYPED_PARAM_UINT},
    {VIR_NODE_MEMORY_SHARED_SLEEP_MILLISECS, VIR_TYPED_PARAM_UINT},
    {VIR_NODE_MEMORY_SHARED_PAGES_SHARED, VIR_TYPED_PARAM_ULLONG},
    {VIR_NODE_MEMORY_SHARED_PAGES_SHARING, VIR_TYPED_PARAM_ULLONG},
    {VIR_NODE_MEMORY_SHARED_PAGES_UNSHARED, VIR_TYPED_PARAM_ULLONG},
    {VIR_NODE_MEMORY_SHARED_PAGES_VOLATILE, VIR_TYPED_PARAM_ULLONG},
    {VIR_NODE_MEMORY_SHARED_FULL_SCANS, VIR_TYPED_PARAM_ULLONG},
#if HAVE_CONST_VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES
    {VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES, VIR_TYPED_PARAM_UINT},
#endif
};

/*
 * call-seq:
 *   conn.node_set_memory_parameters(hash, flags=0) -> nil
 *
 * Call virNodeSetMemoryParameters[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeSetMemoryParameters]
 * to set the memory parameters for this host node.
 */
static VALUE libvirt_connect_node_set_memory_parameters(int argc, VALUE *argv,
                                                        VALUE c)
{
    VALUE hash, flags;
    struct ruby_libvirt_parameter_assign_args args;

    rb_scan_args(argc, argv, "11", &hash, &flags);

    Check_Type(hash, T_HASH);

    args.allowed = memory_allowed;
    args.num_allowed = ARRAY_SIZE(memory_allowed);
    args.params = alloca(sizeof(virTypedParameter) * RHASH_SIZE(hash));
    args.i = 0;

    rb_hash_foreach(hash, ruby_libvirt_typed_parameter_assign, (VALUE)&args);

    ruby_libvirt_generate_call_nil(virNodeSetMemoryParameters,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   args.params, args.i,
                                   ruby_libvirt_value_to_uint(flags));
}
#endif

#if HAVE_VIRNODEGETCPUMAP
struct cpu_map_field_to_value {
    VALUE result;
    int cpu;
    int used;
};

static VALUE cpu_map_field_to_value(VALUE input)
{
    struct cpu_map_field_to_value *ftv = (struct cpu_map_field_to_value *)input;
    char cpuname[10];

    snprintf(cpuname, sizeof(cpuname), "%d", ftv->cpu);
    rb_hash_aset(ftv->result, rb_str_new2(cpuname), ftv->used ? Qtrue : Qfalse);

    return Qnil;
}

/*
 * call-seq:
 *   conn.node_get_cpu_map(flags=0) -> Hash
 *
 * Call virNodeGetCPUMap[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeGetCPUMap]
 * to get a map of online host CPUs.
 */
static VALUE libvirt_connect_node_get_cpu_map(int argc, VALUE *argv, VALUE c)
{
    VALUE flags, result;
    unsigned char *map;
    unsigned int online;
    int ret, i, exception = 0;
    struct cpu_map_field_to_value ftv;

    rb_scan_args(argc, argv, "01", &flags);

    ret = virNodeGetCPUMap(ruby_libvirt_connect_get(c), &map, &online,
                           ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(ret < 0, "virNodeGetCPUMap",
                                ruby_libvirt_connect_get(c));

    result = rb_hash_new();

    for (i = 0; i < ret; i++) {
        ftv.result = result;
        ftv.cpu = i;
        ftv.used = VIR_CPU_USED(map, i);
        rb_protect(cpu_map_field_to_value, (VALUE)&ftv, &exception);
        if (exception) {
            free(map);
            rb_jump_tag(exception);
        }
    }

    free(map);

    return result;
}
#endif

#if HAVE_VIRCONNECTSETKEEPALIVE
/*
 * call-seq:
 *   conn.set_keepalive(interval, count)
 *
 * Call virConnectSetKeepAlive[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectSetKeepAlive]
 * to start sending keepalive messages.
 */
static VALUE libvirt_connect_set_keepalive(VALUE c, VALUE interval, VALUE count)
{
    ruby_libvirt_generate_call_int(virConnectSetKeepAlive,
                                   ruby_libvirt_connect_get(c),
                                   ruby_libvirt_connect_get(c),
                                   NUM2INT(interval), NUM2UINT(count));
}
#endif

#if HAVE_VIRCONNECTLISTALLDOMAINS
/*
 * call-seq:
 *   conn.list_all_domains(flags=0) -> Array
 *
 * Call virConnectListAllDomains[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllDomains]
 * to get an array of domain objects for all domains.
 */
static VALUE libvirt_connect_list_all_domains(int argc, VALUE *argv, VALUE c)
{
    ruby_libvirt_generate_call_list_all(virDomainPtr, argc, argv,
                                        virConnectListAllDomains,
                                        ruby_libvirt_connect_get(c), c,
                                        ruby_libvirt_domain_new, virDomainFree);
}
#endif

#if HAVE_VIRCONNECTLISTALLNETWORKS
/*
 * call-seq:
 *   conn.list_all_networks(flags=0) -> Array
 *
 * Call virConnectListAllNetworks[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllNetworks]
 * to get an array of network objects for all networks.
 */
static VALUE libvirt_connect_list_all_networks(int argc, VALUE *argv, VALUE c)
{
    ruby_libvirt_generate_call_list_all(virNetworkPtr, argc, argv,
                                        virConnectListAllNetworks,
                                        ruby_libvirt_connect_get(c), c,
                                        ruby_libvirt_network_new,
                                        virNetworkFree);
}
#endif

#if HAVE_VIRCONNECTLISTALLINTERFACES
/*
 * call-seq:
 *   conn.list_all_interfaces(flags=0) -> Array
 *
 * Call virConnectListAllInterfaces[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllInterfaces]
 * to get an array of interface objects for all interfaces.
 */
static VALUE libvirt_connect_list_all_interfaces(int argc, VALUE *argv, VALUE c)
{
    ruby_libvirt_generate_call_list_all(virInterfacePtr, argc, argv,
                                        virConnectListAllInterfaces,
                                        ruby_libvirt_connect_get(c), c,
                                        ruby_libvirt_interface_new,
                                        virInterfaceFree);
}
#endif

#if HAVE_VIRCONNECTLISTALLSECRETS
/*
 * call-seq:
 *   conn.list_all_secrets(flags=0) -> Array
 *
 * Call virConnectListAllSecrets[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllSecrets]
 * to get an array of secret objects for all secrets.
 */
static VALUE libvirt_connect_list_all_secrets(int argc, VALUE *argv, VALUE c)
{
    ruby_libvirt_generate_call_list_all(virSecretPtr, argc, argv,
                                        virConnectListAllSecrets,
                                        ruby_libvirt_connect_get(c), c,
                                        ruby_libvirt_secret_new, virSecretFree);
}
#endif

#if HAVE_VIRCONNECTLISTALLNODEDEVICES
/*
 * call-seq:
 *   conn.list_all_nodedevices(flags=0) -> Array
 *
 * Call virConnectListAllNodeDevices[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllNodeDevices]
 * to get an array of nodedevice objects for all nodedevices.
 */
static VALUE libvirt_connect_list_all_nodedevices(int argc, VALUE *argv,
                                                  VALUE c)
{
    ruby_libvirt_generate_call_list_all(virNodeDevicePtr, argc, argv,
                                        virConnectListAllNodeDevices,
                                        ruby_libvirt_connect_get(c), c,
                                        ruby_libvirt_nodedevice_new,
                                        virNodeDeviceFree);
}
#endif

#if HAVE_VIRCONNECTLISTALLSTORAGEPOOLS
/*
 * call-seq:
 *   conn.list_all_storage_pools(flags=0) -> Array
 *
 * Call virConnectListAllStoragePools[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllStoragePools]
 * to get an array of storage pool objects for all storage pools.
 */
static VALUE libvirt_connect_list_all_storage_pools(int argc, VALUE *argv,
                                                    VALUE c)
{
    ruby_libvirt_generate_call_list_all(virStoragePoolPtr, argc, argv,
                                        virConnectListAllStoragePools,
                                        ruby_libvirt_connect_get(c), c,
                                        pool_new, virStoragePoolFree);
}
#endif

#if HAVE_VIRCONNECTLISTALLNWFILTERS
/*
 * call-seq:
 *   conn.list_all_nwfilters(flags=0) -> Array
 *
 * Call virConnectListAllNWFilters[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListAllNWFilters]
 * to get an array of nwfilters for all nwfilter objects.
 */
static VALUE libvirt_connect_list_all_nwfilters(int argc, VALUE *argv, VALUE c)
{
    ruby_libvirt_generate_call_list_all(virNWFilterPtr, argc, argv,
                                        virConnectListAllNWFilters,
                                        ruby_libvirt_connect_get(c), c,
                                        ruby_libvirt_nwfilter_new,
                                        virNWFilterFree);
}
#endif

#if HAVE_VIRCONNECTISALIVE
/*
 * call-seq:
 *   conn.is_alive -> [True|False]
 *
 * Call virConnectIsAlive[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectIsAlive]
 * to determine if the connection is alive.
 */
static VALUE libvirt_connect_is_alive(VALUE c)
{
    ruby_libvirt_generate_call_truefalse(virConnectIsAlive,
                                         ruby_libvirt_connect_get(c),
                                         ruby_libvirt_connect_get(c));
}
#endif

#if HAVE_VIRDOMAINCREATEXMLWITHFILES
/*
 * call-seq:
 *   conn.domain_create_xml_with_files(xml, fds=nil, flags=0) -> Libvirt::Domain
 *
 * Call virDomainCreateXMLWithFiles[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCreateXMLWithFiles]
 * to launch a new guest domain with a set of open file descriptors.
 */
static VALUE libvirt_connect_domain_create_xml_with_files(int argc, VALUE *argv,
                                                          VALUE c)
{
    VALUE xml, fds, flags;
    int *files;
    unsigned int numfiles, i;
    virDomainPtr dom;

    rb_scan_args(argc, argv, "12", &xml, &fds, &flags);

    Check_Type(xml, T_STRING);

    if (TYPE(fds) == T_NIL) {
        files = NULL;
        numfiles = 0;
    }
    else if (TYPE(fds) == T_ARRAY) {
        numfiles = RARRAY_LEN(fds);
        files = alloca(numfiles * sizeof(int));
        for (i = 0; i < numfiles; i++) {
            files[i] = NUM2INT(rb_ary_entry(fds, i));
        }
    }
    else {
        rb_raise(rb_eTypeError, "wrong argument type (expected Array)");
    }

    dom = virDomainCreateXMLWithFiles(ruby_libvirt_connect_get(c),
                                      ruby_libvirt_get_cstring_or_null(xml),
                                      numfiles, files,
                                      ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainCreateXMLWithFiles",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}
#endif

#if HAVE_VIRDOMAINQEMUATTACH
/*
 * call-seq:
 *   conn.qemu_attach(pid, flags=0) -> Libvirt::Domain
 *
 * Call virDomainQemuAttach[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainQemuAttach]
 * to attach to the Qemu process pid.
 */
static VALUE libvirt_connect_qemu_attach(int argc, VALUE *argv, VALUE c)
{
    VALUE pid, flags;
    virDomainPtr dom;

    rb_scan_args(argc, argv, "11", &pid, &flags);

    dom = virDomainQemuAttach(ruby_libvirt_connect_get(c), NUM2UINT(pid),
                              ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(dom == NULL, "virDomainQemuAttach",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_domain_new(dom, c);
}
#endif

#if HAVE_VIRCONNECTGETCPUMODELNAMES
/*
 * call-seq:
 *   conn.get_cpu_model_names(arch, flags=0) -> Array
 *
 * Call virConnectGetCPUModelNames[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetCPUModelNames]
 * to get an array of CPU model names.
 */
static VALUE libvirt_connect_get_cpu_model_names(int argc, VALUE *argv, VALUE c)
{
    VALUE arch, flags, result;
    char **models;
    int i = 0, j, elems = 0;
    struct ruby_libvirt_str_new2_and_ary_store_arg args;
    int exception;

    rb_scan_args(argc, argv, "11", &arch, &flags);

    elems = virConnectGetCPUModelNames(ruby_libvirt_connect_get(c),
                                       StringValueCStr(arch), &models,
                                       ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(elems < 0, "virConnectGetCPUModelNames",
                                ruby_libvirt_connect_get(c));

    result = rb_protect(ruby_libvirt_ary_new2_wrap, (VALUE)&elems, &exception);
    if (exception) {
        goto error;
    }

    for (i = 0; i < elems; i++) {
        args.arr = result;
        args.index = i;
        args.value = models[i];

        rb_protect(ruby_libvirt_str_new2_and_ary_store_wrap, (VALUE)&args,
                   &exception);
        if (exception) {
            goto error;
        }
        free(models[i]);
    }
    free(models);

    return result;

error:
    for (j = i; j < elems; j++) {
        free(models[j]);
    }
    free(models);

    rb_jump_tag(exception);
    return Qnil;
}
#endif

#if HAVE_VIRNODEALLOCPAGES
/*
 * call-seq:
 *   conn.node_alloc_pages(page_arr, cells=nil, flags=0) -> Fixnum
 *
 * Call virNodeAllocPages[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeAllocPages]
 * to reserve huge pages in the system pool.
 */
static VALUE libvirt_connect_node_alloc_pages(int argc, VALUE *argv, VALUE c)
{
    VALUE page_arr, cells, flags, entry, size, count, tmp;
    int i, arraylen, start_cell, ret;
    unsigned int *page_sizes;
    unsigned long long *page_counts;
    unsigned int cell_count;

    rb_scan_args(argc, argv, "12", &page_arr, &cells, &flags);

    Check_Type(page_arr, T_ARRAY);

    arraylen = RARRAY_LEN(page_arr);

    page_sizes = alloca(arraylen * sizeof(unsigned int));
    page_counts = alloca(arraylen * sizeof(unsigned long long));

    for (i = 0; i < arraylen; i++) {
        entry = rb_ary_entry(page_arr, i);
        Check_Type(entry, T_HASH);

        size = rb_hash_aref(entry, rb_str_new2("size"));
        Check_Type(size, T_FIXNUM);

        count = rb_hash_aref(entry, rb_str_new2("count"));
        Check_Type(count, T_FIXNUM);

        page_sizes[i] = NUM2UINT(size);
        page_counts[i] = NUM2ULL(count);
    }

    if (NIL_P(cells)) {
        start_cell = -1;
        cell_count = 0;
    }
    else {
        Check_Type(cells, T_HASH);

        tmp = rb_hash_aref(cells, rb_str_new2("start"));
        Check_Type(tmp, T_FIXNUM);
        start_cell = NUM2INT(tmp);

        tmp = rb_hash_aref(cells, rb_str_new2("count"));
        Check_Type(tmp, T_FIXNUM);
        cell_count = NUM2UINT(tmp);
    }

    ret = virNodeAllocPages(ruby_libvirt_connect_get(c), arraylen, page_sizes,
                            page_counts, start_cell, cell_count,
                            ruby_libvirt_value_to_uint(flags));
    ruby_libvirt_raise_error_if(ret < 0, "virNodeAllocPages",
                                ruby_libvirt_connect_get(c));

    return INT2NUM(ret);
}
#endif

#if HAVE_VIRCONNECTGETDOMAINCAPABILITIES
/*
 * call-seq:
 *   conn.domain_capabilities(emulatorbin, arch, machine, virttype, flags=0) -> String
 *
 * Call virNodeAllocPages[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectGetDomainCapabilities]
 * to get the capabilities of the underlying emulator.
 */
static VALUE libvirt_connect_domain_capabilities(int argc, VALUE *argv, VALUE c)
{
    VALUE emulatorbin, arch, machine, virttype, flags;

    rb_scan_args(argc, argv, "41", &emulatorbin, &arch, &machine, &virttype,
                 &flags);

    ruby_libvirt_generate_call_string(virConnectGetDomainCapabilities,
                                      ruby_libvirt_connect_get(c), 1,
                                      ruby_libvirt_connect_get(c),
                                      ruby_libvirt_get_cstring_or_null(emulatorbin),
                                      ruby_libvirt_get_cstring_or_null(arch),
                                      ruby_libvirt_get_cstring_or_null(machine),
                                      ruby_libvirt_get_cstring_or_null(virttype),
                                      NUM2UINT(flags));
}
#endif

/*
 * Class Libvirt::Connect
 */
void ruby_libvirt_connect_init(void)
{
    c_connect = rb_define_class_under(m_libvirt, "Connect", rb_cObject);

    rb_define_method(c_connect, "close", libvirt_connect_close, 0);
    rb_define_method(c_connect, "closed?", libvirt_connect_closed_p, 0);
    rb_define_method(c_connect, "get_type", libvirt_connect_get_type, 0);
    rb_define_method(c_connect, "get_version", libvirt_connect_get_version, 0);
#if HAVE_VIRCONNECTGETLIBVERSION
    rb_define_method(c_connect, "get_lib_version",
                     libvirt_connect_get_lib_version, 0);
#endif
    rb_define_method(c_connect, "get_hostname", libvirt_connect_get_hostname,
                     0);
    rb_define_method(c_connect, "get_uri", libvirt_connect_get_uri, 0);
    rb_define_method(c_connect, "get_max_vcpus",
                     libvirt_connect_get_max_vcpus, -1);
    rb_define_method(c_connect, "node_get_info",
                     libvirt_connect_node_get_info, 0);
    rb_define_method(c_connect, "node_get_free_memory",
                     libvirt_connect_node_get_free_memory, 0);
    rb_define_method(c_connect, "node_get_cells_free_memory",
                     libvirt_connect_node_get_cells_free_memory, -1);
#if HAVE_VIRNODEGETSECURITYMODEL
    rb_define_method(c_connect, "node_get_security_model",
                     libvirt_connect_node_get_security_model, 0);
#endif
#if HAVE_VIRCONNECTISENCRYPTED
    rb_define_method(c_connect, "encrypted?", libvirt_connect_encrypted_p, 0);
#endif
#if HAVE_VIRCONNECTISSECURE
    rb_define_method(c_connect, "secure?", libvirt_connect_secure_p, 0);
#endif
    rb_define_method(c_connect, "get_capabilities",
                     libvirt_connect_get_capabilities, 0);

#if HAVE_VIRCONNECTCOMPARECPU
    rb_define_const(c_connect, "CPU_COMPARE_ERROR",
                    INT2NUM(VIR_CPU_COMPARE_ERROR));
    rb_define_const(c_connect, "CPU_COMPARE_INCOMPATIBLE",
                    INT2NUM(VIR_CPU_COMPARE_INCOMPATIBLE));
    rb_define_const(c_connect, "CPU_COMPARE_IDENTICAL",
                    INT2NUM(VIR_CPU_COMPARE_IDENTICAL));
    rb_define_const(c_connect, "CPU_COMPARE_SUPERSET",
                    INT2NUM(VIR_CPU_COMPARE_SUPERSET));

    rb_define_method(c_connect, "compare_cpu", libvirt_connect_compare_cpu, -1);
#endif

#if HAVE_CONST_VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE
    rb_define_const(c_connect, "COMPARE_CPU_FAIL_INCOMPATIBLE",
                    INT2NUM(VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE));
#endif

#if HAVE_VIRCONNECTBASELINECPU
    rb_define_method(c_connect, "baseline_cpu", libvirt_connect_baseline_cpu,
                     -1);
#endif
#if HAVE_CONST_VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES
    rb_define_const(c_connect, "BASELINE_CPU_EXPAND_FEATURES",
                    INT2NUM(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES));
#endif

    /* In the libvirt development history, the events were
     * first defined in commit 1509b8027fd0b73c30aeab443f81dd5a18d80544,
     * then ADDED and REMOVED were renamed to DEFINED and UNDEFINED at
     * the same time that the details were added
     * (d3d54d2fc92e350f250eda26cee5d0342416a9cf).  What this means is that
     * we have to check for HAVE_CONST_VIR_DOMAIN_EVENT_DEFINED and
     * HAVE_CONST_VIR_DOMAIN_EVENT_STARTED to untangle these, and then we
     * can make a decision for many of the events based on that.
     */
#if HAVE_CONST_VIR_DOMAIN_EVENT_DEFINED
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
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_BOOTED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_BOOTED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_MIGRATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_RESTORED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_RESTORED));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_PAUSED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_PAUSED));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED));
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED_UNPAUSED",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED_UNPAUSED));
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED_MIGRATED",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED_MIGRATED));
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
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_STARTED
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED));
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED));
#endif
#if HAVE_TYPE_VIRDOMAINSNAPSHOTPTR
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT));
    rb_define_const(c_connect, "DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_SUSPENDED_IOERROR
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_IOERROR",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_IOERROR));
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_WATCHDOG",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_WATCHDOG
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_WATCHDOG",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_WATCHDOG));
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
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_IO_ERROR
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_IO_ERROR",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_IO_ERROR));
    rb_define_const(c_connect, "DOMAIN_EVENT_IO_ERROR_NONE",
                    INT2NUM(VIR_DOMAIN_EVENT_IO_ERROR_NONE));
    rb_define_const(c_connect, "DOMAIN_EVENT_IO_ERROR_PAUSE",
                    INT2NUM(VIR_DOMAIN_EVENT_IO_ERROR_PAUSE));
    rb_define_const(c_connect, "DOMAIN_EVENT_IO_ERROR_REPORT",
                    INT2NUM(VIR_DOMAIN_EVENT_IO_ERROR_REPORT));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_GRAPHICS
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_GRAPHICS",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_GRAPHICS));
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
#endif
#if HAVE_VIRCONNECTDOMAINEVENTREGISTERANY
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_LIFECYCLE",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_LIFECYCLE));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_REBOOT
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_REBOOT",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_REBOOT));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_RTC_CHANGE
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_RTC_CHANGE",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_RTC_CHANGE));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_IO_ERROR_REASON",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON));
#endif

#if HAVE_CONST_VIR_DOMAIN_EVENT_ID_CONTROL_ERROR
    rb_define_const(c_connect, "DOMAIN_EVENT_ID_CONTROL_ERROR",
                    INT2NUM(VIR_DOMAIN_EVENT_ID_CONTROL_ERROR));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_SHUTDOWN
    rb_define_const(c_connect, "DOMAIN_EVENT_SHUTDOWN",
                    INT2NUM(VIR_DOMAIN_EVENT_SHUTDOWN));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_PMSUSPENDED
    rb_define_const(c_connect, "DOMAIN_EVENT_PMSUSPENDED",
                    INT2NUM(VIR_DOMAIN_EVENT_PMSUSPENDED));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_CRASHED
    rb_define_const(c_connect, "DOMAIN_EVENT_CRASHED",
                    INT2NUM(VIR_DOMAIN_EVENT_CRASHED));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_STARTED_WAKEUP
    rb_define_const(c_connect, "DOMAIN_EVENT_STARTED_WAKEUP",
                    INT2NUM(VIR_DOMAIN_EVENT_STARTED_WAKEUP));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_SUSPENDED_RESTORED
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_RESTORED",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_RESTORED));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR
    rb_define_const(c_connect, "DOMAIN_EVENT_SUSPENDED_API_ERROR",
                    INT2NUM(VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT
    rb_define_const(c_connect, "DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED
    rb_define_const(c_connect, "DOMAIN_EVENT_SHUTDOWN_FINISHED",
                    INT2NUM(VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY
    rb_define_const(c_connect, "DOMAIN_EVENT_PMSUSPENDED_MEMORY",
                    INT2NUM(VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_PMSUSPENDED_DISK
    rb_define_const(c_connect, "DOMAIN_EVENT_PMSUSPENDED_DISK",
                    INT2NUM(VIR_DOMAIN_EVENT_PMSUSPENDED_DISK));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_CRASHED_PANICKED
    rb_define_const(c_connect, "DOMAIN_EVENT_CRASHED_PANICKED",
                    INT2NUM(VIR_DOMAIN_EVENT_CRASHED_PANICKED));
#endif
#if HAVE_CONST_VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_UNIX
    rb_define_const(c_connect, "DOMAIN_EVENT_GRAPHICS_ADDRESS_UNIX",
                    INT2NUM(VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_UNIX));
#endif

#if HAVE_VIRCONNECTDOMAINEVENTREGISTER
    rb_define_method(c_connect, "domain_event_register",
                     libvirt_connect_domain_event_register, -1);
    rb_define_method(c_connect, "domain_event_deregister",
                     libvirt_connect_domain_event_deregister, 0);
#endif

#if HAVE_VIRCONNECTDOMAINEVENTREGISTERANY
    rb_define_method(c_connect, "domain_event_register_any",
                     libvirt_connect_domain_event_register_any, -1);
    rb_define_method(c_connect, "domain_event_deregister_any",
                     libvirt_connect_domain_event_deregister_any, 1);
#endif

    /* Domain creation/lookup */
    rb_define_method(c_connect, "num_of_domains",
                     libvirt_connect_num_of_domains, 0);
    rb_define_method(c_connect, "list_domains", libvirt_connect_list_domains,
                     1);
    rb_define_method(c_connect, "num_of_defined_domains",
                     libvirt_connect_num_of_defined_domains, 0);
    rb_define_method(c_connect, "list_defined_domains",
                     libvirt_connect_list_defined_domains, 1);
    rb_define_method(c_connect, "create_domain_linux",
                     libvirt_connect_create_linux, -1);
#if HAVE_VIRDOMAINCREATEXML
    rb_define_method(c_connect, "domain_create_xml",
                     libvirt_connect_domain_create_xml, -1);
#endif
    rb_define_method(c_connect, "domain_lookup_by_name",
                     libvirt_connect_domain_lookup_by_name, 1);
    rb_define_method(c_connect, "domain_lookup_by_id",
                     libvirt_connect_domain_lookup_by_id, 1);
    rb_define_method(c_connect, "domain_lookup_by_uuid_string",
                     libvirt_connect_domain_lookup_by_uuid_string, 1);
    rb_define_method(c_connect, "domain_define_xml",
                     libvirt_connect_domain_define_xml, 1);

#if HAVE_VIRCONNECTDOMAINXMLFROMNATIVE
    rb_define_method(c_connect, "domain_xml_from_native",
                     libvirt_connect_domain_xml_from_native, -1);
#endif
#if HAVE_VIRCONNECTDOMAINXMLTONATIVE
    rb_define_method(c_connect, "domain_xml_to_native",
                     libvirt_connect_domain_xml_to_native, -1);
#endif

#if HAVE_TYPE_VIRINTERFACEPTR
    /* Interface lookup/creation methods */
    rb_define_method(c_connect, "num_of_interfaces",
                     libvirt_connect_num_of_interfaces, 0);
    rb_define_method(c_connect, "list_interfaces",
                     libvirt_connect_list_interfaces, 1);
    rb_define_method(c_connect, "num_of_defined_interfaces",
                     libvirt_connect_num_of_defined_interfaces, 0);
    rb_define_method(c_connect, "list_defined_interfaces",
                     libvirt_connect_list_defined_interfaces, 1);
    rb_define_method(c_connect, "interface_lookup_by_name",
                     libvirt_connect_interface_lookup_by_name, 1);
    rb_define_method(c_connect, "interface_lookup_by_mac",
                     libvirt_connect_interface_lookup_by_mac, 1);
    rb_define_method(c_connect, "interface_define_xml",
                     libvirt_connect_interface_define_xml, -1);
#endif

    /* Network lookup/creation methods */
    rb_define_method(c_connect, "num_of_networks",
                     libvirt_connect_num_of_networks, 0);
    rb_define_method(c_connect, "list_networks", libvirt_connect_list_networks,
                     1);
    rb_define_method(c_connect, "num_of_defined_networks",
                     libvirt_connect_num_of_defined_networks, 0);
    rb_define_method(c_connect, "list_defined_networks",
                     libvirt_connect_list_defined_networks, 1);
    rb_define_method(c_connect, "network_lookup_by_name",
                     libvirt_connect_network_lookup_by_name, 1);
    rb_define_method(c_connect, "network_lookup_by_uuid_string",
                     libvirt_connect_network_lookup_by_uuid_string, 1);
    rb_define_method(c_connect, "network_create_xml",
                     libvirt_connect_network_create_xml, 1);
    rb_define_method(c_connect, "network_define_xml",
                     libvirt_connect_network_define_xml, 1);

    /* Node device lookup/creation methods */
#if HAVE_TYPE_VIRNODEDEVICEPTR
    rb_define_method(c_connect, "node_num_of_devices",
                     libvirt_connect_node_num_of_devices, -1);
    rb_define_method(c_connect, "node_list_devices",
                     libvirt_connect_node_list_devices, -1);
    rb_define_method(c_connect, "node_device_lookup_by_name",
                     libvirt_connect_node_device_lookup_by_name, 1);
#if HAVE_VIRNODEDEVICECREATEXML
    rb_define_method(c_connect, "node_device_create_xml",
                     libvirt_connect_node_device_create_xml, -1);
#endif
#endif

#if HAVE_TYPE_VIRNWFILTERPTR
    /* NWFilter lookup/creation methods */
    rb_define_method(c_connect, "num_of_nwfilters",
                     libvirt_connect_num_of_nwfilters, 0);
    rb_define_method(c_connect, "list_nwfilters",
                     libvirt_connect_list_nwfilters, 1);
    rb_define_method(c_connect, "nwfilter_lookup_by_name",
                     libvirt_connect_nwfilter_lookup_by_name, 1);
    rb_define_method(c_connect, "nwfilter_lookup_by_uuid_string",
                     libvirt_connect_nwfilter_lookup_by_uuid_string, 1);
    rb_define_method(c_connect, "nwfilter_define_xml",
                     libvirt_connect_nwfilter_define_xml, 1);
#endif

#if HAVE_TYPE_VIRSECRETPTR
    /* Secret lookup/creation methods */
    rb_define_method(c_connect, "num_of_secrets",
                     libvirt_connect_num_of_secrets, 0);
    rb_define_method(c_connect, "list_secrets",
                     libvirt_connect_list_secrets, 1);
    rb_define_method(c_connect, "secret_lookup_by_uuid_string",
                     libvirt_connect_secret_lookup_by_uuid_string, 1);
    rb_define_method(c_connect, "secret_lookup_by_usage",
                     libvirt_connect_secret_lookup_by_usage, 2);
    rb_define_method(c_connect, "secret_define_xml",
                     libvirt_connect_secret_define_xml, -1);
#endif

#if HAVE_TYPE_VIRSTORAGEPOOLPTR
    /* StoragePool lookup/creation methods */
    rb_define_method(c_connect, "num_of_storage_pools",
                     libvirt_connect_num_of_storage_pools, 0);
    rb_define_method(c_connect, "list_storage_pools",
                     libvirt_connect_list_storage_pools, 1);
    rb_define_method(c_connect, "num_of_defined_storage_pools",
                     libvirt_connect_num_of_defined_storage_pools, 0);
    rb_define_method(c_connect, "list_defined_storage_pools",
                     libvirt_connect_list_defined_storage_pools, 1);
    rb_define_method(c_connect, "storage_pool_lookup_by_name",
                     libvirt_connect_storage_pool_lookup_by_name, 1);
    rb_define_method(c_connect, "storage_pool_lookup_by_uuid_string",
                     libvirt_connect_storage_pool_lookup_by_uuid_string, 1);
    rb_define_method(c_connect, "storage_pool_create_xml",
                     libvirt_connect_storage_pool_create_xml, -1);
    rb_define_method(c_connect, "storage_pool_define_xml",
                     libvirt_connect_storage_pool_define_xml, -1);
    rb_define_method(c_connect, "find_storage_pool_sources",
                     libvirt_connect_find_storage_pool_sources, -1);
#endif

#if HAVE_VIRCONNECTGETSYSINFO
    rb_define_method(c_connect, "get_sys_info", libvirt_connect_get_sys_info,
                     -1);
#endif
#if HAVE_TYPE_VIRSTREAMPTR
    rb_define_method(c_connect, "stream", libvirt_connect_stream, -1);
#endif

#if HAVE_VIRINTERFACECHANGEBEGIN
    rb_define_method(c_connect, "interface_change_begin",
                     libvirt_connect_interface_change_begin, -1);
    rb_define_method(c_connect, "interface_change_commit",
                     libvirt_connect_interface_change_commit, -1);
    rb_define_method(c_connect, "interface_change_rollback",
                     libvirt_connect_interface_change_rollback, -1);
#endif

#if HAVE_VIRNODEGETCPUSTATS
    rb_define_method(c_connect, "node_get_cpu_stats",
                     libvirt_connect_node_get_cpu_stats, -1);
#endif
#if HAVE_CONST_VIR_NODE_CPU_STATS_ALL_CPUS
    rb_define_const(c_connect, "NODE_CPU_STATS_ALL_CPUS",
                    INT2NUM(VIR_NODE_CPU_STATS_ALL_CPUS));
#endif
#if HAVE_VIRNODEGETMEMORYSTATS
    rb_define_method(c_connect, "node_get_memory_stats",
                     libvirt_connect_node_get_memory_stats, -1);
#endif
#if HAVE_CONST_VIR_NODE_MEMORY_STATS_ALL_CELLS
    rb_define_const(c_connect, "NODE_MEMORY_STATS_ALL_CELLS",
                    INT2NUM(VIR_NODE_MEMORY_STATS_ALL_CELLS));
#endif

#if HAVE_VIRDOMAINSAVEIMAGEGETXMLDESC
    rb_define_method(c_connect, "save_image_get_xml_desc",
                     libvirt_connect_save_image_get_xml_desc, -1);
    rb_define_method(c_connect, "save_image_define_xml",
                     libvirt_connect_save_image_define_xml, -1);
#endif

#if HAVE_VIRNODESUSPENDFORDURATION
    rb_define_const(c_connect, "NODE_SUSPEND_TARGET_MEM",
                    INT2NUM(VIR_NODE_SUSPEND_TARGET_MEM));
    rb_define_const(c_connect, "NODE_SUSPEND_TARGET_DISK",
                    INT2NUM(VIR_NODE_SUSPEND_TARGET_DISK));
    rb_define_const(c_connect, "NODE_SUSPEND_TARGET_HYBRID",
                    INT2NUM(VIR_NODE_SUSPEND_TARGET_HYBRID));

    rb_define_method(c_connect, "node_suspend_for_duration",
                     libvirt_connect_node_suspend_for_duration, -1);
#endif

#if HAVE_VIRNODEGETMEMORYPARAMETERS
    rb_define_method(c_connect, "node_get_memory_parameters",
                     libvirt_connect_node_get_memory_parameters, -1);
    rb_define_method(c_connect, "node_set_memory_parameters",
                     libvirt_connect_node_set_memory_parameters, -1);
#endif

#if HAVE_VIRNODEGETCPUMAP
    rb_define_method(c_connect, "node_get_cpu_map",
                     libvirt_connect_node_get_cpu_map, -1);
#endif

#if HAVE_VIRCONNECTSETKEEPALIVE
    rb_define_method(c_connect, "set_keepalive", libvirt_connect_set_keepalive,
                     2);
#endif

#if HAVE_VIRCONNECTLISTALLDOMAINS
    rb_define_const(c_connect, "LIST_DOMAINS_ACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_ACTIVE));
    rb_define_const(c_connect, "LIST_DOMAINS_INACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_INACTIVE));
    rb_define_const(c_connect, "LIST_DOMAINS_PERSISTENT",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_PERSISTENT));
    rb_define_const(c_connect, "LIST_DOMAINS_TRANSIENT",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_TRANSIENT));
    rb_define_const(c_connect, "LIST_DOMAINS_RUNNING",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_RUNNING));
    rb_define_const(c_connect, "LIST_DOMAINS_PAUSED",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_PAUSED));
    rb_define_const(c_connect, "LIST_DOMAINS_SHUTOFF",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_SHUTOFF));
    rb_define_const(c_connect, "LIST_DOMAINS_OTHER",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_OTHER));
    rb_define_const(c_connect, "LIST_DOMAINS_MANAGEDSAVE",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE));
    rb_define_const(c_connect, "LIST_DOMAINS_NO_MANAGEDSAVE",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE));
    rb_define_const(c_connect, "LIST_DOMAINS_AUTOSTART",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_AUTOSTART));
    rb_define_const(c_connect, "LIST_DOMAINS_NO_AUTOSTART",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART));
    rb_define_const(c_connect, "LIST_DOMAINS_HAS_SNAPSHOT",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT));
    rb_define_const(c_connect, "LIST_DOMAINS_NO_SNAPSHOT",
                    INT2NUM(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT));
    rb_define_method(c_connect, "list_all_domains",
                     libvirt_connect_list_all_domains, -1);
#endif
#if HAVE_VIRCONNECTLISTALLNETWORKS
    rb_define_const(c_connect, "LIST_NETWORKS_ACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_NETWORKS_ACTIVE));
    rb_define_const(c_connect, "LIST_NETWORKS_INACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_NETWORKS_INACTIVE));
    rb_define_const(c_connect, "LIST_NETWORKS_PERSISTENT",
                    INT2NUM(VIR_CONNECT_LIST_NETWORKS_PERSISTENT));
    rb_define_const(c_connect, "LIST_NETWORKS_TRANSIENT",
                    INT2NUM(VIR_CONNECT_LIST_NETWORKS_TRANSIENT));
    rb_define_const(c_connect, "LIST_NETWORKS_AUTOSTART",
                    INT2NUM(VIR_CONNECT_LIST_NETWORKS_AUTOSTART));
    rb_define_const(c_connect, "LIST_NETWORKS_NO_AUTOSTART",
                    INT2NUM(VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART));
    rb_define_method(c_connect, "list_all_networks",
                     libvirt_connect_list_all_networks, -1);
#endif
#if HAVE_VIRCONNECTLISTALLINTERFACES
    rb_define_const(c_connect, "LIST_INTERFACES_INACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_INTERFACES_INACTIVE));
    rb_define_const(c_connect, "LIST_INTERFACES_ACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_INTERFACES_ACTIVE));
    rb_define_method(c_connect, "list_all_interfaces",
                     libvirt_connect_list_all_interfaces, -1);
#endif
#if HAVE_VIRCONNECTLISTALLSECRETS
    rb_define_const(c_connect, "LIST_SECRETS_EPHEMERAL",
                    INT2NUM(VIR_CONNECT_LIST_SECRETS_EPHEMERAL));
    rb_define_const(c_connect, "LIST_SECRETS_NO_EPHEMERAL",
                    INT2NUM(VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL));
    rb_define_const(c_connect, "LIST_SECRETS_PRIVATE",
                    INT2NUM(VIR_CONNECT_LIST_SECRETS_PRIVATE));
    rb_define_const(c_connect, "LIST_SECRETS_NO_PRIVATE",
                    INT2NUM(VIR_CONNECT_LIST_SECRETS_NO_PRIVATE));
    rb_define_method(c_connect, "list_all_secrets",
                     libvirt_connect_list_all_secrets, -1);
#endif
#if HAVE_VIRCONNECTLISTALLNODEDEVICES
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_SYSTEM",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_SYSTEM));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_PCI_DEV",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_PCI_DEV));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_USB_DEV",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_DEV));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_USB_INTERFACE",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_INTERFACE));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_NET",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_NET));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_SCSI_HOST",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_HOST));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_SCSI_TARGET",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_TARGET));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_SCSI",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_STORAGE",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_STORAGE));
#if HAVE_CONST_VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_FC_HOST",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST));
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_VPORTS",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPORTS));
#endif
#if HAVE_CONST_VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC
    rb_define_const(c_connect, "LIST_NODE_DEVICES_CAP_SCSI_GENERIC",
                    INT2NUM(VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC));
#endif
    rb_define_method(c_connect, "list_all_nodedevices",
                     libvirt_connect_list_all_nodedevices, -1);
#endif
#if HAVE_VIRCONNECTLISTALLSTORAGEPOOLS
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_INACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_ACTIVE",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_PERSISTENT",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_TRANSIENT",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_AUTOSTART",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_NO_AUTOSTART",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_DIR",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_DIR));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_FS",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_FS));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_NETFS",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_NETFS));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_LOGICAL",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_DISK",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_DISK));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_ISCSI",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_SCSI",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_SCSI));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_MPATH",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_MPATH));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_RBD",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_RBD));
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_SHEEPDOG",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG));
    rb_define_method(c_connect, "list_all_storage_pools",
                     libvirt_connect_list_all_storage_pools, -1);
#endif
#if HAVE_CONST_VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_GLUSTER",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER));
#endif
#if HAVE_CONST_VIR_CONNECT_LIST_STORAGE_POOLS_ZFS
    rb_define_const(c_connect, "LIST_STORAGE_POOLS_ZFS",
                    INT2NUM(VIR_CONNECT_LIST_STORAGE_POOLS_ZFS));
#endif
#if HAVE_VIRCONNECTLISTALLNWFILTERS
    rb_define_method(c_connect, "list_all_nwfilters",
                     libvirt_connect_list_all_nwfilters, -1);
#endif
#if HAVE_VIRCONNECTISALIVE
    rb_define_method(c_connect, "alive?", libvirt_connect_is_alive, 0);
#endif
#if HAVE_VIRDOMAINCREATEXMLWITHFILES
    rb_define_method(c_connect, "domain_create_xml_with_files",
                     libvirt_connect_domain_create_xml_with_files, -1);
#endif
#if HAVE_VIRDOMAINQEMUATTACH
    rb_define_method(c_connect, "qemu_attach", libvirt_connect_qemu_attach, -1);
#endif
#if HAVE_VIRCONNECTGETCPUMODELNAMES
    rb_define_method(c_connect, "get_cpu_model_names",
                     libvirt_connect_get_cpu_model_names, -1);
#endif
#if HAVE_VIRNODEALLOCPAGES
    rb_define_const(c_connect, "NODE_ALLOC_PAGES_ADD",
                    INT2NUM(VIR_NODE_ALLOC_PAGES_ADD));
    rb_define_const(c_connect, "NODE_ALLOC_PAGES_SET",
                    INT2NUM(VIR_NODE_ALLOC_PAGES_SET));
    rb_define_method(c_connect, "node_alloc_pages",
		     libvirt_connect_node_alloc_pages, -1);
#endif
#if HAVE_VIRCONNECTGETDOMAINCAPABILITIES
    rb_define_method(c_connect, "domain_capabilities",
                     libvirt_connect_domain_capabilities, -1);
#endif
}
