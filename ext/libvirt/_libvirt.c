/*
 * libvirt.c: Ruby bindings for libvirt
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
 *
 * Author: David Lutterkort <dlutter@redhat.com>
 */

#include <ruby.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include "extconf.h"
#include "common.h"
#include "storage.h"
#include "connect.h"
#include "network.h"
#include "nodedevice.h"
#include "secret.h"
#include "nwfilter.h"
#include "interface.h"
#include "domain.h"

static VALUE c_libvirt_version;

VALUE m_libvirt;

// define additional errors here
static VALUE e_ConnectionError;         // ConnectionError - error durring connection establishment
VALUE e_DefinitionError;
VALUE e_RetrieveError;
VALUE e_Error;

/*
 * call-seq:
 *   Libvirt::version(type) -> [ libvirt_version, type_version ]
 *
 * Call
 * +virGetVersion+[http://www.libvirt.org/html/libvirt-libvirt.html#virGetVersion]
 * to get the version of libvirt and of the hypervisor TYPE. Returns an
 * array with two entries of type Libvirt::Version.
 */
static VALUE libvirt_version(int argc, VALUE *argv, VALUE m) {
    unsigned long libVer;
    VALUE type;
    unsigned long typeVer;
    int r;
    VALUE result, rargv[2];

    rb_scan_args(argc, argv, "01", &type);

    r = virGetVersion(&libVer, get_string_or_nil(type), &typeVer);
    _E(r < 0, create_error(rb_eArgError, "virGetVersion",
                           "Failed to get version", NULL));

    result = rb_ary_new2(2);
    rargv[0] = rb_str_new2("libvirt");
    rargv[1] = ULONG2NUM(libVer);
    rb_ary_push(result, rb_class_new_instance(2, rargv, c_libvirt_version));
    rargv[0] = type;
    rargv[1] = ULONG2NUM(typeVer);
    rb_ary_push(result, rb_class_new_instance(2, rargv, c_libvirt_version));
    return result;
}

static VALUE internal_open(int argc, VALUE *argv, VALUE m, int readonly)
{
    VALUE uri;
    char *uri_c;
    virConnectPtr conn;

    rb_scan_args(argc, argv, "01", &uri);

    uri_c = get_string_or_nil(uri);

    if (readonly)
        conn = virConnectOpenReadOnly(uri_c);
    else
        conn = virConnectOpen(uri_c);

    if (conn == NULL)
        rb_raise(e_ConnectionError, "Failed to open%sconnection to '%s'",
                 readonly ? " readonly " : " ", uri_c);

    return connect_new(conn);
}

/*
 * call-seq:
 *   Libvirt::open(url) -> Libvirt::Connect
 *
 * Call
 * +virConnectOpen+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectOpen]
 * to open a connection to a URL.  Returns a new Libvirt::Connect object.
 */
static VALUE libvirt_open(int argc, VALUE *argv, VALUE m) {
    return internal_open(argc, argv, m, 0);
}

/*
 * call-seq:
 *   Libvirt::open_read_only(url) -> Libvirt::Connect
 *
 * Call
 * +virConnectOpenReadOnly+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectOpenReadOnly]
 * to open a read-only connection to a URL.  Returns a new Libvirt::Connect
 * object.
 */
static VALUE libvirt_open_read_only(int argc, VALUE *argv, VALUE m) {
    return internal_open(argc, argv, m, 1);
}

/*
 * Module Libvirt
 */
void Init__libvirt() {
    int r;

    m_libvirt = rb_define_module("Libvirt");
    c_libvirt_version = rb_define_class_under(m_libvirt, "Version",
                                              rb_cObject);


    /*
     * Libvirt Errors
     */
    e_Error =           rb_define_class_under(m_libvirt, "Error",
                                              rb_eStandardError);
    e_ConnectionError = rb_define_class_under(m_libvirt, "ConnectionError",
                                              e_Error);
    e_DefinitionError = rb_define_class_under(m_libvirt, "DefinitionError",
                                              e_Error);
    e_RetrieveError =   rb_define_class_under(m_libvirt, "RetrieveError",
                                              e_Error);

    // create 'libvirt_function_name' and 'vir_connect_ptr' attributes on e_Error class
    rb_define_attr(e_Error, "libvirt_function_name", 1, 0);
    rb_define_attr(e_Error, "libvirt_message", 1, 0);

    rb_define_module_function(m_libvirt, "version", libvirt_version, -1);
	rb_define_module_function(m_libvirt, "open", libvirt_open, -1);
	rb_define_module_function(m_libvirt, "open_read_only",
                              libvirt_open_read_only, -1);
    // FIXME: implement this
    //rb_define_module_function(m_libvirt, "open_auth", libvirt_open_auth, -1);

    init_connect();
    init_storage();
    init_network();
    init_nodedevice();
    init_secret();
    init_nwfilter();
    init_interface();
    init_domain();

    r = virInitialize();
    if (r < 0)
        rb_raise(rb_eSystemCallError, "virInitialize failed");
}
