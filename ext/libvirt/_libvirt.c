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

/* define additional errors here */
static VALUE e_ConnectionError;         /* ConnectionError - error during connection establishment */
VALUE e_DefinitionError;
VALUE e_RetrieveError;
VALUE e_Error;
VALUE e_NoSupportError;

/* custom error function to suppress libvirt printing to stderr */
static void rubyLibvirtErrorFunc(void *userdata, virErrorPtr err){
}

/*
 * call-seq:
 *   Libvirt::version(type=nil) -> [ libvirt_version, type_version ]
 *
 * Call
 * +virGetVersion+[http://www.libvirt.org/html/libvirt-libvirt.html#virGetVersion]
 * to get the version of libvirt and of the hypervisor TYPE.
 */
static VALUE libvirt_version(int argc, VALUE *argv, VALUE m) {
    unsigned long libVer;
    VALUE type;
    unsigned long typeVer;
    int r;
    VALUE result, rargv[2];

    rb_scan_args(argc, argv, "01", &type);

    r = virGetVersion(&libVer, get_string_or_nil(type), &typeVer);
    _E(r < 0, create_error(rb_eArgError, "virGetVersion", NULL));

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

    _E(conn == NULL, create_error(e_ConnectionError,
                                  readonly ? "virConnectOpenReadOnly" : "virConnectOpen",
                                  NULL));

    return connect_new(conn);
}

/*
 * call-seq:
 *   Libvirt::open(uri=nil) -> Libvirt::Connect
 *
 * Call
 * +virConnectOpen+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectOpen]
 * to open a connection to a URL.
 */
static VALUE libvirt_open(int argc, VALUE *argv, VALUE m) {
    return internal_open(argc, argv, m, 0);
}

/*
 * call-seq:
 *   Libvirt::open_read_only(uri=nil) -> Libvirt::Connect
 *
 * Call
 * +virConnectOpenReadOnly+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectOpenReadOnly]
 * to open a read-only connection to a URL.
 */
static VALUE libvirt_open_read_only(int argc, VALUE *argv, VALUE m) {
    return internal_open(argc, argv, m, 1);
}

static int libvirt_auth_callback_wrapper(virConnectCredentialPtr cred,
                                         unsigned int ncred, void *cbdata) {
    VALUE userdata;
    VALUE newcred;
    int i;
    VALUE result;

    userdata = (VALUE)cbdata;

    if (!rb_block_given_p())
        rb_raise(rb_eRuntimeError, "No block given, this should never happen!\n");

    for (i = 0; i < ncred; i++) {
        newcred = rb_hash_new();

        rb_hash_aset(newcred, rb_str_new2("type"), INT2FIX(cred[i].type));
        rb_hash_aset(newcred, rb_str_new2("prompt"),
                     rb_str_new2(cred[i].prompt));
        if (cred[i].challenge)
            rb_hash_aset(newcred, rb_str_new2("challenge"),
                         rb_str_new2(cred[i].challenge));
        else
            rb_hash_aset(newcred, rb_str_new2("challenge"), Qnil);
        if (cred[i].defresult)
            rb_hash_aset(newcred, rb_str_new2("defresult"),
                         rb_str_new2(cred[i].defresult));
        else
            rb_hash_aset(newcred, rb_str_new2("defresult"), Qnil);
        rb_hash_aset(newcred, rb_str_new2("result"), Qnil);
        rb_hash_aset(newcred, rb_str_new2("userdata"), userdata);

        result = rb_yield(newcred);
        if (NIL_P(result)) {
            cred[i].result = NULL;
            cred[i].resultlen = 0;
        }
        else {
            cred[i].result = strdup(StringValueCStr(result));
            cred[i].resultlen = strlen(cred[i].result);
        }
    }

    return 0;
}


struct wrap_callout {
    char *uri;
    virConnectAuthPtr auth;
    unsigned int flags;
};

static VALUE rb_open_auth_wrap(VALUE arg) {
    struct wrap_callout *e = (struct wrap_callout *)arg;

    return (VALUE)virConnectOpenAuth(e->uri, e->auth, e->flags);
}

static VALUE rb_num2int_wrap(VALUE arg) {
    return NUM2INT(arg);
}

/*
 * call-seq:
 *   Libvirt::open_auth(uri=nil, credlist=nil, userdata=nil, flags=0) {|...| authentication block} -> Libvirt::Connect
 *
 * Call
 * +virConnectOpenAuth+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectOpenAuth]
 * to open a connection to a libvirt URI, with a possible authentication block.
 * If an authentication block is desired, then credlist should be an array that
 * specifies which credentials the authentication block is willing to support;
 * the full list is available at http://libvirt.org/html/libvirt-libvirt.html#virConnectCredentialType.
 * If userdata is not nil and an authentication block is given, userdata will
 * be passed unaltered into the authentication block.  The flags parameter
 * controls how to open connection.  The only options currently available for
 * flags are 0 for a read/write connection and Libvirt::CONNECT_RO for a
 * read-only connection.
 *
 * If the credlist is not empty, and an authentication block is given, the
 * authentication block will be called once for each credential necessary
 * to complete the authentication.  The authentication block will be passed a
 * single parameter, which is a hash of values containing information necessary
 * to complete authentication.  This hash contains 5 elements:
 *
 * type - the type of credential to be examined
 * prompt - a suggested prompt to show to the user
 * challenge - any additional challenge information
 * defresult - a default result to use if credentials could not be obtained
 * userdata - the userdata passed into open_auth initially
 *
 * The authentication block should return the result of collecting the
 * information; these results will then be sent to libvirt for authentication.
 */
static VALUE libvirt_open_auth(int argc, VALUE *argv, VALUE m) {
    virConnectAuthPtr auth;
    VALUE uri;
    VALUE credlist;
    VALUE userdata;
    VALUE flags_val;
    char *uri_c;
    virConnectPtr conn = NULL;
    unsigned int flags;
    int auth_alloc;
    int i;
    VALUE tmp;
    int exception = 0;
    struct rb_ary_entry_arg args;
    struct wrap_callout callargs;

    rb_scan_args(argc, argv, "04", &uri, &credlist, &userdata, &flags_val);

    /* handle the optional URI */
    uri_c = get_string_or_nil(uri);

    /* handle the optional flags */
    if (NIL_P(flags_val))
        flags = 0;
    else
        flags = NUM2UINT(flags_val);

    if (rb_block_given_p()) {
        auth = ALLOC(virConnectAuth);
        auth_alloc = 1;

        if (TYPE(credlist) == T_NIL)
            auth->ncredtype = 0;
        else if (TYPE(credlist) == T_ARRAY)
            auth->ncredtype = RARRAY_LEN(credlist);
        else
            rb_raise(rb_eTypeError, "wrong argument type (expected Array or nil)");
        auth->credtype = NULL;
        if (auth->ncredtype > 0) {
            /* we don't use ALLOC_N here because that can throw an exception,
             * and leak the auth pointer.  Instead we use normal malloc
             * (which has a slightly higher chance of returning NULL), and
             * then properly cleanup if it fails
             */
            auth->credtype = malloc(sizeof(int) * auth->ncredtype);
            if (auth->credtype == NULL) {
                xfree(auth);
                rb_memerror();
            }
            for (i = 0; i < auth->ncredtype; i++) {
                args.arr = credlist;
                args.elem = i;
                tmp = rb_protect(rb_ary_entry_wrap, (VALUE)&args, &exception);
                if (exception)
                    goto do_cleanup;

                auth->credtype[i] = rb_protect(rb_num2int_wrap, tmp,
                                               &exception);
                if (exception)
                    goto do_cleanup;
            }
        }

        auth->cb = libvirt_auth_callback_wrapper;
        auth->cbdata = (void *)userdata;
    }
    else {
        auth = virConnectAuthPtrDefault;
        auth_alloc = 0;
    }

    callargs.uri = uri_c;
    callargs.auth = auth;
    callargs.flags = flags;

    conn = (virConnectPtr)rb_protect(rb_open_auth_wrap, (VALUE)&callargs,
                                     &exception);

do_cleanup:
    if (auth_alloc) {
        free(auth->credtype);
        xfree(auth);
    }

    if (exception)
        rb_jump_tag(exception);

    _E(conn == NULL, create_error(e_ConnectionError, "virConnectOpenAuth",
                                  NULL));

    return connect_new(conn);
}

/*
 * Module Libvirt
 */
void Init__libvirt() {
    int r;

    m_libvirt = rb_define_module("Libvirt");
    c_libvirt_version = rb_define_class_under(m_libvirt, "Version",
                                              rb_cObject);

    rb_define_const(m_libvirt, "CONNECT_RO", INT2NUM(VIR_CONNECT_RO));

    rb_define_const(m_libvirt, "CRED_USERNAME", INT2NUM(VIR_CRED_USERNAME));
    rb_define_const(m_libvirt, "CRED_AUTHNAME", INT2NUM(VIR_CRED_AUTHNAME));
    rb_define_const(m_libvirt, "CRED_LANGUAGE", INT2NUM(VIR_CRED_LANGUAGE));
    rb_define_const(m_libvirt, "CRED_CNONCE", INT2NUM(VIR_CRED_CNONCE));
    rb_define_const(m_libvirt, "CRED_PASSPHRASE", INT2NUM(VIR_CRED_PASSPHRASE));
    rb_define_const(m_libvirt, "CRED_ECHOPROMPT", INT2NUM(VIR_CRED_ECHOPROMPT));
    rb_define_const(m_libvirt, "CRED_NOECHOPROMPT", INT2NUM(VIR_CRED_NOECHOPROMPT));
    rb_define_const(m_libvirt, "CRED_REALM", INT2NUM(VIR_CRED_REALM));
    rb_define_const(m_libvirt, "CRED_EXTERNAL", INT2NUM(VIR_CRED_EXTERNAL));

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
    e_NoSupportError =  rb_define_class_under(m_libvirt, "NoSupportError",
                                              e_Error);

    rb_define_attr(e_Error, "libvirt_function_name", 1, 0);
    rb_define_attr(e_Error, "libvirt_message", 1, 0);

    rb_define_module_function(m_libvirt, "version", libvirt_version, -1);
	rb_define_module_function(m_libvirt, "open", libvirt_open, -1);
	rb_define_module_function(m_libvirt, "open_read_only",
                              libvirt_open_read_only, -1);
    rb_define_module_function(m_libvirt, "open_auth", libvirt_open_auth, -1);

    init_connect();
    init_storage();
    init_network();
    init_nodedevice();
    init_secret();
    init_nwfilter();
    init_interface();
    init_domain();

    virSetErrorFunc(NULL, rubyLibvirtErrorFunc);

    r = virInitialize();
    if (r < 0)
        rb_raise(rb_eSystemCallError, "virInitialize failed");
}
