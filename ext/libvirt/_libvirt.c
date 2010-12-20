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

#if HAVE_VIRCONNECTOPENAUTH
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
 *
 * prompt - a suggested prompt to show to the user
 *
 * challenge - any additional challenge information
 *
 * defresult - a default result to use if credentials could not be obtained
 *
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
#endif

#if HAVE_VIREVENTREGISTERIMPL
static VALUE add_handle, update_handle, remove_handle;
static VALUE add_timeout, update_timeout, remove_timeout;

/*
 * call-seq:
 *   Libvirt::event_invoke_handle_callback(handle, fd, events, opaque) -> Qnil
 *
 * Unlike most of the other functions in the ruby-libvirt bindings, this one
 * does not directly correspond to a libvirt API function.  Instead, this
 * module method (and event_invoke_timeout_callback) are meant to be called
 * when there is an event of interest to libvirt on one of the file descriptors
 * that libvirt uses.  The application is notified of the file descriptors
 * that libvirt uses via the callbacks from Libvirt::event_register_impl.  When
 * there is an event of interest, the application must call
 * event_invoke_timeout_callback to ensure proper operation.
 *
 * Libvirt::event_invoke_handle_callback takes 4 arguments:
 *
 * handle
 *          an application specific handle ID.  This can be any integer, but
 *          must be unique from all other libvirt handles in the application.
 * fd
 *          the file descriptor of interest.  This was given to the application
 *          as a callback to add_handle of Libvirt::event_register_impl
 * events
 *          the events that have occured on the fd.  Note that the events are
 *          libvirt specific, and are some combination of
 *          Libvirt::EVENT_HANDLE_READABLE, Libvirt::EVENT_HANDLE_WRITABLE,
 *          Libvirt::EVENT_HANDLE_ERROR, Libvirt::EVENT_HANDLE_HANGUP.  To
 *          notify libvirt of more than one event at a time, these values should
 *          be logically OR'ed together.
 * opaque
 *          the opaque data passed from libvirt during the
 *          Libvirt::event_register_impl add_handle callback.  To ensure proper
 *          operation this data must be passed through to
 *          event_invoke_handle_callback without modification.
 */
static VALUE libvirt_event_invoke_handle_callback(VALUE m, VALUE handle,
                                                  VALUE fd, VALUE events,
                                                  VALUE opaque) {
    virEventHandleCallback cb;
    void *op;
    VALUE libvirt_cb;
    VALUE libvirt_opaque;

    if (TYPE(opaque) != T_HASH)
        rb_raise(rb_eTypeError,
                 "wrong event callback argument type (expected Hash)");

    libvirt_cb = rb_hash_aref(opaque, rb_str_new2("libvirt_cb"));

    /* This is equivalent to Data_Get_Struct; I reproduce it here because
     * I don't want the additional type-cast that Data_Get_Struct does
     */
    Check_Type(libvirt_cb, T_DATA);
    cb = DATA_PTR(libvirt_cb);

    if (cb) {
        libvirt_opaque = rb_hash_aref(opaque, rb_str_new2("opaque"));
        Data_Get_Struct(libvirt_opaque, void *, op);
        cb(NUM2INT(handle), NUM2INT(fd), NUM2INT(events), op);
    }

    return Qnil;
}

/*
 * call-seq:
 *   Libvirt::event_invoke_timeout_callback(timer, opaque) -> Qnil
 *
 * Unlike most of the other functions in the ruby-libvirt bindings, this one
 * does not directly correspond to a libvirt API function.  Instead, this
 * module method (and event_invoke_handle_callback) are meant to be called
 * when there is a timeout of interest to libvirt.  The application is
 * notified of the timers that libvirt uses via the callbacks from
 * Libvirt::event_register_impl.  When a timeout expires, the application must
 * call event_invoke_timeout_callback to ensure proper operation.
 *
 * Libvirt::event_invoke_timeout_callback takes 2 arguments:
 *
 * handle
 *          an application specific timer ID.  This can be any integer, but
 *          must be unique from all other libvirt timers in the application.
 * opaque
 *          the opaque data passed from libvirt during the
 *          Libvirt::event_register_impl add_handle callback.  To ensure proper
 *          operation this data must be passed through to
 *          event_invoke_handle_callback without modification.
 */
static VALUE libvirt_event_invoke_timeout_callback(VALUE m, VALUE timer,
                                                   VALUE opaque) {
    virEventTimeoutCallback cb;
    void *op;
    VALUE libvirt_cb;
    VALUE libvirt_opaque;

    if (TYPE(opaque) != T_HASH)
        rb_raise(rb_eTypeError,
                 "wrong event callback argument type (expected Hash)");

    libvirt_cb = rb_hash_aref(opaque, rb_str_new2("libvirt_cb"));

    /* This is equivalent to Data_Get_Struct; I reproduce it here because
     * I don't want the additional type-cast that Data_Get_Struct does
     */
    Check_Type(libvirt_cb, T_DATA);
    cb = DATA_PTR(libvirt_cb);

    if (cb) {
        libvirt_opaque = rb_hash_aref(opaque, rb_str_new2("opaque"));
        Data_Get_Struct(libvirt_opaque, void *, op);
        cb(NUM2INT(timer), op);
    }

    return Qnil;
}

static int internal_add_handle_func(int fd, int events,
                                    virEventHandleCallback cb, void *opaque,
                                    virFreeCallback ff) {
    VALUE rubyargs;
    VALUE res;

    rubyargs = rb_hash_new();
    rb_hash_aset(rubyargs, rb_str_new2("libvirt_cb"),
                 Data_Wrap_Struct(rb_class_of(add_handle), NULL, NULL, cb));
    rb_hash_aset(rubyargs, rb_str_new2("opaque"),
                 Data_Wrap_Struct(rb_class_of(add_handle), NULL, NULL, opaque));
    rb_hash_aset(rubyargs, rb_str_new2("free_func"),
                 Data_Wrap_Struct(rb_class_of(add_handle), NULL, NULL, ff));

    /* call out to the ruby object */
    if (strcmp(rb_obj_classname(add_handle), "Symbol") == 0)
        res = rb_funcall(rb_class_of(add_handle), rb_to_id(add_handle), 3,
                         INT2FIX(fd), INT2FIX(events), rubyargs);
    else if (strcmp(rb_obj_classname(add_handle), "Proc") == 0)
        res = rb_funcall(add_handle, rb_intern("call"), 3, INT2FIX(fd),
                         INT2FIX(events), rubyargs);
    else
        rb_raise(rb_eTypeError,
                 "wrong add handle callback argument type (expected Symbol or Proc)");

    if (TYPE(res) != T_FIXNUM)
        rb_raise(rb_eTypeError,
                 "expected integer return from add_handle callback");

    return NUM2INT(res);
}

static void internal_update_handle_func(int watch, int event) {
    /* call out to the ruby object */
    if (strcmp(rb_obj_classname(update_handle), "Symbol") == 0)
        rb_funcall(rb_class_of(update_handle), rb_to_id(update_handle), 2,
                   INT2FIX(watch), INT2FIX(event));
    else if (strcmp(rb_obj_classname(update_handle), "Proc") == 0)
        rb_funcall(update_handle, rb_intern("call"), 2, INT2FIX(watch),
                   INT2FIX(event));
    else
        rb_raise(rb_eTypeError,
                 "wrong update handle callback argument type (expected Symbol or Proc)");
}

static int internal_remove_handle_func(int watch) {
    VALUE res;
    virFreeCallback ff_cb;
    void *op;
    VALUE libvirt_opaque;
    VALUE ff;

    /* call out to the ruby object */
    if (strcmp(rb_obj_classname(remove_handle), "Symbol") == 0)
        res = rb_funcall(rb_class_of(remove_handle), rb_to_id(remove_handle),
                         1, INT2FIX(watch));
    else if (strcmp(rb_obj_classname(remove_handle), "Proc") == 0)
        res = rb_funcall(remove_handle, rb_intern("call"), 1, INT2FIX(watch));
    else
        rb_raise(rb_eTypeError,
                 "wrong remove handle callback argument type (expected Symbol or Proc)");

    if (TYPE(res) != T_HASH)
        rb_raise(rb_eTypeError,
                 "expected opaque hash returned from remove_handle callback");

    ff = rb_hash_aref(res, rb_str_new2("free_func"));
    if (!NIL_P(ff)) {
        /* This is equivalent to Data_Get_Struct; I reproduce it here because
         * I don't want the additional type-cast that Data_Get_Struct does
         */
        Check_Type(ff, T_DATA);
        ff_cb = DATA_PTR(ff);
        if (ff_cb) {
            libvirt_opaque = rb_hash_aref(res, rb_str_new2("opaque"));
            Data_Get_Struct(libvirt_opaque, void *, op);

            (*ff_cb)(op);
        }
    }

    return 0;
}

static int internal_add_timeout_func(int interval, virEventTimeoutCallback cb,
                                     void *opaque, virFreeCallback ff) {
    VALUE rubyargs;
    VALUE res;

    rubyargs = rb_hash_new();

    rb_hash_aset(rubyargs, rb_str_new2("libvirt_cb"),
                 Data_Wrap_Struct(rb_class_of(add_timeout), NULL, NULL, cb));
    rb_hash_aset(rubyargs, rb_str_new2("opaque"),
                 Data_Wrap_Struct(rb_class_of(add_timeout), NULL, NULL,
                                  opaque));
    rb_hash_aset(rubyargs, rb_str_new2("free_func"),
                 Data_Wrap_Struct(rb_class_of(add_timeout), NULL, NULL, ff));

    /* call out to the ruby object */
    if (strcmp(rb_obj_classname(add_timeout), "Symbol") == 0)
        res = rb_funcall(rb_class_of(add_timeout), rb_to_id(add_timeout), 2,
                         INT2FIX(interval), rubyargs);
    else if (strcmp(rb_obj_classname(add_timeout), "Proc") == 0)
        res = rb_funcall(add_timeout, rb_intern("call"), 2, INT2FIX(interval),
                         rubyargs);
    else
        rb_raise(rb_eTypeError,
                 "wrong add timeout callback argument type (expected Symbol or Proc)");

    if (TYPE(res) != T_FIXNUM)
        rb_raise(rb_eTypeError,
                 "expected integer return from add_timeout callback");

    return NUM2INT(res);
}

static void internal_update_timeout_func(int timer, int timeout) {
    /* call out to the ruby object */
    if (strcmp(rb_obj_classname(update_timeout), "Symbol") == 0)
        rb_funcall(rb_class_of(update_timeout), rb_to_id(update_timeout), 2,
                   INT2FIX(timer), INT2FIX(timeout));
    else if (strcmp(rb_obj_classname(update_timeout), "Proc") == 0)
        rb_funcall(update_timeout, rb_intern("call"), 2, INT2FIX(timer),
                   INT2FIX(timeout));
    else
        rb_raise(rb_eTypeError,
                 "wrong update timeout callback argument type (expected Symbol or Proc)");
}

static int internal_remove_timeout_func(int timer) {
    VALUE res;
    virFreeCallback ff_cb;
    void *op;
    VALUE libvirt_opaque;
    VALUE ff;

    /* call out to the ruby object */
    if (strcmp(rb_obj_classname(remove_timeout), "Symbol") == 0)
        res = rb_funcall(rb_class_of(remove_timeout), rb_to_id(remove_timeout),
                         1, INT2FIX(timer));
    else if (strcmp(rb_obj_classname(remove_timeout), "Proc") == 0)
        res = rb_funcall(remove_timeout, rb_intern("call"), 1, INT2FIX(timer));
    else
        rb_raise(rb_eTypeError,
                 "wrong remove timeout callback argument type (expected Symbol or Proc)");

    if (TYPE(res) != T_HASH)
        rb_raise(rb_eTypeError,
                 "expected opaque hash returned from remove_timeout callback");

    ff = rb_hash_aref(res, rb_str_new2("free_func"));
    if (!NIL_P(ff)) {
        /* This is equivalent to Data_Get_Struct; I reproduce it here because
         * I don't want the additional type-cast that Data_Get_Struct does
         */
        Check_Type(ff, T_DATA);
        ff_cb = DATA_PTR(ff);
        if (ff_cb) {
            libvirt_opaque = rb_hash_aref(res, rb_str_new2("opaque"));
            Data_Get_Struct(libvirt_opaque, void *, op);

            (*ff_cb)(op);
        }
    }

    return 0;
}

#define set_event_func_or_null(type)                \
    do {                                            \
        if (NIL_P(type))                            \
            type##_temp = NULL;                     \
        else                                        \
            type##_temp = internal_##type##_func;   \
    } while(0)

static int is_symbol_proc_or_nil(VALUE handle) {
    if (NIL_P(handle))
        return 1;
    return is_symbol_or_proc(handle);
}

/*
 * call-seq:
 *   Libvirt::event_register_impl(add_handle=nil, update_handle=nil, remove_handle=nil, add_timeout=nil, update_timeout=nil, remove_timeout=nil) -> Qnil
 *
 * Call
 * +virEventRegisterImpl+[http://www.libvirt.org/html/libvirt-libvirt.html#virEventRegisterImpl]
 * to register callback handlers for handles and timeouts.  These handles and
 * timeouts are used as part of the libvirt infrastructure for generating
 * domain events.  Each callback must be a Symbol (that is the name of a
 * method to callback), a Proc, or nil (to disable the callback).  In the
 * end-user application program, these callbacks are typically used to track
 * the file descriptors or timers that libvirt is interested in (and is intended
 * to be integrated into the "main loop" of a UI program).  The individual
 * callbacks will be given a certain number of arguments, and must return
 * certain values.  Those arguments and return types are:
 *
 * add_handle(fd, events, opaque) => Fixnum
 *
 * update_handle(handleID, event) => nil
 *
 * remove_handle(handleID) => opaque data from add_handle
 *
 * add_timeout(interval, opaque) => Fixnum
 *
 * update_timeout(timerID, timeout) => nil
 *
 * remove_timeout(timerID) => opaque data from add_timeout
 *
 * Any arguments marked as "opaque" must be accepted from the library and saved
 * without modification.  The values passed to the callbacks are meant to be
 * passed to the event_invoke_handle_callback and event_invoke_timeout_callback
 * module methods; see the documentation for those methods for more details.
 */
static VALUE libvirt_conn_event_register_impl(int argc, VALUE *argv, VALUE c) {
    virEventAddHandleFunc add_handle_temp;
    virEventUpdateHandleFunc update_handle_temp;
    virEventRemoveHandleFunc remove_handle_temp;
    virEventAddTimeoutFunc add_timeout_temp;
    virEventUpdateTimeoutFunc update_timeout_temp;
    virEventRemoveTimeoutFunc remove_timeout_temp;

    /*
     * subtle; we put the arguments (callbacks) directly into the global
     * add_handle, update_handle, etc. variables.  Then we register the
     * internal functions as the callbacks with virEventRegisterImpl
     */
    rb_scan_args(argc, argv, "06", &add_handle, &update_handle, &remove_handle,
                 &add_timeout, &update_timeout, &remove_timeout);

    if (!is_symbol_proc_or_nil(add_handle) ||
        !is_symbol_proc_or_nil(update_handle) ||
        !is_symbol_proc_or_nil(remove_handle) ||
        !is_symbol_proc_or_nil(add_timeout) ||
        !is_symbol_proc_or_nil(update_timeout) ||
        !is_symbol_proc_or_nil(remove_timeout))
        rb_raise(rb_eTypeError,
                 "wrong argument type (expected Symbol, Proc, or nil)");

    set_event_func_or_null(add_handle);
    set_event_func_or_null(update_handle);
    set_event_func_or_null(remove_handle);
    set_event_func_or_null(add_timeout);
    set_event_func_or_null(update_timeout);
    set_event_func_or_null(remove_timeout);

    /* virEventRegisterImpl returns void, so no error checking here */
    virEventRegisterImpl(add_handle_temp, update_handle_temp,
                         remove_handle_temp, add_timeout_temp,
                         update_timeout_temp, remove_timeout_temp);

    return Qnil;
}
#endif

/*
 * Module Libvirt
 */
void Init__libvirt() {
    m_libvirt = rb_define_module("Libvirt");
    c_libvirt_version = rb_define_class_under(m_libvirt, "Version",
                                              rb_cObject);

#if HAVE_VIRCONNECTOPENAUTH
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
#endif

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
    rb_define_attr(e_Error, "libvirt_code", 1, 0);

    rb_define_module_function(m_libvirt, "version", libvirt_version, -1);
    rb_define_module_function(m_libvirt, "open", libvirt_open, -1);
    rb_define_module_function(m_libvirt, "open_read_only",
                              libvirt_open_read_only, -1);
#if HAVE_VIRCONNECTOPENAUTH
    rb_define_module_function(m_libvirt, "open_auth", libvirt_open_auth, -1);
#endif

#if HAVE_VIREVENTREGISTERIMPL
    rb_define_const(m_libvirt, "EVENT_HANDLE_READABLE",
                    INT2NUM(VIR_EVENT_HANDLE_READABLE));
    rb_define_const(m_libvirt, "EVENT_HANDLE_WRITABLE",
                    INT2NUM(VIR_EVENT_HANDLE_WRITABLE));
    rb_define_const(m_libvirt, "EVENT_HANDLE_ERROR",
                    INT2NUM(VIR_EVENT_HANDLE_ERROR));
    rb_define_const(m_libvirt, "EVENT_HANDLE_HANGUP",
                    INT2NUM(VIR_EVENT_HANDLE_HANGUP));

    /* since we are using globals, we have to register with the gc */
    rb_global_variable(&add_handle);
    rb_global_variable(&update_handle);
    rb_global_variable(&remove_handle);
    rb_global_variable(&add_timeout);
    rb_global_variable(&update_timeout);
    rb_global_variable(&remove_timeout);

    rb_define_module_function(m_libvirt, "event_register_impl",
                              libvirt_conn_event_register_impl, -1);
    rb_define_module_function(m_libvirt, "event_invoke_handle_callback",
                              libvirt_event_invoke_handle_callback, 4);
    rb_define_module_function(m_libvirt, "event_invoke_timeout_callback",
                              libvirt_event_invoke_timeout_callback, 2);
#endif

    init_connect();
    init_storage();
    init_network();
    init_nodedevice();
    init_secret();
    init_nwfilter();
    init_interface();
    init_domain();

    virSetErrorFunc(NULL, rubyLibvirtErrorFunc);

    if (virInitialize() < 0)
        rb_raise(rb_eSystemCallError, "virInitialize failed");
}
