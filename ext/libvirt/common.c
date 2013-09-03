/*
 * common.c: Common utilities for the ruby libvirt bindings
 *
 * Copyright (C) 2007,2010 Red Hat Inc.
 * Copyright (C) 2013 Chris Lalancette <clalancette@gmail.com>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <ruby.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include "common.h"

struct rb_exc_new2_arg {
    VALUE error;
    char *msg;
};

static VALUE rb_exc_new2_wrap(VALUE arg)
{
    struct rb_exc_new2_arg *e = (struct rb_exc_new2_arg *)arg;

    return rb_exc_new2(e->error, e->msg);
}

VALUE rb_ary_new2_wrap(VALUE arg)
{
    return rb_ary_new2(*((int *)arg));
}

VALUE rb_ary_push_wrap(VALUE arg)
{
    struct rb_ary_push_arg *e = (struct rb_ary_push_arg *)arg;

    return rb_ary_push(e->arr, e->value);
}

VALUE rb_str_new2_wrap(VALUE arg)
{
    char **str = (char **)arg;

    return rb_str_new2(*str);
}

VALUE rb_ary_entry_wrap(VALUE arg)
{
    struct rb_ary_entry_arg *e = (struct rb_ary_entry_arg *)arg;

    return rb_ary_entry(e->arr, e->elem);
}

VALUE rb_ary_new_wrap(VALUE arg)
{
    return rb_ary_new();
}

VALUE rb_str_new_wrap(VALUE arg)
{
    struct rb_str_new_arg *e = (struct rb_str_new_arg *)arg;

    return rb_str_new(e->val, e->size);
}

VALUE rb_iv_set_wrap(VALUE arg)
{
    struct rb_iv_set_arg *e = (struct rb_iv_set_arg *)arg;

    return rb_iv_set(e->klass, e->member, e->value);
}

VALUE rb_class_new_instance_wrap(VALUE arg)
{
    struct rb_class_new_instance_arg *e = (struct rb_class_new_instance_arg *)arg;

    return rb_class_new_instance(e->argc, e->argv, e->klass);
}

VALUE rb_string_value_cstr_wrap(VALUE arg)
{
    return (VALUE)rb_string_value_cstr((VALUE *)arg);
}

/* Error handling */
VALUE create_error(VALUE error, const char* method, virConnectPtr conn)
{
    VALUE ruby_errinfo;
    virErrorPtr err;
    char *msg;
    int rc;
    struct rb_exc_new2_arg arg;
    int exception = 0;

    if (conn == NULL) {
        err = virGetLastError();
    }
    else {
        err = virConnGetLastError(conn);
    }

    if (err != NULL && err->message != NULL) {
        rc = asprintf(&msg, "Call to %s failed: %s", method, err->message);
    }
    else {
        rc = asprintf(&msg, "Call to %s failed", method);
    }

    if (rc < 0) {
        /* there's not a whole lot we can do here; try to raise an
         * out-of-memory message */
        rb_memerror();
    }

    arg.error = error;
    arg.msg = msg;
    ruby_errinfo = rb_protect(rb_exc_new2_wrap, (VALUE)&arg, &exception);
    free(msg);
    if (exception) {
        rb_jump_tag(exception);
    }

    rb_iv_set(ruby_errinfo, "@libvirt_function_name", rb_str_new2(method));

    if (err != NULL) {
        rb_iv_set(ruby_errinfo, "@libvirt_code", INT2NUM(err->code));
        rb_iv_set(ruby_errinfo, "@libvirt_component", INT2NUM(err->domain));
        rb_iv_set(ruby_errinfo, "@libvirt_level", INT2NUM(err->level));
        if (err->message != NULL) {
            rb_iv_set(ruby_errinfo, "@libvirt_message",
                      rb_str_new2(err->message));
        }
    }

    return ruby_errinfo;
};

char *get_string_or_nil(VALUE arg)
{
    if (TYPE(arg) == T_NIL) {
        return NULL;
    }
    else if (TYPE(arg) == T_STRING) {
        return StringValueCStr(arg);
    }
    else {
        rb_raise(rb_eTypeError, "wrong argument type (expected String or nil)");
    }

    return NULL;
}

VALUE generic_new(VALUE klass, void *ptr, VALUE conn,
                  RUBY_DATA_FUNC free_func)
{
    VALUE result;
    result = Data_Wrap_Struct(klass, NULL, free_func, ptr);
    rb_iv_set(result, "@connection", conn);
    return result;
}

int is_symbol_or_proc(VALUE handle)
{
    return ((strcmp(rb_obj_classname(handle), "Symbol") == 0) ||
            (strcmp(rb_obj_classname(handle), "Proc") == 0));
}

/* this is an odd function, because it has massive side-effects.
 * The intended usage of this function is after a list has been collected
 * from a libvirt list function, and now we want to make an array out of it.
 * However, it is possible that the act of creating an array causes an
 * exception, which would lead to a memory leak of the values we got from
 * libvirt.  Therefore, this function not only wraps all of the relevant
 * calls with rb_protect, it also frees every individual entry in list after
 * it is done with it.  Freeing list itself is left to the callers.
 */
VALUE gen_list(int num, char **list)
{
    VALUE result;
    int exception = 0;
    int i, j;
    struct rb_ary_push_arg arg;

    i = 0;

    result = rb_protect(rb_ary_new2_wrap, (VALUE)&num, &exception);
    if (exception) {
        goto exception;
    }
    for (i = 0; i < num; i++) {
        arg.arr = result;
        arg.value = rb_protect(rb_str_new2_wrap, (VALUE)&((*list)[i]),
                               &exception);
        if (exception) {
            goto exception;
        }
        rb_protect(rb_ary_push_wrap, (VALUE)&arg, &exception);
        if (exception) {
            goto exception;
        }
        xfree(list[i]);
    }

    return result;

exception:
    for (j = i; j < num; j++) {
        xfree(list[j]);
    }
    rb_jump_tag(exception);

    /* not needed, but here to shut the compiler up */
    return Qnil;
}

VALUE get_parameters(int argc, VALUE *argv, VALUE d, virConnectPtr conn,
                     int (*nparams_cb)(VALUE d, unsigned int flags),
                     char *(*get_cb)(VALUE d, unsigned int flags,
                                     virTypedParameterPtr params, int *nparams))
{
    int nparams;
    virTypedParameterPtr params;
    VALUE result;
    int i;
    char *errname;
    unsigned int flags;
    VALUE flags_val;
    VALUE val;

    rb_scan_args(argc, argv, "01", &flags_val);

    if (NIL_P(flags_val)) {
        flags = 0;
    }
    else {
        flags = NUM2UINT(flags_val);
    }

    nparams = nparams_cb(d, flags);

    result = rb_hash_new();

    if (nparams == 0) {
        return result;
    }

    params = alloca(sizeof(virTypedParameter) * nparams);

    errname = get_cb(d, flags, params, &nparams);
    _E(errname != NULL, create_error(e_RetrieveError, errname, conn));

    for (i = 0; i < nparams; i++) {
        switch(params[i].type) {
        case VIR_TYPED_PARAM_INT:
            val = INT2NUM(params[i].value.i);
            break;
        case VIR_TYPED_PARAM_UINT:
            val = UINT2NUM(params[i].value.ui);
            break;
        case VIR_TYPED_PARAM_LLONG:
            val = LL2NUM(params[i].value.l);
            break;
        case VIR_TYPED_PARAM_ULLONG:
            val = ULL2NUM(params[i].value.ul);
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            val = rb_float_new(params[i].value.d);
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            val = (params[i].value.b == 0) ? Qfalse : Qtrue;
            break;
        case VIR_TYPED_PARAM_STRING:
            val = rb_str_new2(params[i].value.s);
            break;
        default:
            rb_raise(rb_eArgError, "Invalid parameter type");
        }

        rb_hash_aset(result, rb_str_new2(params[i].field), val);
    }

    return result;
}

VALUE set_parameters(VALUE d, VALUE in, virConnectPtr conn,
                     int (*nparams_cb)(VALUE d, unsigned int flags),
                     char *(*get_cb)(VALUE d, unsigned int flags,
                                     virTypedParameterPtr params, int *nparams),
                     char *(*set_cb)(VALUE d, unsigned int flags,
                                     virTypedParameterPtr params, int nparams))
{
    int nparams;
    virTypedParameterPtr params;
    int i;
    char *errname;
    VALUE input;
    VALUE flags_val;
    unsigned int flags;
    VALUE val;

    if (TYPE(in) == T_HASH) {
        input = in;
        flags_val = INT2NUM(0);
    }
    else if (TYPE(in) == T_ARRAY) {
        if (RARRAY_LEN(in) != 2) {
            rb_raise(rb_eArgError, "wrong number of arguments (%ld for 1 or 2)",
                     RARRAY_LEN(in));
        }
        input = rb_ary_entry(in, 0);
        flags_val = rb_ary_entry(in, 1);
    }
    else {
        rb_raise(rb_eTypeError, "wrong argument type (expected Hash or Array)");
    }

    Check_Type(input, T_HASH);

    /* we do this up-front for proper argument error checking */
    flags = NUM2UINT(flags_val);

    if (RHASH_SIZE(input) == 0) {
        return Qnil;
    }

    /* Complicated.  The below all stems from the fact that we have no way to
     * discover what type each parameter should be based on the input.
     * Instead, we ask libvirt to give us the current parameters and types,
     * and then we replace the values with the new values.  That way we find
     * out what the old types were, and if the new types don't match, libvirt
     * will throw an error.
     */

    nparams = nparams_cb(d, flags);

    params = alloca(sizeof(virTypedParameter) * nparams);

    errname = get_cb(d, flags, params, &nparams);
    _E(errname != NULL, create_error(e_RetrieveError, errname, conn));

    for (i = 0; i < nparams; i++) {
        val = rb_hash_aref(input, rb_str_new2(params[i].field));
        if (NIL_P(val)) {
            continue;
        }

        switch(params[i].type) {
        case VIR_TYPED_PARAM_INT:
            params[i].value.i = NUM2INT(val);
            break;
        case VIR_TYPED_PARAM_UINT:
            params[i].value.ui = NUM2UINT(val);
            break;
        case VIR_TYPED_PARAM_LLONG:
            params[i].value.l = NUM2LL(val);
            break;
        case VIR_TYPED_PARAM_ULLONG:
            params[i].value.ul = NUM2ULL(val);
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            params[i].value.d = NUM2DBL(val);
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            params[i].value.b = (val == Qtrue) ? 1 : 0;
            break;
        case VIR_TYPED_PARAM_STRING:
            params[i].value.s = StringValueCStr(val);
            break;
        default:
            rb_raise(rb_eArgError, "Invalid parameter type");
        }
    }

    errname = set_cb(d, flags, params, nparams);
    if (errname != NULL) {
        rb_exc_raise(create_error(e_RetrieveError, errname, conn));
    }

    return Qnil;
}

VALUE integer_default_if_nil(VALUE in, int def)
{
    if (NIL_P(in)) {
        return INT2NUM(def);
    }

    return in;
}
