/*
 * common.c: Common utilities for the ruby libvirt bindings
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

static VALUE rb_exc_new2_wrap(VALUE arg) {
    struct rb_exc_new2_arg *e = (struct rb_exc_new2_arg *)arg;

    return rb_exc_new2(e->error, e->msg);
}

VALUE rb_ary_new2_wrap(VALUE arg) {
    return rb_ary_new2(*((int *)arg));
}

VALUE rb_ary_push_wrap(VALUE arg) {
    struct rb_ary_push_arg *e = (struct rb_ary_push_arg *)arg;

    return rb_ary_push(e->arr, e->value);
}

VALUE rb_str_new2_wrap(VALUE arg) {
    char **str = (char **)arg;

    return rb_str_new2(*str);
}

VALUE rb_ary_entry_wrap(VALUE arg) {
    struct rb_ary_entry_arg *e = (struct rb_ary_entry_arg *)arg;

    return rb_ary_entry(e->arr, e->elem);
}

VALUE rb_str_new_wrap(VALUE arg) {
    struct rb_str_new_arg *e = (struct rb_str_new_arg *)arg;

    return rb_str_new(e->val, e->size);
}

VALUE rb_ary_new_wrap(VALUE arg) {
    return rb_ary_new();
}

VALUE rb_iv_set_wrap(VALUE arg) {
    struct rb_iv_set_arg *e = (struct rb_iv_set_arg *)arg;

    return rb_iv_set(e->klass, e->member, e->value);
}

VALUE rb_class_new_instance_wrap(VALUE arg) {
    struct rb_class_new_instance_arg *e = (struct rb_class_new_instance_arg *)arg;

    return rb_class_new_instance(e->argc, e->argv, e->klass);
}

VALUE rb_string_value_cstr_wrap(VALUE arg) {
    return (VALUE)rb_string_value_cstr((VALUE *)arg);
}

/* Error handling */
VALUE create_error(VALUE error, const char* method, virConnectPtr conn) {
    VALUE ruby_errinfo;
    virErrorPtr err;
    char *msg;
    int rc;
    struct rb_exc_new2_arg arg;
    int exception = 0;

    if (conn == NULL)
        err = virGetLastError();
    else
        err = virConnGetLastError(conn);

    if (err != NULL && err->message != NULL)
        rc = asprintf(&msg, "Call to %s failed: %s", method, err->message);
    else
        rc = asprintf(&msg, "Call to %s failed", method);

    if (rc < 0) {
        /* there's not a whole lot we can do here; try to raise an
         * out-of-memory message */
        rb_memerror();
    }

    arg.error = error;
    arg.msg = msg;
    ruby_errinfo = rb_protect(rb_exc_new2_wrap, (VALUE)&arg, &exception);
    free(msg);
    if (exception)
        rb_jump_tag(exception);

    rb_iv_set(ruby_errinfo, "@libvirt_function_name", rb_str_new2(method));

    if (err != NULL) {
        rb_iv_set(ruby_errinfo, "@libvirt_code", INT2FIX(err->code));
        if (err->message != NULL)
            rb_iv_set(ruby_errinfo, "@libvirt_message",
                      rb_str_new2(err->message));
    }

    return ruby_errinfo;
};

char *get_string_or_nil(VALUE arg)
{
    if (TYPE(arg) == T_NIL)
        return NULL;
    else if (TYPE(arg) == T_STRING)
        return StringValueCStr(arg);
    else
        rb_raise(rb_eTypeError, "wrong argument type (expected String or nil)");    return NULL;
}

VALUE generic_new(VALUE klass, void *ptr, VALUE conn,
                  RUBY_DATA_FUNC free_func) {
    VALUE result;
    result = Data_Wrap_Struct(klass, NULL, free_func, ptr);
    rb_iv_set(result, "@connection", conn);
    return result;
}

int is_symbol_or_proc(VALUE handle) {
    return ((strcmp(rb_obj_classname(handle), "Symbol") == 0) ||
            (strcmp(rb_obj_classname(handle), "Proc") == 0));
}

/* this is an odd function, because it has massive side-effects.  The first
 * tip that something is weird here should be the triple-starred list.
 * The intended usage of this function is after a list has been collected
 * from a libvirt list function, and now we want to make an array out of it.
 * However, it is possible that the act of creating an array causes an
 * exception, which would lead to a memory leak of the values we got from
 * libvirt.  Therefore, this function not only wraps all of the relevant
 * calls with rb_protect, it also frees every individual entry in list
 * along with list itself.
 */
VALUE gen_list(int num, char ***list) {
    VALUE result;
    int exception = 0;
    int i, j;
    struct rb_ary_push_arg arg;

    result = rb_protect(rb_ary_new2_wrap, (VALUE)&num, &exception);
    if (exception) {
        for (i = 0; i < num; i++)
            free((*list)[i]);
        xfree(*list);
        rb_jump_tag(exception);
    }
    for (i = 0; i < num; i++) {
        arg.arr = result;
        arg.value = rb_protect(rb_str_new2_wrap, (VALUE)&((*list)[i]),
                               &exception);
        if (exception) {
            for (j = i; j < num; j++)
                xfree((*list)[j]);
            xfree(*list);
            rb_jump_tag(exception);
        }
        rb_protect(rb_ary_push_wrap, (VALUE)&arg, &exception);
        if (exception) {
            for (j = i; j < num; j++)
                xfree((*list)[j]);
            xfree(*list);
            rb_jump_tag(exception);
        }
        xfree((*list)[i]);
    }
    xfree(*list);

    return result;
}
