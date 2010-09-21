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

#include <ruby.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

/* Error handling */
VALUE create_error(VALUE error, const char* method, virConnectPtr conn) {
    VALUE ruby_errinfo;
    virErrorPtr err;
    char *msg;
    int rc;

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

    /* FIXME: if rb_exc_new2 fails, we will leak msg */
    ruby_errinfo = rb_exc_new2(error, msg);

    free(msg);

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

