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

static void connect_free(void *p) {
    int r;
    
    r = virConnectClose((virConnectPtr) p);
    if (r == -1)
        rb_raise(rb_eException, "Connection close failed");
}

static VALUE connect_new(virConnectPtr p) {
    return Data_Wrap_Struct(c_connect, NULL, connect_free, p);
}

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

void Init_rblibvirt() {
    m_libvirt = rb_define_module("Libvirt");
    c_connect = rb_define_class_under(m_libvirt, "Connect", rb_cObject);

	rb_define_module_function(m_libvirt, "open", m_open, 1);
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
