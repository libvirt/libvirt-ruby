/*
 * interface.c: virInterface methods
 *
 * Copyright (C) 2010 Red Hat Inc.
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
#include "common.h"
#include "connect.h"
#include "extconf.h"

#if HAVE_TYPE_VIRINTERFACEPTR
static VALUE c_interface;

static void interface_free(void *i) {
    generic_free(Interface, i);
}

static virInterfacePtr interface_get(VALUE s) {
    generic_get(Interface, s);
}

VALUE interface_new(virInterfacePtr i, VALUE conn) {
    return generic_new(c_interface, i, conn, interface_free);
}

/*
 * call-seq:
 *   interface.undefine -> nil
 *
 * Call +virInterfaceUndefine+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceUndefine]
 * to undefine this interface.
 */
static VALUE libvirt_interface_undefine(VALUE s) {
    gen_call_void(virInterfaceUndefine, conn(s), interface_get(s));
}

/*
 * call-seq:
 *   interface.create(flags=0) -> nil
 *
 * Call +virInterfaceCreate+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceCreate]
 * to start this interface.
 */
static VALUE libvirt_interface_create(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);
    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virInterfaceCreate, conn(s), interface_get(s),
                  NUM2UINT(flags));
}

/*
 * call-seq:
 *   interface.destroy(flags=0) -> nil
 *
 * Call +virInterfaceDestroy+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceDestroy]
 * to shutdown this interface.
 */
static VALUE libvirt_interface_destroy(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);
    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virInterfaceDestroy, conn(s), interface_get(s),
                  NUM2UINT(flags));
}

#if HAVE_VIRINTERFACEISACTIVE
/*
 * call-seq:
 *   interface.active? -> [true|false]
 *
 * Call +virInterfaceIsActive+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceIsActive]
 * to determine if this interface is currently active.
 */
static VALUE libvirt_interface_active_p(VALUE p) {
    gen_call_truefalse(virInterfaceIsActive, conn(p), interface_get(p));
}
#endif

/*
 * call-seq:
 *   interface.name -> string
 *
 * Call +virInterfaceGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceGetName]
 * to retrieve the name of this interface.
 */
static VALUE libvirt_interface_name(VALUE s) {
    gen_call_string(virInterfaceGetName, conn(s), 0, interface_get(s));
}

/*
 * call-seq:
 *   interface.mac -> string
 *
 * Call +virInterfaceGetMACString+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceGetMACString]
 * to retrieve the MAC address of this interface.
 */
static VALUE libvirt_interface_mac(VALUE s) {
    gen_call_string(virInterfaceGetMACString, conn(s), 0, interface_get(s));
}

/*
 * call-seq:
 *   interface.xml_desc -> string
 *
 * Call +virInterfaceGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceGetXMLDesc]
 * to retrieve the XML of this interface.
 */
static VALUE libvirt_interface_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_string(virInterfaceGetXMLDesc, conn(s), 1, interface_get(s),
                    NUM2UINT(flags));
}

/*
 * call-seq:
 *   interface.free -> nil
 *
 * Call +virInterfaceFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virInterfaceFree]
 * to free this interface.  The object will no longer be valid after this call.
 */
static VALUE libvirt_interface_free(VALUE s) {
    gen_call_free(Interface, s);
}
#endif

/*
 * Class Libvirt::Interface
 */
void init_interface()
{
#if HAVE_TYPE_VIRINTERFACEPTR
    c_interface = rb_define_class_under(m_libvirt, "Interface", rb_cObject);
#if HAVE_CONST_VIR_INTERFACE_XML_INACTIVE
    rb_define_const(c_interface, "XML_INACTIVE",
                    INT2NUM(VIR_INTERFACE_XML_INACTIVE));
#endif
    rb_define_attr(c_interface, "connection", 1, 0);

    /* Interface object methods */
    rb_define_method(c_interface, "name", libvirt_interface_name, 0);
    rb_define_method(c_interface, "mac", libvirt_interface_mac, 0);
    rb_define_method(c_interface, "xml_desc", libvirt_interface_xml_desc, -1);
    rb_define_method(c_interface, "undefine", libvirt_interface_undefine, 0);
    rb_define_method(c_interface, "create", libvirt_interface_create, -1);
    rb_define_method(c_interface, "destroy", libvirt_interface_destroy, -1);
    rb_define_method(c_interface, "free", libvirt_interface_free, 0);
#if HAVE_VIRINTERFACEISACTIVE
    rb_define_method(c_interface, "active?", libvirt_interface_active_p, 0);
#endif
#endif
}
