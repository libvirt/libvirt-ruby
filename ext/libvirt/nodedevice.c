/*
 * nodedevice.c: virNodeDevice methods
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

static VALUE c_nodedevice;

static void nodedevice_free(void *s) {
    generic_free(NodeDevice, s);
}

static virNodeDevicePtr nodedevice_get(VALUE s) {
    generic_get(NodeDevice, s);
}

static VALUE nodedevice_new(virNodeDevicePtr s, VALUE conn) {
    return generic_new(c_nodedevice, s, conn, nodedevice_free);
}

/*
 * call-seq:
 *   conn.num_of_nodedevices -> fixnum
 *
 * Call +virNodeNumOfDevices+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeNumOfDevices]
 */
static VALUE libvirt_conn_num_of_nodedevices(int argc, VALUE *argv, VALUE c) {
    int result;
    virConnectPtr conn = connect_get(c);
    VALUE cap, flags;

    rb_scan_args(argc, argv, "02", &cap, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    result = virNodeNumOfDevices(conn, get_string_or_nil(cap), NUM2UINT(flags));
    _E(result < 0, create_error(e_RetrieveError, "virNodeNumOfDevices", "",
                                conn));

    return INT2NUM(result);
}

/*
 * call-seq:
 *   conn.list_nodedevices -> list
 *
 * Call +virNodeListDevices+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeListDevices]
 */
static VALUE libvirt_conn_list_nodedevices(int argc, VALUE *argv, VALUE c) {
    int i, r, num;
    virConnectPtr conn = connect_get(c);
    VALUE cap, flags;
    char *capstr;
    VALUE result;
    char **names;

    rb_scan_args(argc, argv, "02", &cap, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    capstr = get_string_or_nil(cap);

    num = virNodeNumOfDevices(conn, capstr, 0);
    _E(num < 0, create_error(e_RetrieveError, "virNodeNumOfDevices", "", conn));
    if (num == 0) {
        /* if num is 0, don't call virNodeListDevices function */
        result = rb_ary_new2(num);
        return result;
    }
    names = ALLOC_N(char *, num);
    r = virNodeListDevices(conn, capstr, names, num, NUM2UINT(flags));
    if (r < 0) {
        free(names);
        _E(r < 0, create_error(e_RetrieveError, "virNodeListDevices", "", conn));
    }

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, rb_str_new2(names[i]));
        free(names[i]);
    }
    free(names);
    return result;
}

/*
 * call-seq:
 *   conn.lookup_nodedevice_by_name -> Libvirt::NodeDevice
 *
 * Call +virNodeDeviceLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceLookupByName]
 */
static VALUE libvirt_conn_lookup_nodedevice_by_name(VALUE c, VALUE name) {
    virNodeDevicePtr nodedev;
    virConnectPtr conn = connect_get(c);

    nodedev = virNodeDeviceLookupByName(conn, StringValueCStr(name));
    _E(nodedev == NULL, create_error(e_RetrieveError, "virNodeDeviceLookupByName", "", conn));

    return nodedevice_new(nodedev, c);

}

#if HAVE_VIRNODEDEVICECREATEXML
/*
 * call-seq:
 *   conn.create_nodedevice_xml -> Libvirt::NodeDevice
 *
 * Call +virNodeDeviceCreateXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceCreateXML]
 */
static VALUE libvirt_conn_create_nodedevice_xml(int argc, VALUE *argv, VALUE c) {
    virNodeDevicePtr nodedev;
    virConnectPtr conn = connect_get(c);
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    nodedev = virNodeDeviceCreateXML(conn, StringValueCStr(xml), NUM2UINT(flags));
    _E(nodedev == NULL, create_error(e_Error, "virNodeDeviceCreateXML", "", conn));

    return nodedevice_new(nodedev, c);
}
#endif

/*
 * call-seq:
 *   nodedevice.name -> string
 *
 * Call +virNodeDeviceGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceGetName]
 */
static VALUE libvirt_nodedevice_name(VALUE c) {
    gen_call_string(virNodeDeviceGetName, connect_get(c), 0, nodedevice_get(c));
}

/*
 * call-seq:
 *   nodedevice.parent -> string
 *
 * Call +virNodeDeviceGetParent+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceGetParent]
 */
static VALUE libvirt_nodedevice_parent(VALUE c) {
    /* unfortunately we can't use gen_call_string() here because
     * virNodeDeviceGetParent() returns NULL as a valid value (when this
     * device has no parent.  Hand-code it instead
     */

    const char *str;

    str = virNodeDeviceGetParent(nodedevice_get(c));
    if (str == NULL)
        return Qnil;
    else
        return rb_str_new2(str);
}

/*
 * call-seq:
 *   nodedevice.num_of_caps -> fixnum
 *
 * Call +virNodeDeviceNumOfCaps+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceNumOfCaps]
 */
static VALUE libvirt_nodedevice_num_of_caps(VALUE c) {
    int result;

    result = virNodeDeviceNumOfCaps(nodedevice_get(c));
    _E(result < 0, create_error(e_RetrieveError, "virNodeNumOfDevices", "", connect_get(c)));

    return INT2NUM(result);
}

/*
 * call-seq:
 *   nodedevice.list_caps -> list
 *
 * Call +virNodeDeviceListCaps+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceListCaps]
 */
static VALUE libvirt_nodedevice_list_caps(VALUE c) {
    int i, r, num;
    virConnectPtr conn = connect_get(c);
    virNodeDevicePtr nodedev = nodedevice_get(c);
    VALUE result;
    char **names;

    num = virNodeDeviceNumOfCaps(nodedev);
    _E(num < 0, create_error(e_RetrieveError, "virNodeDeviceNumOfCaps", "", conn));
    if (num == 0) {
        /* if num is 0, don't call virNodeDeviceListCaps function */
        result = rb_ary_new2(num);
        return result;
    }
    names = ALLOC_N(char *, num);
    r = virNodeDeviceListCaps(nodedev, names, num);
    if (r < 0) {
        free(names);
        _E(r < 0, create_error(e_RetrieveError, "virNodeDeviceListCaps", "", conn));
    }

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, rb_str_new2(names[i]));
        free(names[i]);
    }
    free(names);
    return result;
}

/*
 * call-seq:
 *   nodedevice.xml_desc -> string
 *
 * Call +virNodeDeviceGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceGetXMLDesc]
 */
static VALUE libvirt_nodedevice_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virNodeDeviceGetXMLDesc, conn(s), 1,
                    nodedevice_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   nodedevice.detach -> nil
 *
 * Call +virNodeDeviceDettach+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceDettach]
 */
static VALUE libvirt_nodedevice_detach(VALUE s) {
    gen_call_void(virNodeDeviceDettach, conn(s), nodedevice_get(s));
}

/*
 * call-seq:
 *   nodedevice.reattach -> nil
 *
 * Call +virNodeDeviceReAttach+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceReAttach]
 */
static VALUE libvirt_nodedevice_reattach(VALUE s) {
    gen_call_void(virNodeDeviceReAttach, conn(s), nodedevice_get(s));
}

/*
 * call-seq:
 *   nodedevice.reset -> nil
 *
 * Call +virNodeDeviceReset+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceReset]
 */
static VALUE libvirt_nodedevice_reset(VALUE s) {
    gen_call_void(virNodeDeviceReset, conn(s), nodedevice_get(s));
}

#if HAVE_VIRNODEDEVICEDESTROY
/*
 * call-seq:
 *   nodedevice.destroy -> nil
 *
 * Call +virNodeDeviceDestroy+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceDestroy]
 */
static VALUE libvirt_nodedevice_destroy(VALUE s) {
    gen_call_void(virNodeDeviceDestroy, conn(s), nodedevice_get(s));
}
#endif

/*
 * call-seq:
 *   nodedevice.free -> nil
 *
 * Call +virNodeDeviceFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceFree]
 */
static VALUE libvirt_nodedevice_free(VALUE s) {
    gen_call_free(NodeDevice, s);
}

/*
 * Class Libvirt::NodeDevice
 */
void init_nodedevice()
{
    c_nodedevice = rb_define_class_under(m_libvirt, "NodeDevice", rb_cObject);
    rb_define_method(c_connect, "num_of_nodedevices",
                     libvirt_conn_num_of_nodedevices, -1);
    rb_define_method(c_connect, "list_nodedevices",
                     libvirt_conn_list_nodedevices, -1);
    rb_define_method(c_connect, "lookup_nodedevice_by_name",
                     libvirt_conn_lookup_nodedevice_by_name, 1);
#if HAVE_VIRNODEDEVICECREATEXML
    rb_define_method(c_connect, "create_nodedevice_xml",
                     libvirt_conn_create_nodedevice_xml, -1);
#endif

    rb_define_method(c_nodedevice, "name", libvirt_nodedevice_name, 0);
    rb_define_method(c_nodedevice, "parent", libvirt_nodedevice_parent, 0);
    rb_define_method(c_nodedevice, "num_of_caps",
                     libvirt_nodedevice_num_of_caps, 0);
    rb_define_method(c_nodedevice, "list_caps",
                     libvirt_nodedevice_list_caps, 0);
    rb_define_method(c_nodedevice, "xml_desc", libvirt_nodedevice_xml_desc, -1);
    rb_define_method(c_nodedevice, "detach", libvirt_nodedevice_detach, 0);
    rb_define_method(c_nodedevice, "reattach", libvirt_nodedevice_reattach, 0);
    rb_define_method(c_nodedevice, "reset", libvirt_nodedevice_reset, 0);
#if HAVE_VIRNODEDEVICEDESTROY
    rb_define_method(c_nodedevice, "destroy", libvirt_nodedevice_destroy, 0);
#endif
    rb_define_method(c_nodedevice, "free", libvirt_nodedevice_free, 0);
}
