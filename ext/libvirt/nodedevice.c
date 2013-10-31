/*
 * nodedevice.c: virNodeDevice methods
 *
 * Copyright (C) 2010 Red Hat Inc.
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

#include <ruby.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include "common.h"
#include "connect.h"
#include "extconf.h"

#if HAVE_TYPE_VIRNODEDEVICEPTR
static VALUE c_nodedevice;

static void nodedevice_free(void *s)
{
    ruby_libvirt_free_struct(NodeDevice, s);
}

static virNodeDevicePtr nodedevice_get(VALUE n)
{
    ruby_libvirt_get_struct(NodeDevice, n);
}

VALUE ruby_libvirt_nodedevice_new(virNodeDevicePtr n, VALUE conn)
{
    return ruby_libvirt_new_class(c_nodedevice, n, conn, nodedevice_free);
}

/*
 * call-seq:
 *   nodedevice.get_name -> String
 *
 * Call virNodeDeviceGetName[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceGetName]
 * to retrieve the name of the node device.
 */
static VALUE libvirt_nodedevice_get_name(VALUE c)
{
    ruby_libvirt_generate_call_string(virNodeDeviceGetName,
                                      ruby_libvirt_connect_get(c), 0,
                                      nodedevice_get(c));
}

/*
 * call-seq:
 *   nodedevice.get_parent -> String
 *
 * Call virNodeDeviceGetParent[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceGetParent]
 * to retrieve the parent of the node device.
 */
static VALUE libvirt_nodedevice_get_parent(VALUE c)
{
    /* unfortunately we can't use ruby_libvirt_generate_call_string() here
     * because virNodeDeviceGetParent() returns NULL as a valid value (when this
     * device has no parent).  Hand-code it instead
     */

    const char *str;

    str = virNodeDeviceGetParent(nodedevice_get(c));
    if (str == NULL) {
        return Qnil;
    }
    else {
        return rb_str_new2(str);
    }
}

/*
 * call-seq:
 *   nodedevice.num_of_caps -> Fixnum
 *
 * Call virNodeDeviceNumOfCaps[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceNumOfCaps]
 * to retrieve the number of capabilities of the node device.
 */
static VALUE libvirt_nodedevice_num_of_caps(VALUE c)
{
    ruby_libvirt_generate_call_int(virNodeDeviceNumOfCaps,
                                   ruby_libvirt_connect_get(c),
                                   nodedevice_get(c));
}

/*
 * call-seq:
 *   nodedevice.list_caps(num) -> list
 *
 * Call virNodeDeviceListCaps[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceListCaps]
 * to retrieve a list of capabilities of the node device.
 */
static VALUE libvirt_nodedevice_list_caps(VALUE c, VALUE num_val)
{
    int r, num;
    char **names;

    num = NUM2INT(num_val);

    if (num == 0) {
        /* if num is 0, don't call virNodeDeviceListCaps function */
        return rb_ary_new2(num);
    }

    names = alloca(sizeof(char *) * num);
    r = virNodeDeviceListCaps(nodedevice_get(c), names, num);
    ruby_libvirt_raise_error_if(r < 0, "virNodeDeviceListCaps",
                                ruby_libvirt_connect_get(c));

    return ruby_libvirt_generate_list(r, names);
}

/*
 * call-seq:
 *   nodedevice.get_xml_desc(flags=0) -> String
 *
 * Call virNodeDeviceGetXMLDesc[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceGetXMLDesc]
 * to retrieve the XML for the node device.
 */
static VALUE libvirt_nodedevice_get_xml_desc(int argc, VALUE *argv, VALUE n)
{
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    ruby_libvirt_generate_call_string(virNodeDeviceGetXMLDesc,
                                      ruby_libvirt_connect_get(n),
                                      1, nodedevice_get(n),
                                      ruby_libvirt_value_to_uint(flags));
}

/*
 * call-seq:
 *   nodedevice.dettach -> nil
 *
 * Call virNodeDeviceDettach[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceDettach]
 * to detach the node device from the node.
 */
static VALUE libvirt_nodedevice_dettach(VALUE n)
{
    ruby_libvirt_generate_call_nil(virNodeDeviceDettach,
                                   ruby_libvirt_connect_get(n),
                                   nodedevice_get(n));
}

#if HAVE_VIRNODEDEVICEDETACHFLAGS
/*
 * call-seq:
 *   nodedevice.detach_flags(driver=nil, flags=0) -> nil
 *
 * Call virNodeDeviceDetachFlags[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceDetachFlags]
 * to detach the node device from the node.
 */
static VALUE libvirt_nodedevice_detach_flags(int argc, VALUE *argv, VALUE n)
{
    VALUE driver, flags;

    rb_scan_args(argc, argv, "02", &driver, &flags);

    ruby_libvirt_generate_call_nil(virNodeDeviceDetachFlags,
                                   ruby_libvirt_connect_get(n),
                                   nodedevice_get(n),
                                   ruby_libvirt_get_cstring_or_null(driver),
                                   ruby_libvirt_value_to_uint(flags));
}
#endif

/*
 * call-seq:
 *   nodedevice.reattach -> nil
 *
 * Call virNodeDeviceReAttach[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceReAttach]
 * to reattach the node device to the node.
 */
static VALUE libvirt_nodedevice_reattach(VALUE n)
{
    ruby_libvirt_generate_call_nil(virNodeDeviceReAttach,
                                   ruby_libvirt_connect_get(n),
                                   nodedevice_get(n));
}

/*
 * call-seq:
 *   nodedevice.reset -> nil
 *
 * Call virNodeDeviceReset[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceReset]
 * to reset the node device.
 */
static VALUE libvirt_nodedevice_reset(VALUE n)
{
    ruby_libvirt_generate_call_nil(virNodeDeviceReset,
                                   ruby_libvirt_connect_get(n),
                                   nodedevice_get(n));
}

#if HAVE_VIRNODEDEVICEDESTROY
/*
 * call-seq:
 *   nodedevice.destroy -> nil
 *
 * Call virNodeDeviceDestroy[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceDestroy]
 * to shutdown the node device.
 */
static VALUE libvirt_nodedevice_destroy(VALUE n)
{
    ruby_libvirt_generate_call_nil(virNodeDeviceDestroy,
                                   ruby_libvirt_connect_get(n),
                                   nodedevice_get(n));
}
#endif

/*
 * call-seq:
 *   nodedevice.free -> nil
 *
 * Call virNodeDeviceFree[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceFree]
 * to free the node device object.  After this call the node device object is
 * no longer valid.
 */
static VALUE libvirt_nodedevice_free(VALUE n)
{
    ruby_libvirt_generate_call_free(NodeDevice, n);
}

#if HAVE_VIRNODEDEVICELOOKUPSCSIHOSTBYWWN
/*
 * call-seq:
 *   nodedevice.lookup_scsi_host_by_wwn(wwnn, wwpn, flags=0) -> Libvirt::NodeDevice
 *
 * Call virNodeDeviceLookupSCSIHostByWWN[http://www.libvirt.org/html/libvirt-libvirt.html#virNodeDeviceLookupSCSIHostByWWN]
 * to look up a SCSI host by its WWNN and WWPN.
 */
static VALUE libvirt_nodedevice_lookup_scsi_host_by_wwn(int argc, VALUE *argv,
                                                        VALUE n)
{
    VALUE wwnn, wwpn, flags;
    virNodeDevicePtr nd;

    rb_scan_args(argc, argv, "21", &wwnn, &wwpn, &flags);

    nd = virNodeDeviceLookupSCSIHostByWWN(ruby_libvirt_connect_get(n),
                                          StringValueCStr(wwnn),
                                          StringValueCStr(wwpn),
                                          ruby_libvirt_value_to_uint(flags));
    if (nd == NULL) {
        return Qnil;
    }

    return ruby_libvirt_nodedevice_new(nd, ruby_libvirt_conn_attr(n));
}
#endif

#endif

/*
 * Class Libvirt::NodeDevice
 */
void ruby_libvirt_nodedevice_init(void)
{
#if HAVE_TYPE_VIRNODEDEVICEPTR
    c_nodedevice = rb_define_class_under(m_libvirt, "NodeDevice", rb_cObject);

    rb_define_attr(c_nodedevice, "connection", 1, 0);

    rb_define_method(c_nodedevice, "get_name", libvirt_nodedevice_get_name, 0);
    rb_define_method(c_nodedevice, "get_parent",
                     libvirt_nodedevice_get_parent, 0);
    rb_define_method(c_nodedevice, "num_of_caps",
                     libvirt_nodedevice_num_of_caps, 0);
    rb_define_method(c_nodedevice, "list_caps",
                     libvirt_nodedevice_list_caps, 1);
    rb_define_method(c_nodedevice, "get_xml_desc",
                     libvirt_nodedevice_get_xml_desc, -1);
    rb_define_method(c_nodedevice, "dettach", libvirt_nodedevice_dettach, 0);
#if HAVE_VIRNODEDEVICEDETACHFLAGS
    rb_define_method(c_nodedevice, "detach_flags",
                     libvirt_nodedevice_detach_flags, -1);
#endif
    rb_define_method(c_nodedevice, "reattach", libvirt_nodedevice_reattach, 0);
    rb_define_method(c_nodedevice, "reset", libvirt_nodedevice_reset, 0);
#if HAVE_VIRNODEDEVICEDESTROY
    rb_define_method(c_nodedevice, "destroy", libvirt_nodedevice_destroy, 0);
#endif
    rb_define_method(c_nodedevice, "free", libvirt_nodedevice_free, 0);
#if HAVE_VIRNODEDEVICELOOKUPSCSIHOSTBYWWN
    rb_define_method(c_nodedevice, "lookup_scsi_host_by_wwn",
                     libvirt_nodedevice_lookup_scsi_host_by_wwn, -1);
#endif
#endif
}
