/*
 * nwfilter.c: virNWFilter methods
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

#if HAVE_TYPE_VIRNWFILTERPTR
static VALUE c_nwfilter;

static void nwfilter_free(void *n)
{
    generic_free(NWFilter, n);
}

static virNWFilterPtr nwfilter_get(VALUE n)
{
    generic_get(NWFilter, n);
}

VALUE nwfilter_new(virNWFilterPtr n, VALUE conn)
{
    return generic_new(c_nwfilter, n, conn, nwfilter_free);
}

/*
 * call-seq:
 *   nwfilter.undefine -> nil
 *
 * Call virNWFilterUndefine[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterUndefine]
 * to undefine the network filter.
 */
static VALUE libvirt_nwfilter_undefine(VALUE n)
{
    gen_call_void(virNWFilterUndefine, connect_get(n), nwfilter_get(n));
}

/*
 * call-seq:
 *   nwfilter.name -> string
 *
 * Call virNWFilterGetName[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterGetName]
 * to retrieve the network filter name.
 */
static VALUE libvirt_nwfilter_name(VALUE n)
{
    gen_call_string(virNWFilterGetName, connect_get(n), 0, nwfilter_get(n));
}

/*
 * call-seq:
 *   nwfilter.uuid -> string
 *
 * Call virNWFilterGetUUIDString[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterGetUUIDString]
 * to retrieve the network filter UUID.
 */
static VALUE libvirt_nwfilter_uuid(VALUE n)
{
    int r;
    char uuid[VIR_UUID_STRING_BUFLEN];

    r = virNWFilterGetUUIDString(nwfilter_get(n), uuid);
    _E(r < 0, create_error(e_RetrieveError, "virNWFilterGetUUIDString",
                           connect_get(n)));

    return rb_str_new2((char *)uuid);
}

/*
 * call-seq:
 *   nwfilter.xml_desc(flags=0) -> string
 *
 * Call virNWFilterGetXMLDesc[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterGetXMLDesc]
 * to retrieve the XML for this network filter.
 */
static VALUE libvirt_nwfilter_xml_desc(int argc, VALUE *argv, VALUE n)
{
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    flags = integer_default_if_nil(flags, 0);

    gen_call_string(virNWFilterGetXMLDesc, connect_get(n), 1, nwfilter_get(n),
                    NUM2UINT(flags));
}

/*
 * call-seq:
 *   nwfilter.free -> nil
 *
 * Call virNWFilterFree[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterFree]
 * to free this network filter.  After this call the network filter object is
 * no longer valid.
 */
static VALUE libvirt_nwfilter_free(VALUE n)
{
    gen_call_free(NWFilter, n);
}

#endif

/*
 * Class Libvirt::NWFilter
 */
void init_nwfilter()
{
#if HAVE_TYPE_VIRNWFILTERPTR
    c_nwfilter = rb_define_class_under(m_libvirt, "NWFilter", rb_cObject);
    rb_define_attr(c_nwfilter, "connection", 1, 0);

    /* NWFilter object methods */
    rb_define_method(c_nwfilter, "undefine", libvirt_nwfilter_undefine, 0);
    rb_define_method(c_nwfilter, "name", libvirt_nwfilter_name, 0);
    rb_define_method(c_nwfilter, "uuid", libvirt_nwfilter_uuid, 0);
    rb_define_method(c_nwfilter, "xml_desc", libvirt_nwfilter_xml_desc, -1);
    rb_define_method(c_nwfilter, "free", libvirt_nwfilter_free, 0);
#endif
}
