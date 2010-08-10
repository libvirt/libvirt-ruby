/*
 * nwfilter.c: virNWFilter methods
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

#if HAVE_TYPE_VIRNWFILTERPTR
static VALUE c_nwfilter;

static void nwfilter_free(void *nw) {
    generic_free(NWFilter, nw);
}

static virNWFilterPtr nwfilter_get(VALUE nw) {
    generic_get(NWFilter, nw);
}

static VALUE nwfilter_new(virNWFilterPtr nw, VALUE conn) {
    return generic_new(c_nwfilter, nw, conn, nwfilter_free);
}

/*
 * call-seq:
 *   conn.num_of_nwfilters -> fixnum
 *
 * Call +virConnectNumOfNWFilters+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfNWFilters]
 * to retrieve the number of network filters on this connection.
 */
static VALUE libvirt_conn_num_of_nwfilters(VALUE s) {
    gen_conn_num_of(s, NWFilters);
}

/*
 * call-seq:
 *   conn.list_nwfilters -> list
 *
 * Call +virConnectListNWFilters+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListNWFilters]
 * to retrieve a list of network filter names on this connection.
 */
static VALUE libvirt_conn_list_nwfilters(VALUE s) {
    gen_conn_list_names(s, NWFilters);
}

/*
 * call-seq:
 *   conn.lookup_nwfilter_by_name(name) -> Libvirt::NWFilter
 *
 * Call +virNWFilterLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterLookupByName]
 * to retrieve a network filter object by name.
 */
static VALUE libvirt_conn_lookup_nwfilter_by_name(VALUE c, VALUE name) {
    virNWFilterPtr nwfilter;
    virConnectPtr conn = connect_get(c);

    nwfilter = virNWFilterLookupByName(conn, StringValueCStr(name));
    _E(nwfilter == NULL, create_error(e_RetrieveError,
                                      "virNWFilterLookupByName", "", conn));

    return nwfilter_new(nwfilter, c);
}

/*
 * call-seq:
 *   conn.lookup_nwfilter_by_uuid(uuid) -> Libvirt::NWFilter
 *
 * Call +virNWFilterLookupByUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterLookupByUUIDString]
 * to retrieve a network filter object by UUID.
 */
static VALUE libvirt_conn_lookup_nwfilter_by_uuid(VALUE c, VALUE uuid) {
    virNWFilterPtr nwfilter;
    virConnectPtr conn = connect_get(c);

    nwfilter = virNWFilterLookupByUUIDString(conn, StringValueCStr(uuid));
    _E(nwfilter == NULL, create_error(e_RetrieveError,
                                      "virNWFilterLookupByUUIDString", "",
                                      conn));

    return nwfilter_new(nwfilter, c);
}

/*
 * call-seq:
 *   conn.define_nwfilter_xml(xml) -> Libvirt::NWFilter
 *
 * Call +virNWFilterDefineXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterDefineXML]
 * to define a new network filter from xml.
 */
static VALUE libvirt_conn_define_nwfilter_xml(VALUE c, VALUE xml) {
    virNWFilterPtr nwfilter;
    virConnectPtr conn = connect_get(c);

    nwfilter = virNWFilterDefineXML(conn, StringValueCStr(xml));
    _E(nwfilter == NULL, create_error(e_DefinitionError,
                                      "virNWFilterDefineXML", "", conn));

    return nwfilter_new(nwfilter, c);
}

/*
 * call-seq:
 *   nwfilter.undefine -> nil
 *
 * Call +virNWFilterUndefine+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterUndefine]
 * to undefine the network filter.
 */
static VALUE libvirt_nwfilter_undefine(VALUE s) {
    gen_call_void(virNWFilterUndefine, conn(s), nwfilter_get(s));
}

/*
 * call-seq:
 *   nwfilter.name -> string
 *
 * Call +virNWFilterGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterGetName]
 * to retrieve the network filter name.
 */
static VALUE libvirt_nwfilter_name(VALUE s) {
    gen_call_string(virNWFilterGetName, conn(s), 0, nwfilter_get(s));
}

/*
 * call-seq:
 *   nwfilter.uuid -> string
 *
 * Call +virNWFilterGetUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterGetUUIDString]
 * to retrieve the network filter UUID.
 */
static VALUE libvirt_nwfilter_uuid(VALUE s) {
    virNWFilterPtr nwfilter = nwfilter_get(s);
    int r;
    char uuid[VIR_UUID_STRING_BUFLEN];

    r = virNWFilterGetUUIDString(nwfilter, uuid);
    _E(r < 0, create_error(e_RetrieveError, "virNWFilterGetUUIDString", "",
                           conn(s)));

    return rb_str_new2((char *)uuid);
}

/*
 * call-seq:
 *   nwfilter.xml_desc(flags=0) -> string
 *
 * Call +virNWFilterGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterGetXMLDesc]
 * to retrieve the XML for this network filter.
 */
static VALUE libvirt_nwfilter_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virNWFilterGetXMLDesc, conn(s), 1, nwfilter_get(s),
                    NUM2UINT(flags));
}

/*
 * call-seq:
 *   nwfilter.free -> nil
 *
 * Call +virNWFilterFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virNWFilterFree]
 * to free this network filter.  After this call the network filter object is
 * no longer valid.
 */
static VALUE libvirt_nwfilter_free(VALUE s) {
    gen_call_free(NWFilter, s);
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

    /* NWFilter lookup/creation methods */
    rb_define_method(c_connect, "num_of_nwfilters",
                     libvirt_conn_num_of_nwfilters, 0);
    rb_define_method(c_connect, "list_nwfilters",
                     libvirt_conn_list_nwfilters, 0);
    rb_define_method(c_connect, "lookup_nwfilter_by_name",
                     libvirt_conn_lookup_nwfilter_by_name, 1);
    rb_define_method(c_connect, "lookup_nwfilter_by_uuid",
                     libvirt_conn_lookup_nwfilter_by_uuid, 1);
    rb_define_method(c_connect, "define_nwfilter_xml",
                     libvirt_conn_define_nwfilter_xml, 1);

    /* NWFilter object methods */
    rb_define_method(c_nwfilter, "undefine", libvirt_nwfilter_undefine, 0);
    rb_define_method(c_nwfilter, "name", libvirt_nwfilter_name, 0);
    rb_define_method(c_nwfilter, "uuid", libvirt_nwfilter_uuid, 0);
    rb_define_method(c_nwfilter, "xml_desc", libvirt_nwfilter_xml_desc, -1);
    rb_define_method(c_nwfilter, "free", libvirt_nwfilter_free, 0);
#endif
}
