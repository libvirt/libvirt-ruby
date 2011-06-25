/*
 * network.c: virNetwork methods
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
#include "common.h"
#include "connect.h"
#include "extconf.h"

#if HAVE_TYPE_VIRNETWORKPTR
static VALUE c_network;

static void network_free(void *d) {
    generic_free(Network, d);
}

static virNetworkPtr network_get(VALUE s) {
    generic_get(Network, s);
}

VALUE network_new(virNetworkPtr n, VALUE conn) {
    return generic_new(c_network, n, conn, network_free);
}

/*
 * call-seq:
 *   net.undefine -> nil
 *
 * Call +virNetworkUndefine+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkUndefine]
 * to undefine this network.
 */
static VALUE libvirt_netw_undefine(VALUE s) {
    gen_call_void(virNetworkUndefine, conn(s), network_get(s));
}

/*
 * call-seq:
 *   net.create -> nil
 *
 * Call +virNetworkCreate+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkCreate]
 * to start this network.
 */
static VALUE libvirt_netw_create(VALUE s) {
    gen_call_void(virNetworkCreate, conn(s), network_get(s));
}

/*
 * call-seq:
 *   net.destroy -> nil
 *
 * Call +virNetworkDestroy+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkDestroy]
 * to shutdown this network.
 */
static VALUE libvirt_netw_destroy(VALUE s) {
    gen_call_void(virNetworkDestroy, conn(s), network_get(s));
}

/*
 * call-seq:
 *   net.name -> string
 *
 * Call +virNetworkGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkGetName]
 * to retrieve the name of this network.
 */
static VALUE libvirt_netw_name(VALUE s) {
    gen_call_string(virNetworkGetName, conn(s), network_get(s));
}

/*
 * call-seq:
 *   net.uuid -> string
 *
 * Call +virNetworkGetUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkGetUUIDString]
 * to retrieve the UUID of this network.
 */
static VALUE libvirt_netw_uuid(VALUE s) {
    virNetworkPtr netw = network_get(s);
    char uuid[VIR_UUID_STRING_BUFLEN];
    int r;

    r = virNetworkGetUUIDString(netw, uuid);
    _E(r < 0, create_error(e_RetrieveError, "virNetworkGetUUIDString",
                           conn(s)));

    return rb_str_new2((char *) uuid);
}

/*
 * call-seq:
 *   net.xml_desc(flags=0) -> string
 *
 * Call +virNetworkGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkGetXMLDesc]
 * to retrieve the XML for this network.
 */
static VALUE libvirt_netw_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_string(virNetworkGetXMLDesc, conn(s), network_get(s),
                    NUM2UINT(flags));
}

/*
 * call-seq:
 *   net.bridge_name -> string
 *
 * Call +virNetworkGetBridgeName+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkGetBridgeName]
 * to retrieve the bridge name for this network.
 */
static VALUE libvirt_netw_bridge_name(VALUE s) {
    gen_call_string(virNetworkGetBridgeName, conn(s), network_get(s));
}

/*
 * call-seq:
 *   net.autostart? -> [true|false]
 *
 * Call +virNetworkGetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkGetAutostart]
 * to determine if this network will be autostarted when libvirtd starts.
 */
static VALUE libvirt_netw_autostart(VALUE s){
    virNetworkPtr netw = network_get(s);
    int r, autostart;

    r = virNetworkGetAutostart(netw, &autostart);
    _E(r < 0, create_error(e_RetrieveError, "virNetworkAutostart", conn(s)));

    return autostart ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   net.autostart = [true|false]
 *
 * Call +virNetworkSetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkSetAutostart]
 * to set this network to be autostarted when libvirtd starts.
 */
static VALUE libvirt_netw_autostart_set(VALUE s, VALUE autostart) {
    if (autostart != Qtrue && autostart != Qfalse)
        rb_raise(rb_eTypeError,
                 "wrong argument type (expected TrueClass or FalseClass)");

    gen_call_void(virNetworkSetAutostart, conn(s), network_get(s),
                  RTEST(autostart) ? 1 : 0);
}

/*
 * call-seq:
 *   net.free -> nil
 *
 * Call +virNetworkFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkFree]
 * to free this network.  The object will no longer be valid after this call.
 */
static VALUE libvirt_netw_free(VALUE s) {
    gen_call_free(Network, s);
}

#if HAVE_VIRNETWORKISACTIVE
/*
 * call-seq:
 *   net.active? -> [true|false]
 *
 * Call +virNetworkIsActive+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkIsActive]
 * to determine if this network is currently active.
 */
static VALUE libvirt_netw_active_p(VALUE s) {
    gen_call_truefalse(virNetworkIsActive, conn(s), network_get(s));
}
#endif

#if HAVE_VIRNETWORKISPERSISTENT
/*
 * call-seq:
 *   net.persistent? -> [true|false]
 *
 * Call +virNetworkIsPersistent+[http://www.libvirt.org/html/libvirt-libvirt.html#virNetworkIsPersistent]
 * to determine if this network is persistent.
 */
static VALUE libvirt_netw_persistent_p(VALUE s) {
    gen_call_truefalse(virNetworkIsPersistent, conn(s), network_get(s));
}
#endif

#endif

/*
 * Class Libvirt::Network
 */
void init_network()
{
#if HAVE_TYPE_VIRNETWORKPTR
    c_network = rb_define_class_under(m_libvirt, "Network", rb_cObject);
    rb_define_attr(c_network, "connection", 1, 0);

    rb_define_method(c_network, "undefine", libvirt_netw_undefine, 0);
    rb_define_method(c_network, "create", libvirt_netw_create, 0);
    rb_define_method(c_network, "destroy", libvirt_netw_destroy, 0);
    rb_define_method(c_network, "name", libvirt_netw_name, 0);
    rb_define_method(c_network, "uuid", libvirt_netw_uuid, 0);
    rb_define_method(c_network, "xml_desc", libvirt_netw_xml_desc, -1);
    rb_define_method(c_network, "bridge_name", libvirt_netw_bridge_name, 0);
    rb_define_method(c_network, "autostart", libvirt_netw_autostart, 0);
    rb_define_method(c_network, "autostart?", libvirt_netw_autostart, 0);
    rb_define_method(c_network, "autostart=", libvirt_netw_autostart_set, 1);
    rb_define_method(c_network, "free", libvirt_netw_free, 0);
#if HAVE_VIRNETWORKISACTIVE
    rb_define_method(c_network, "active?", libvirt_netw_active_p, 0);
#endif
#if HAVE_VIRNETWORKISPERSISTENT
    rb_define_method(c_network, "persistent?", libvirt_netw_persistent_p, 0);
#endif
#endif
}
