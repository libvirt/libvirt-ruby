/*
 * storage.c: virStoragePool and virStorageVolume methods
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

#if HAVE_TYPE_VIRSTORAGEVOLPTR
/* this has to be here (as opposed to below with the rest of the volume
 * stuff) because libvirt_vol_get_pool() relies on it
 */
static virStorageVolPtr vol_get(VALUE s) {
    generic_get(StorageVol, s);
}
#endif

#if HAVE_TYPE_VIRSTORAGEPOOLPTR
static VALUE c_storage_pool;
static VALUE c_storage_pool_info;

/*
 * Class Libvirt::StoragePool
 */

static void pool_free(void *d) {
    generic_free(StoragePool, d);
}

static virStoragePoolPtr pool_get(VALUE s) {
    generic_get(StoragePool, s);
}

static VALUE pool_new(virStoragePoolPtr n, VALUE conn) {
    return generic_new(c_storage_pool, n, conn, pool_free);
}

/*
 * call-seq:
 *   conn.list_storage_pools -> list
 *
 * Call +virConnectListStoragePools+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListStoragePools]
 */
static VALUE libvirt_conn_list_storage_pools(VALUE s) {
    gen_conn_list_names(s, StoragePools);
}

/*
 * call-seq:
 *   conn.num_of_storage_pools -> fixnum
 *
 * Call +virConnectNumOfStoragePools+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfStoragePools]
 */
static VALUE libvirt_conn_num_of_storage_pools(VALUE s) {
    gen_conn_num_of(s, StoragePools);
}

/*
 * call-seq:
 *   conn.list_defined_storage_pools -> list
 *
 * Call +virConnectListDefinedStoragePools+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDefinedStoragePools]
 */
static VALUE libvirt_conn_list_defined_storage_pools(VALUE s) {
    gen_conn_list_names(s, DefinedStoragePools);
}

/*
 * call-seq:
 *   conn.num_of_defined_storage_pools -> fixnum
 *
 * Call +virConnectNumOfDefinedStoragePools+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDefinedStoragePools]
 */
static VALUE libvirt_conn_num_of_defined_storage_pools(VALUE s) {
    gen_conn_num_of(s, DefinedStoragePools);
}

/*
 * call-seq:
 *   conn.lookup_pool_by_name -> Libvirt::StoragePool
 *
 * Call +virStoragePoolLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolLookupByName]
 */
static VALUE libvirt_conn_lookup_pool_by_name(VALUE c, VALUE name) {
    virStoragePoolPtr pool;
    virConnectPtr conn = connect_get(c);

    pool = virStoragePoolLookupByName(conn, StringValueCStr(name));
    _E(pool == NULL, create_error(e_RetrieveError,
                                  "virStoragePoolLookupByName", "", conn));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.lookup_pool_by_uuid -> Libvirt::StoragePool
 *
 * Call +virStoragePoolLookupByUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolLookupByUUIDString]
 */
static VALUE libvirt_conn_lookup_pool_by_uuid(VALUE c, VALUE uuid) {
    virStoragePoolPtr pool;
    virConnectPtr conn = connect_get(c);

    pool = virStoragePoolLookupByUUIDString(conn, StringValueCStr(uuid));
    _E(pool == NULL, create_error(e_RetrieveError,
                                  "virStoragePoolLookupByUUID", "", conn));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   vol.get_pool -> Libvirt::StoragePool
 *
 * Call +virStoragePoolLookupByVolume+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolLookupByVolume]
 */
static VALUE libvirt_vol_get_pool(VALUE v) {
    virStoragePoolPtr pool;

    pool = virStoragePoolLookupByVolume(vol_get(v));
    _E(pool == NULL, create_error(e_RetrieveError,
                                  "virStoragePoolLookupByVolume", "", conn(v)));

    return pool_new(pool, conn_attr(v));
}

/*
 * call-seq:
 *   conn.create_pool_xml -> Libvirt::StoragePool
 *
 * Call +virStoragePoolCreateXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolCreateXML]
 */
static VALUE libvirt_conn_create_pool_xml(int argc, VALUE *argv, VALUE c) {
    virStoragePoolPtr pool;
    virConnectPtr conn = connect_get(c);
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    pool = virStoragePoolCreateXML(conn, StringValueCStr(xml), NUM2UINT(flags));
    _E(pool == NULL, create_error(e_Error, "virStoragePoolCreateXML", "",
                                  conn));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.define_pool_xml -> Libvirt::StoragePool
 *
 * Call +virStoragePoolDefineXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolDefineXML]
 */
static VALUE libvirt_conn_define_pool_xml(int argc, VALUE *argv, VALUE c) {
    virStoragePoolPtr pool;
    virConnectPtr conn = connect_get(c);
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    pool = virStoragePoolDefineXML(conn, StringValueCStr(xml), NUM2UINT(flags));
    _E(pool == NULL, create_error(e_DefinitionError, "virStoragePoolDefineXML",
                                  "", conn));

    return pool_new(pool, c);
}

/*
 * call-seq:
 *   conn.find_storage_pool_sources -> string
 *
 * Call +virConnectFindStoragePoolSources+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectFindStoragePoolSources]
 */
static VALUE libvirt_conn_find_storage_pool_sources(int argc, VALUE *argv, VALUE c) {
    VALUE type, srcSpec_val, flags;

    rb_scan_args(argc, argv, "12", &type, &srcSpec_val, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virConnectFindStoragePoolSources, conn(c), 1,
                    connect_get(c), StringValueCStr(type),
                    get_string_or_nil(srcSpec_val), NUM2UINT(flags));
}

/*
 * call-seq:
 *   pool.build -> nil
 *
 * Call +virStoragePoolBuild+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolBuild]
 */
static VALUE libvirt_pool_build(int argc, VALUE *argv, VALUE p) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virStoragePoolBuild, conn(p), pool_get(p), NUM2UINT(flags));
}

/*
 * call-seq:
 *   pool.undefine -> nil
 *
 * Call +virStoragePoolUndefine+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolUndefine]
 */
static VALUE libvirt_pool_undefine(VALUE p) {
    gen_call_void(virStoragePoolUndefine, conn(p), pool_get(p));
}

/*
 * call-seq:
 *   pool.create -> nil
 *
 * Call +virStoragePoolCreate+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolCreate]
 */
static VALUE libvirt_pool_create(int argc, VALUE *argv, VALUE p) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virStoragePoolCreate, conn(p), pool_get(p), NUM2UINT(flags));
}

/*
 * call-seq:
 *   pool.destroy -> nil
 *
 * Call +virStoragePoolDestroy+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolDestroy]
 */
static VALUE libvirt_pool_destroy(VALUE p) {
    gen_call_void(virStoragePoolDestroy, conn(p), pool_get(p));
}

/*
 * call-seq:
 *   pool.delete -> nil
 *
 * Call +virStoragePoolDelete+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolDelete]
 */
static VALUE libvirt_pool_delete(int argc, VALUE *argv, VALUE p) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virStoragePoolDelete, conn(p), pool_get(p), NUM2UINT(flags));
}

/*
 * call-seq:
 *   pool.refresh -> nil
 *
 * Call +virStoragePoolRefresh+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolRefresh]
 */
static VALUE libvirt_pool_refresh(int argc, VALUE *argv, VALUE p) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virStoragePoolRefresh, conn(p), pool_get(p), NUM2UINT(flags));
}

/*
 * call-seq:
 *   pool.name -> string
 *
 * Call +virStoragePoolGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolGetName]
 */
static VALUE libvirt_pool_name(VALUE s) {
    gen_call_string(virStoragePoolGetName, conn(s), 0, pool_get(s));
}

/*
 * call-seq:
 *   pool.uuid -> string
 *
 * Call +virStoragePoolGetUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolGetUUIDString]
 */
static VALUE libvirt_pool_uuid(VALUE s) {
    char uuid[VIR_UUID_STRING_BUFLEN];
    int r;

    r = virStoragePoolGetUUIDString(pool_get(s), uuid);
    _E(r < 0, create_error(e_RetrieveError, "virStoragePoolGetUUIDString", "",
                           conn(s)));

    return rb_str_new2((char *) uuid);
}

/*
 * call-seq:
 *   pool.info -> Libvirt::StoragePoolInfo
 *
 * Call +virStoragePoolGetInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolGetInfo]
 */
static VALUE libvirt_pool_info(VALUE s) {
    virStoragePoolInfo info;
    int r;
    VALUE result;

    r = virStoragePoolGetInfo(pool_get(s), &info);
    _E(r < 0, create_error(e_RetrieveError, "virStoragePoolGetInfo", "",
                           conn(s)));

    result = rb_class_new_instance(0, NULL, c_storage_pool_info);
    rb_iv_set(result, "@state", INT2FIX(info.state));
    rb_iv_set(result, "@capacity", ULL2NUM(info.capacity));
    rb_iv_set(result, "@allocation", ULL2NUM(info.allocation));
    rb_iv_set(result, "@available", ULL2NUM(info.available));

    return result;
}

/*
 * call-seq:
 *   pool.xml_desc -> string
 *
 * Call +virStoragePoolGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolGetXMLDesc]
 */
static VALUE libvirt_pool_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virStoragePoolGetXMLDesc, conn(s), 1, pool_get(s),
                    NUM2UINT(flags));
}

/*
 * call-seq:
 *   pool.autostart? -> [true|false]
 *
 * Call +virStoragePoolGetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolGetAutostart]
 */
static VALUE libvirt_pool_autostart(VALUE s){
    int r, autostart;

    r = virStoragePoolGetAutostart(pool_get(s), &autostart);
    _E(r < 0, create_error(e_RetrieveError, "virStoragePoolGetAutostart", "",
                           conn(s)));

    return autostart ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   pool.autostart_set -> nil
 *
 * Call +virStoragePoolSetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolSetAutostart]
 */
static VALUE libvirt_pool_autostart_set(VALUE s, VALUE autostart) {
    gen_call_void(virStoragePoolSetAutostart, conn(s), pool_get(s),
                  RTEST(autostart) ? 1 : 0);
}

/*
 * call-seq:
 *   pool.num_of_volumes -> fixnum
 *
 * Call +virStoragePoolNumOfVolumes+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolNumOfVolumes]
 */
static VALUE libvirt_pool_num_of_volumes(VALUE s) {
    int n = virStoragePoolNumOfVolumes(pool_get(s));
    _E(n < 0, create_error(e_RetrieveError, "virStoragePoolNumOfVolumes", "",
                           conn(s)));

    return INT2FIX(n);
}

/*
 * call-seq:
 *   pool.list_volumes -> list
 *
 * Call +virStoragePoolListVolumes+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolListVolumes]
 */
static VALUE libvirt_pool_list_volumes(VALUE s) {
    int i, r, num;
    char **names;
    virStoragePoolPtr pool = pool_get(s);
    VALUE result;

    num = virStoragePoolNumOfVolumes(pool);
    _E(num < 0, create_error(e_RetrieveError, "virStoragePoolNumOfVolumes", "",
                             conn(s)));
    if (num == 0) {
        result = rb_ary_new2(num);
        return result;
    }

    names = ALLOC_N(char *, num);
    r = virStoragePoolListVolumes(pool, names, num);
    if (r < 0) {
        free(names);
        rb_exc_raise(create_error(e_RetrieveError, "virStoragePoolListVolumes",
                                  "", conn(s)));
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
 *   pool.free -> nil
 *
 * Call +virStoragePoolFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolFree]
 */
static VALUE libvirt_pool_free(VALUE s) {
    gen_call_free(StoragePool, s);
}
#endif

#if HAVE_TYPE_VIRSTORAGEVOLPTR
/*
 * Libvirt::StorageVol
 */
static VALUE c_storage_vol;
static VALUE c_storage_vol_info;

static void vol_free(void *d) {
    generic_free(StorageVol, d);
}

static VALUE vol_new(virStorageVolPtr n, VALUE conn) {
    return generic_new(c_storage_vol, n, conn, vol_free);
}

/*
 * call-seq:
 *   pool.lookup_vol_by_name -> Libvirt::StorageVol
 *
 * Call +virStorageVolLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolLookupByName]
 */
static VALUE libvirt_pool_lookup_vol_by_name(VALUE p, VALUE name) {
    virStorageVolPtr vol;

    vol = virStorageVolLookupByName(pool_get(p), StringValueCStr(name));
    _E(vol == NULL, create_error(e_RetrieveError, "virStorageVolLookupByName",
                                 "", conn(p)));

    return vol_new(vol, conn_attr(p));
}

/*
 * call-seq:
 *   pool.lookup_vol_by_key -> Libvirt::StorageVol
 *
 * Call +virStorageVolLookupByKey+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolLookupByKey]
 */
static VALUE libvirt_pool_lookup_vol_by_key(VALUE p, VALUE key) {
    virStorageVolPtr vol;

    // FIXME: Why does this take a connection, not a pool ?
    vol = virStorageVolLookupByKey(conn(p), StringValueCStr(key));
    _E(vol == NULL, create_error(e_RetrieveError, "virStorageVolLookupByKey",
                                 "", conn(p)));

    return vol_new(vol, conn_attr(p));
}

/*
 * call-seq:
 *   pool.lookup_vol_by_path -> Libvirt::StorageVol
 *
 * Call +virStorageVolLookupByPath+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolLookupByPath]
 */
static VALUE libvirt_pool_lookup_vol_by_path(VALUE p, VALUE path) {
    virStorageVolPtr vol;

    // FIXME: Why does this take a connection, not a pool ?
    vol = virStorageVolLookupByPath(conn(p), StringValueCStr(path));
    _E(vol == NULL, create_error(e_RetrieveError, "virStorageVolLookupByPath",
                                 "", conn(p)));

    return vol_new(vol, conn_attr(p));
}

/*
 * call-seq:
 *   vol.name -> string
 *
 * Call +virStorageVolGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolGetName]
 */
static VALUE libvirt_vol_name(VALUE v) {
    gen_call_string(virStorageVolGetName, conn(v), 0, vol_get(v));
}

/*
 * call-seq:
 *   vol.key -> string
 *
 * Call +virStorageVolGetKey+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolGetKey]
 */
static VALUE libvirt_vol_key(VALUE v) {
    gen_call_string(virStorageVolGetKey, conn(v), 0, vol_get(v));
}

/*
 * call-seq:
 *   pool.vol_create_xml -> Libvirt::StorageVol
 *
 * Call +virStorageVolCreateXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolCreateXML]
 */
static VALUE libvirt_pool_vol_create_xml(int argc, VALUE *argv, VALUE p) {
    virStorageVolPtr vol;
    virConnectPtr c = conn(p);
    VALUE xml, flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    vol = virStorageVolCreateXML(pool_get(p), StringValueCStr(xml),
                                 NUM2UINT(flags));
    _E(vol == NULL, create_error(e_Error, "virNetworkCreateXML", "", c));

    return vol_new(vol, conn_attr(p));
}

/*
 * call-seq:
 *   pool.vol_create_xml_from -> Libvirt::StorageVol
 *
 * Call +virStorageVolCreateXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolCreateXML]
 */
static VALUE libvirt_pool_vol_create_xml_from(int argc, VALUE *argv, VALUE p) {
    virStorageVolPtr vol;
    virConnectPtr c = conn(p);
    VALUE xml, flags, cloneval;

    rb_scan_args(argc, argv, "21", &xml, &cloneval, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    vol = virStorageVolCreateXMLFrom(pool_get(p), StringValueCStr(xml),
                                     vol_get(cloneval), NUM2UINT(flags));
    _E(vol == NULL, create_error(e_Error, "virNetworkCreateXMLFrom", "", c));

    return vol_new(vol, conn_attr(p));
}

#if HAVE_VIRSTORAGEPOOLISACTIVE
/*
 * call-seq:
 *   pool.active? -> [true|false]
 *
 * Call +virStoragePoolIsActive+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolIsActive]
 */
static VALUE libvirt_pool_active_p(VALUE p) {
    gen_call_truefalse(virStoragePoolIsActive, conn(p), pool_get(p));
}
#endif

#if HAVE_VIRSTORAGEPOOLISPERSISTENT
/*
 * call-seq:
 *   pool.persistent? -> [true|false]
 *
 * Call +virStoragePoolIsPersistent+[http://www.libvirt.org/html/libvirt-libvirt.html#virStoragePoolIsPersistent]
 */
static VALUE libvirt_pool_persistent_p(VALUE p) {
    gen_call_truefalse(virStoragePoolIsPersistent, conn(p), pool_get(p));
}
#endif

/*
 * call-seq:
 *   vol.delete -> nil
 *
 * Call +virStorageVolDelete+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolDelete]
 */
static VALUE libvirt_vol_delete(int argc, VALUE *argv, VALUE v) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virStorageVolDelete, conn(v), vol_get(v), NUM2UINT(flags));
}

#if HAVE_VIRSTORAGEVOLWIPE
/*
 * call-seq:
 *   vol.wipe -> nil
 *
 * Call +virStorageVolWipe+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolWipe]
 */
static VALUE libvirt_vol_wipe(int argc, VALUE *argv, VALUE v) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virStorageVolWipe, conn(v), vol_get(v), NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   vol.info -> Libvirt::StorageVolInfo
 *
 * Call +virStorageVolGetInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolGetInfo]
 */
static VALUE libvirt_vol_info(VALUE v) {
    virStorageVolInfo info;
    int r;
    VALUE result;

    r = virStorageVolGetInfo(vol_get(v), &info);
    _E(r < 0, create_error(e_RetrieveError, "virStorageVolGetInfo", "",
                           conn(v)));

    result = rb_class_new_instance(0, NULL, c_storage_vol_info);
    rb_iv_set(result, "@type", INT2NUM(info.type));
    rb_iv_set(result, "@capacity", ULL2NUM(info.capacity));
    rb_iv_set(result, "@allocation", ULL2NUM(info.allocation));

    return result;
}

/*
 * call-seq:
 *   vol.xml_desc -> string
 *
 * Call +virStorageVolGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolGetXMLDesc]
 */
static VALUE libvirt_vol_xml_desc(int argc, VALUE *argv, VALUE v) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virStorageVolGetXMLDesc, conn(v), 1, vol_get(v),
                    NUM2UINT(flags));
}

/*
 * call-seq:
 *   vol.path -> string
 *
 * Call +virStorageVolGetPath+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolGetPath]
 */
static VALUE libvirt_vol_path(VALUE v) {
    gen_call_string(virStorageVolGetPath, conn(v), 1, vol_get(v));
}

/*
 * call-seq:
 *   vol.free -> nil
 *
 * Call +virStorageVolFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virStorageVolFree]
 */
static VALUE libvirt_vol_free(VALUE s) {
    gen_call_free(StorageVol, s);
}
#endif

void init_storage(void) {
    /*
     * Class Libvirt::StoragePool and Libvirt::StoragePoolInfo
     */
#if HAVE_TYPE_VIRSTORAGEPOOLPTR
    c_storage_pool_info = rb_define_class_under(m_libvirt, "StoragePoolInfo",
                                                rb_cObject);
    rb_define_attr(c_storage_pool_info, "state", 1, 0);
    rb_define_attr(c_storage_pool_info, "capacity", 1, 0);
    rb_define_attr(c_storage_pool_info, "allocation", 1, 0);
    rb_define_attr(c_storage_pool_info, "available", 1, 0);

    c_storage_pool = rb_define_class_under(m_libvirt, "StoragePool",
                                           rb_cObject);
#define DEF_POOLCONST(name)                                        \
    rb_define_const(c_storage_pool, #name, INT2NUM(VIR_STORAGE_POOL_##name))
    /* virStoragePoolState */
    DEF_POOLCONST(INACTIVE);
    DEF_POOLCONST(BUILDING);
    DEF_POOLCONST(RUNNING);
    DEF_POOLCONST(DEGRADED);
#ifdef VIR_STORAGE_POOL_INACCESSIBLE
    DEF_POOLCONST(INACCESSIBLE);
#endif
    /* virStoragePoolBuildFlags */
    DEF_POOLCONST(BUILD_NEW);
    DEF_POOLCONST(BUILD_REPAIR);
    DEF_POOLCONST(BUILD_RESIZE);
    /* virStoragePoolDeleteFlags */
    DEF_POOLCONST(DELETE_NORMAL);
    DEF_POOLCONST(DELETE_ZEROED);
#undef DEF_POOLCONST

    /* StoragePool lookup/creation methods */
    rb_define_method(c_connect, "num_of_storage_pools",
                     libvirt_conn_num_of_storage_pools, 0);
    rb_define_method(c_connect, "list_storage_pools",
                     libvirt_conn_list_storage_pools, 0);
    rb_define_method(c_connect, "num_of_defined_storage_pools",
                     libvirt_conn_num_of_defined_storage_pools, 0);
    rb_define_method(c_connect, "list_defined_storage_pools",
                     libvirt_conn_list_defined_storage_pools, 0);
    rb_define_method(c_connect, "lookup_storage_pool_by_name",
                     libvirt_conn_lookup_pool_by_name, 1);
    rb_define_method(c_connect, "lookup_storage_pool_by_uuid",
                     libvirt_conn_lookup_pool_by_uuid, 1);
    rb_define_method(c_connect, "create_storage_pool_xml",
                     libvirt_conn_create_pool_xml, -1);
    rb_define_method(c_connect, "define_storage_pool_xml",
                     libvirt_conn_define_pool_xml, -1);
    rb_define_method(c_connect, "discover_storage_pool_sources",
                     libvirt_conn_find_storage_pool_sources, -1);

    /* Creating/destroying pools */
    rb_define_method(c_storage_pool, "build", libvirt_pool_build, -1);
    rb_define_method(c_storage_pool, "undefine", libvirt_pool_undefine, 0);
    rb_define_method(c_storage_pool, "create", libvirt_pool_create, -1);
    rb_define_method(c_storage_pool, "destroy", libvirt_pool_destroy, 0);
    rb_define_method(c_storage_pool, "delete", libvirt_pool_delete, -1);
    rb_define_method(c_storage_pool, "refresh", libvirt_pool_refresh, -1);
    /* StoragePool information */
    rb_define_method(c_storage_pool, "name", libvirt_pool_name, 0);
    rb_define_method(c_storage_pool, "uuid", libvirt_pool_uuid, 0);
    rb_define_method(c_storage_pool, "info", libvirt_pool_info, 0);
    rb_define_method(c_storage_pool, "xml_desc", libvirt_pool_xml_desc, -1);
    rb_define_method(c_storage_pool, "autostart", libvirt_pool_autostart, 0);
    rb_define_method(c_storage_pool, "autostart?", libvirt_pool_autostart, 0);
    rb_define_method(c_storage_pool, "autostart=",
                     libvirt_pool_autostart_set, 1);
    /* List/lookup storage volumes within a pool */
    rb_define_method(c_storage_pool, "num_of_volumes",
                     libvirt_pool_num_of_volumes, 0);
    rb_define_method(c_storage_pool, "list_volumes",
                     libvirt_pool_list_volumes, 0);
    /* Lookup volumes based on various attributes */
    rb_define_method(c_storage_pool, "lookup_volume_by_name",
                     libvirt_pool_lookup_vol_by_name, 1);
    rb_define_method(c_storage_pool, "lookup_volume_by_key",
                     libvirt_pool_lookup_vol_by_key, 1);
    rb_define_method(c_storage_pool, "lookup_volume_by_path",
                     libvirt_pool_lookup_vol_by_path, 1);
    rb_define_method(c_storage_pool, "free", libvirt_pool_free, 0);
    rb_define_method(c_storage_pool, "create_vol_xml",
                     libvirt_pool_vol_create_xml, -1);
    rb_define_method(c_storage_pool, "create_vol_xml_from",
                     libvirt_pool_vol_create_xml_from, -1);
#if HAVE_VIRSTORAGEPOOLISACTIVE
    rb_define_method(c_storage_pool, "active?", libvirt_pool_active_p, 0);
#endif
#if HAVE_VIRSTORAGEPOOLISPERSISTENT
    rb_define_method(c_storage_pool, "persistent?",
                     libvirt_pool_persistent_p, 0);
#endif
#endif

#if HAVE_TYPE_VIRSTORAGEVOLPTR
    /*
     * Class Libvirt::StorageVol and Libvirt::StorageVolInfo
     */
    c_storage_vol_info = rb_define_class_under(m_libvirt, "StorageVolInfo",
                                               rb_cObject);
    rb_define_attr(c_storage_vol_info, "type", 1, 0);
    rb_define_attr(c_storage_vol_info, "capacity", 1, 0);
    rb_define_attr(c_storage_vol_info, "allocation", 1, 0);

    c_storage_vol = rb_define_class_under(m_libvirt, "StorageVol",
                                          rb_cObject);
#define DEF_VOLCONST(name)                                        \
    rb_define_const(c_storage_vol, #name, INT2NUM(VIR_STORAGE_VOL_##name))
    /* virStorageVolType */
    DEF_VOLCONST(FILE);
    DEF_VOLCONST(BLOCK);
    /* virStorageVolDeleteFlags */
    DEF_VOLCONST(DELETE_NORMAL);
    DEF_VOLCONST(DELETE_ZEROED);
#undef DEF_VOLCONST

    rb_define_method(c_storage_vol, "pool", libvirt_vol_get_pool, 0);
    rb_define_method(c_storage_vol, "name", libvirt_vol_name, 0);
    rb_define_method(c_storage_vol, "key", libvirt_vol_key, 0);
    rb_define_method(c_storage_vol, "delete", libvirt_vol_delete, -1);
#if HAVE_VIRSTORAGEVOLWIPE
    rb_define_method(c_storage_vol, "wipe", libvirt_vol_wipe, -1);
#endif
    rb_define_method(c_storage_vol, "info", libvirt_vol_info, 0);
    rb_define_method(c_storage_vol, "xml_desc", libvirt_vol_xml_desc, -1);
    rb_define_method(c_storage_vol, "path", libvirt_vol_path, 0);
    rb_define_method(c_storage_vol, "free", libvirt_vol_free, 0);
#endif
}
