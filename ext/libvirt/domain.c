/*
 * domain.c: virDomain methods
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

VALUE c_domain;
static VALUE c_domain_info;
static VALUE c_domain_ifinfo;
static VALUE c_domain_security_label;
static VALUE c_domain_block_stats;
#if HAVE_TYPE_VIRDOMAINBLOCKINFOPTR
static VALUE c_domain_block_info;
#endif
#if HAVE_TYPE_VIRDOMAINMEMORYSTATPTR
static VALUE c_domain_memory_stats;
#endif
#if HAVE_TYPE_VIRDOMAINSNAPSHOTPTR
static VALUE c_domain_snapshot;
#endif
#if HAVE_TYPE_VIRDOMAINJOBINFOPTR
static VALUE c_domain_job_info;
#endif

static void domain_free(void *d) {
    generic_free(Domain, d);
}

static VALUE domain_new(virDomainPtr d, VALUE conn) {
    return generic_new(c_domain, d, conn, domain_free);
}

static virDomainPtr domain_get(VALUE s) {
    generic_get(Domain, s);
}

/*
 * call-seq:
 *   conn.num_of_domains -> fixnum
 *
 * Call +virConnectNumOfDomains+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDomains]
 */
static VALUE libvirt_conn_num_of_domains(VALUE s) {
    gen_conn_num_of(s, Domains);
}

/*
 * call-seq:
 *   conn.list_domains -> list
 *
 * Call +virConnectListDomains+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDomains]
 */
static VALUE libvirt_conn_list_domains(VALUE s) {
    int i, r, num, *ids;
    virConnectPtr conn = connect_get(s);
    VALUE result;

    num = virConnectNumOfDomains(conn);
    _E(num < 0, create_error(e_RetrieveError, "virConnectNumOfDomains", "", conn));
    if (num == 0) {
        result = rb_ary_new2(num);
        return result;
    }

    ids = ALLOC_N(int, num);
    r = virConnectListDomains(conn, ids, num);
    if (r < 0) {
        free(ids);
        _E(r < 0, create_error(e_RetrieveError, "virConnectListDomains", "", conn));
    }

    result = rb_ary_new2(num);
    for (i=0; i<num; i++) {
        rb_ary_push(result, INT2NUM(ids[i]));
    }
    free(ids);
    return result;
}

/*
 * call-seq:
 *   conn.num_of_defined_domains -> fixnum
 *
 * Call +virConnectNumOfDefinedDomains+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectNumOfDefinedDomains]
 */
static VALUE libvirt_conn_num_of_defined_domains(VALUE s) {
    gen_conn_num_of(s, DefinedDomains);
}

/*
 * call-seq:
 *   conn.list_defined_domains -> list
 *
 * Call +virConnectListDefinedDomains+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectListDefinedDomains]
 */
static VALUE libvirt_conn_list_defined_domains(VALUE s) {
    gen_conn_list_names(s, DefinedDomains);
}

/*
 * call-seq:
 *   dom.create_linux -> Libvirt::Domain
 *
 * Call +virDomainCreateLinux+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCreateLinux]
 */
static VALUE libvirt_conn_create_linux(int argc, VALUE *argv, VALUE c) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);
    VALUE flags, xml;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    dom = virDomainCreateLinux(conn, StringValueCStr(xml), NUM2UINT(flags));
    _E(dom == NULL, create_error(e_Error, "virDomainCreateLinux", "", conn));

    return domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.lookup_domain_by_name -> Libvirt::Domain
 *
 * Call +virDomainLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainLookupByName]
 */
static VALUE libvirt_conn_lookup_domain_by_name(VALUE c, VALUE name) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainLookupByName(conn, StringValueCStr(name));
    _E(dom == NULL, create_error(e_RetrieveError, "virDomainLookupByName", "", conn));

    return domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.lookup_domain_by_id -> Libvirt::Domain
 *
 * Call +virDomainLookupByID+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainLookupByID]
 */
static VALUE libvirt_conn_lookup_domain_by_id(VALUE c, VALUE id) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainLookupByID(conn, NUM2INT(id));
    _E(dom == NULL, create_error(e_RetrieveError, "virDomainLookupByID", "", conn));

    return domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.lookup_domain_by_uuid -> Libvirt::Domain
 *
 * Call +virDomainLookupByUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainLookupByUUIDString]
 */
static VALUE libvirt_conn_lookup_domain_by_uuid(VALUE c, VALUE uuid) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainLookupByUUIDString(conn, StringValueCStr(uuid));
    _E(dom == NULL, create_error(e_RetrieveError, "virDomainLookupByUUID", "", conn));

    return domain_new(dom, c);
}

/*
 * call-seq:
 *   conn.define_domain_xml -> Libvirt::Domain
 *
 * Call +virDomainDefineXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainDefineXML]
 */
static VALUE libvirt_conn_define_domain_xml(VALUE c, VALUE xml) {
    virDomainPtr dom;
    virConnectPtr conn = connect_get(c);

    dom = virDomainDefineXML(conn, StringValueCStr(xml));
    _E(dom == NULL, create_error(e_DefinitionError, "virDomainDefineXML", "", conn));

    return domain_new(dom, c);
}

#if HAVE_VIRCONNECTDOMAINXMLFROMNATIVE
/*
 * call-seq:
 *   conn.domain_xml_from_native -> string
 *
 * Call +virConnectDomainXMLFromNative+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainXMLFromNative]
 */
static VALUE libvirt_conn_domain_xml_from_native(int argc, VALUE *argv, VALUE s) {
    VALUE nativeFormat, xml, flags;
    char *ret;
    VALUE result;

    rb_scan_args(argc, argv, "21", &nativeFormat, &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    ret = virConnectDomainXMLFromNative(conn(s), StringValueCStr(nativeFormat),
                                        StringValueCStr(xml), NUM2UINT(flags));
    _E(ret == NULL,
       create_error(e_Error, "virConnectDomainXMLFromNative", "", conn(s)));

    result = rb_str_new2(ret);

    free(ret);

    return result;
}
#endif

#if HAVE_VIRCONNECTDOMAINXMLTONATIVE
/*
 * call-seq:
 *   conn.domain_xml_to_native -> string
 *
 * Call +virConnectDomainXMLToNative+[http://www.libvirt.org/html/libvirt-libvirt.html#virConnectDomainXMLToNative]
 */
static VALUE libvirt_conn_domain_xml_to_native(int argc, VALUE *argv, VALUE s) {
    VALUE nativeFormat, xml, flags;
    char *ret;
    VALUE result;

    rb_scan_args(argc, argv, "21", &nativeFormat, &xml, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    ret = virConnectDomainXMLToNative(conn(s), StringValueCStr(nativeFormat),
                                      StringValueCStr(xml), NUM2UINT(flags));
    _E(ret == NULL,
       create_error(e_Error, "virConnectDomainXMLToNative", "", conn(s)));

    result = rb_str_new2(ret);

    free(ret);

    return result;
}
#endif

/*
 * call-seq:
 *   dom.migrate -> Libvirt::Domain
 *
 * Call +virDomainMigrate+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrate]
 */
static VALUE libvirt_dom_migrate(int argc, VALUE *argv, VALUE s) {
    VALUE dconn, flags, dname_val, uri_val, bandwidth;
    virDomainPtr ddom = NULL;

    rb_scan_args(argc, argv, "14", &dconn, &flags, &dname_val, &uri_val,
                 &bandwidth);

    if (NIL_P(bandwidth))
        bandwidth = INT2FIX(0);
    if (NIL_P(flags))
        flags = INT2FIX(0);

    ddom = virDomainMigrate(domain_get(s), conn(dconn), NUM2ULONG(flags),
                            get_string_or_nil(dname_val),
                            get_string_or_nil(uri_val), NUM2ULONG(bandwidth));

    _E(ddom == NULL,
       create_error(e_Error, "virDomainMigrate", "", conn(s)));

    return domain_new(ddom, dconn);
}

#if HAVE_VIRDOMAINMIGRATETOURI
/*
 * call-seq:
 *   dom.migrate_to_uri -> nil
 *
 * Call +virDomainMigrateToURI+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrateToURI]
 */
static VALUE libvirt_dom_migrate_to_uri(int argc, VALUE *argv, VALUE s) {
    VALUE flags, dname_val, bandwidth, duri_val;
    int ret;

    rb_scan_args(argc, argv, "13", &duri_val, &flags, &dname_val, &bandwidth);

    if (NIL_P(bandwidth))
        bandwidth = INT2FIX(0);
    if (NIL_P(flags))
        flags = INT2FIX(0);

    ret = virDomainMigrateToURI(domain_get(s), StringValueCStr(duri_val),
                                NUM2ULONG(flags), get_string_or_nil(dname_val),
                                NUM2ULONG(bandwidth));

    _E(ret < 0,
       create_error(e_Error, "virDomainMigrateToURI", "", conn(s)));

    return Qnil;
}
#endif

#if HAVE_VIRDOMAINMIGRATESETMAXDOWNTIME
/*
 * call-seq:
 *   dom.migrate_set_max_downtime -> nil
 *
 * Call +virDomainMigrateSetMaxDowntime+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrateSetMaxDowntime]
 */
static VALUE libvirt_dom_migrate_set_max_downtime(int argc, VALUE *argv, VALUE s) {
    VALUE downtime, flags;
    int ret;

    rb_scan_args(argc, argv, "11", &downtime, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    ret = virDomainMigrateSetMaxDowntime(domain_get(s), NUM2ULL(downtime),
                                         NUM2UINT(flags));

    _E(ret < 0,
       create_error(e_Error, "virDomainMigrateSetMaxDowntime", "", conn(s)));

    return Qnil;
}
#endif

/*
 * call-seq:
 *   dom.shutdown -> nil
 *
 * Call +virDomainShutdown+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainShutdown]
 */
static VALUE libvirt_dom_shutdown(VALUE s) {
    gen_call_void(virDomainShutdown, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.reboot -> nil
 *
 * Call +virDomainReboot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainReboot]
 */
static VALUE libvirt_dom_reboot(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virDomainReboot, conn(s), domain_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.destroy -> nil
 *
 * Call +virDomainDestroy+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainDestroy]
 */
static VALUE libvirt_dom_destroy(VALUE s) {
    gen_call_void(virDomainDestroy, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.suspend -> nil
 *
 * Call +virDomainSuspend+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSuspend]
 */
static VALUE libvirt_dom_suspend(VALUE s) {
    gen_call_void(virDomainSuspend, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.resume -> nil
 *
 * Call +virDomainResume+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainResume]
 */
static VALUE libvirt_dom_resume(VALUE s) {
    gen_call_void(virDomainResume, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.save -> nil
 *
 * Call +virDomainSave+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSave]
 */
static VALUE libvirt_dom_save(VALUE s, VALUE to) {
    gen_call_void(virDomainSave, conn(s), domain_get(s), StringValueCStr(to));
}

#if HAVE_VIRDOMAINMANAGEDSAVE
/*
 * call-seq:
 *   dom.managed_save -> nil
 *
 * Call +virDomainManagedSave+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainManagedSave]
 */
static VALUE libvirt_dom_managed_save(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virDomainManagedSave, conn(s), domain_get(s),
                  NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.has_managed_save -> [true|false]
 *
 * Call +virDomainHasManagedSaveImage+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainHasManagedSaveImage]
 */
static VALUE libvirt_dom_has_managed_save(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_truefalse(virDomainHasManagedSaveImage, conn(s), domain_get(s),
                       NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.managed_save_remove -> nil
 *
 * Call +virDomainManagedSaveRemove+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainManagedSaveRemove]
 */
static VALUE libvirt_dom_managed_save_remove(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virDomainManagedSaveRemove, conn(s), domain_get(s),
                  NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   dom.core_dump -> nil
 *
 * Call +virDomainCoreDump+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCoreDump]
 */
static VALUE libvirt_dom_core_dump(int argc, VALUE *argv, VALUE s) {
    VALUE to, flags;

    rb_scan_args(argc, argv, "11", &to, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virDomainCoreDump, conn(s), domain_get(s),
                  StringValueCStr(to), NUM2INT(flags));
}

/*
 * call-seq:
 *   dom.restore -> nil
 *
 * Call +virDomainRestore+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainRestore]
 */
static VALUE libvirt_dom_s_restore(VALUE klass, VALUE c, VALUE from) {
    gen_call_void(virDomainRestore, conn(c), connect_get(c),
                  StringValueCStr(from));
}

/*
 * call-seq:
 *   domain.info -> Libvirt::Domain::Info
 *
 * Call +virDomainGetInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetInfo]
 */
static VALUE libvirt_dom_info(VALUE s) {
    virDomainPtr dom = domain_get(s);
    virDomainInfo info;
    int r;
    VALUE result;

    r = virDomainGetInfo(dom, &info);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetInfo", "", conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_info);
    rb_iv_set(result, "@state", CHR2FIX(info.state));
    rb_iv_set(result, "@max_mem", ULONG2NUM(info.maxMem));
    rb_iv_set(result, "@memory", ULONG2NUM(info.memory));
    rb_iv_set(result, "@nr_virt_cpu", INT2FIX((int) info.nrVirtCpu));
    rb_iv_set(result, "@cpu_time", ULL2NUM(info.cpuTime));
    return result;
}

/*
 * call-seq:
 *   domain.security_label -> Libvirt::Domain::SecurityLabel
 *
 * Call +virDomainGetSecurityLabel+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetSecurityLabel]
 */
static VALUE libvirt_dom_security_label(VALUE s) {
    virDomainPtr dom = domain_get(s);
    virSecurityLabel seclabel;
    int r;
    VALUE result;

    r = virDomainGetSecurityLabel(dom, &seclabel);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetSecurityLabel", "", conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_security_label);
    rb_iv_set(result, "@label", rb_str_new2(seclabel.label));
    rb_iv_set(result, "@enforcing", INT2NUM(seclabel.enforcing));

    return result;
}

/*
 * call-seq:
 *   domain.block_stats -> Libvirt::Domain::BlockStats
 *
 * Call +virDomainBlockStats+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainBlockStats]
 */
static VALUE libvirt_dom_block_stats(VALUE s, VALUE path) {
    virDomainPtr dom = domain_get(s);
    virDomainBlockStatsStruct stats;
    int r;
    VALUE result;

    r = virDomainBlockStats(dom, StringValueCStr(path), &stats, sizeof(stats));
    _E(r < 0, create_error(e_RetrieveError, "virDomainBlockStats", "", conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_block_stats);
    rb_iv_set(result, "@rd_req", LL2NUM(stats.rd_req));
    rb_iv_set(result, "@rd_bytes", LL2NUM(stats.rd_bytes));
    rb_iv_set(result, "@wr_req", LL2NUM(stats.wr_req));
    rb_iv_set(result, "@wr_bytes", LL2NUM(stats.wr_bytes));
    rb_iv_set(result, "@errs", LL2NUM(stats.errs));

    return result;
}

#if HAVE_TYPE_VIRDOMAINMEMORYSTATPTR
/*
 * call-seq:
 *   domain.memory_stats -> Libvirt::Domain::MemoryStats
 *
 * Call +virDomainMemoryStats+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMemoryStats]
 */
static VALUE libvirt_dom_memory_stats(int argc, VALUE *argv, VALUE s) {
    virDomainPtr dom = domain_get(s);
    virDomainMemoryStatStruct stats[6];
    int r;
    VALUE result;
    VALUE flags;
    VALUE tmp;
    int i;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    r = virDomainMemoryStats(dom, stats, 6, NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virDomainMemoryStats", "", conn(s)));

    result = rb_ary_new2(r);
    for (i=0; i<r; i++) {
        tmp = rb_class_new_instance(0, NULL, c_domain_memory_stats);
        rb_iv_set(tmp, "@tag", INT2NUM(stats[i].tag));
        rb_iv_set(tmp, "@val", ULL2NUM(stats[i].val));

        rb_ary_push(result, tmp);
    }                                           \

    return result;
}
#endif

#if HAVE_TYPE_VIRDOMAINBLOCKINFOPTR
/*
 * call-seq:
 *   domain.block_info -> Libvirt::Domain::BlockInfo
 *
 * Call +virDomainGetBlockInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetBlockInfo]
 */
static VALUE libvirt_dom_block_info(int argc, VALUE *argv, VALUE s) {
    virDomainPtr dom = domain_get(s);
    virDomainBlockInfo info;
    int r;
    VALUE result;
    VALUE flags;
    VALUE path;

    rb_scan_args(argc, argv, "11", &path, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    r = virDomainGetBlockInfo(dom, StringValueCStr(path), &info, NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetBlockInfo", "", conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_block_info);
    rb_iv_set(result, "@capacity", ULL2NUM(info.capacity));
    rb_iv_set(result, "@allocation", ULL2NUM(info.allocation));
    rb_iv_set(result, "@physical", ULL2NUM(info.physical));

    return result;
}
#endif

/*
 * call-seq:
 *   domain.block_peek -> string
 *
 * Call +virDomainBlockPeek+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainBlockPeek]
 */
static VALUE libvirt_dom_block_peek(int argc, VALUE *argv, VALUE s) {
    virDomainPtr dom = domain_get(s);
    VALUE path, offset, size, flags;
    char *buffer;
    int r;
    VALUE ret;

    rb_scan_args(argc, argv, "31", &path, &offset, &size, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    buffer = ALLOC_N(char, size);

    r = virDomainBlockPeek(dom, StringValueCStr(path),
                           NUM2ULL(offset), NUM2UINT(size), buffer,
                           NUM2UINT(flags));

    if (r < 0) {
        free(buffer);
        rb_exc_raise(create_error(e_RetrieveError, "virDomainBlockPeek", "",
                                  conn(s)));
    }

    ret = rb_str_new((char *)buffer, size);

    free(buffer);

    return ret;
}

/*
 * call-seq:
 *   domain.memory_peek -> string
 *
 * Call +virDomainMemoryPeek+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMemoryPeek]
 */
static VALUE libvirt_dom_memory_peek(int argc, VALUE *argv, VALUE s) {
    virDomainPtr dom = domain_get(s);
    VALUE start, size, flags;
    char *buffer;
    int r;
    VALUE ret;

    rb_scan_args(argc, argv, "21", &start, &size, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    buffer = ALLOC_N(char, size);

    r = virDomainMemoryPeek(dom, NUM2ULL(start), NUM2UINT(size), buffer,
                           NUM2UINT(flags));

    if (r < 0) {
        free(buffer);
        rb_exc_raise(create_error(e_RetrieveError, "virDomainMemoryPeek", "",
                                  conn(s)));
    }

    ret = rb_str_new((char *)buffer, size);

    free(buffer);

    return ret;
}

#if HAVE_VIRDOMAINISACTIVE
/*
 * call-seq:
 *   domain.active? -> [true|false]
 *
 * Call +virDomainIsActive+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainIsActive]
 */
static VALUE libvirt_dom_active_p(VALUE d) {
    gen_call_truefalse(virDomainIsActive, conn(d), domain_get(d));
}
#endif

#if HAVE_VIRDOMAINISPERSISTENT
/*
 * call-seq:
 *   domain.persistent? -> [true|false]
 *
 * Call +virDomainIsPersistent+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainIsPersistent]
 */
static VALUE libvirt_dom_persistent_p(VALUE d) {
    gen_call_truefalse(virDomainIsPersistent, conn(d), domain_get(d));
}
#endif

/*
 * call-seq:
 *   domain.ifinfo -> Libvirt::Domain::IfInfo
 *
 * Call +virDomainInterfaceStats+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainInterfaceStats]
 */
static VALUE libvirt_dom_if_stats(VALUE s, VALUE sif) {
    virDomainPtr dom = domain_get(s);
    char *ifname = get_string_or_nil(sif);
    virDomainInterfaceStatsStruct ifinfo;
    int r;
    VALUE result = Qnil;

    if (ifname) {
        r = virDomainInterfaceStats(dom, ifname, &ifinfo,
                                    sizeof(virDomainInterfaceStatsStruct));
        _E(r < 0, create_error(e_RetrieveError, "virDomainInterfaceStats", "",
                               conn(s)));

        result = rb_class_new_instance(0, NULL, c_domain_ifinfo);
        rb_iv_set(result, "@rx_bytes", LL2NUM(ifinfo.rx_bytes));
        rb_iv_set(result, "@rx_packets", LL2NUM(ifinfo.rx_packets));
        rb_iv_set(result, "@rx_errs", LL2NUM(ifinfo.rx_errs));
        rb_iv_set(result, "@rx_drop", LL2NUM(ifinfo.rx_drop));
        rb_iv_set(result, "@tx_bytes", LL2NUM(ifinfo.tx_bytes));
        rb_iv_set(result, "@tx_packets", LL2NUM(ifinfo.tx_packets));
        rb_iv_set(result, "@tx_errs", LL2NUM(ifinfo.tx_errs));
        rb_iv_set(result, "@tx_drop", LL2NUM(ifinfo.tx_drop));
    }
    return result;
}

/*
 * call-seq:
 *   dom.name -> string
 *
 * Call +virDomainGetName+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetName]
 */
static VALUE libvirt_dom_name(VALUE s) {
    gen_call_string(virDomainGetName, conn(s), 0, domain_get(s));
}

/*
 * call-seq:
 *   dom.id -> fixnum
 *
 * Call +virDomainGetID+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetID]
 */
static VALUE libvirt_dom_id(VALUE s) {
    virDomainPtr dom = domain_get(s);
    unsigned int id;
    int out;

    id = virDomainGetID(dom);
    _E(id < 0, create_error(e_RetrieveError, "virDomainGetID", "", conn(s)));

    /* we need to cast the unsigned int id to a signed int out to handle the
     * -1 case
     */
    out = id;

    return INT2NUM(out);
}

/*
 * call-seq:
 *   dom.uuid -> string
 *
 * Call +virDomainGetUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetUUIDString]
 */
static VALUE libvirt_dom_uuid(VALUE s) {
    virDomainPtr dom = domain_get(s);
    char uuid[VIR_UUID_STRING_BUFLEN];
    int r;

    r = virDomainGetUUIDString(dom, uuid);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetUUIDString", "", conn(s)));

    return rb_str_new2((char *) uuid);
}

/*
 * call-seq:
 *   dom.os_type -> string
 *
 * Call +virDomainGetOSType+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetOSType]
 */
static VALUE libvirt_dom_os_type(VALUE s) {
    gen_call_string(virDomainGetOSType, conn(s), 1, domain_get(s));
}

/*
 * call-seq:
 *   dom.max_memory -> fixnum
 *
 * Call +virDomainGetMaxMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetMaxMemory]
 */
static VALUE libvirt_dom_max_memory(VALUE s) {
    virDomainPtr dom = domain_get(s);
    unsigned long max_memory;

    max_memory = virDomainGetMaxMemory(dom);
    _E(max_memory == 0, create_error(e_RetrieveError, "virDomainGetMaxMemory", "", conn(s)));

    return ULONG2NUM(max_memory);
}

/*
 * call-seq:
 *   dom.max_memory_set -> nil
 *
 * Call +virDomainSetMaxMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetMaxMemory]
 */
static VALUE libvirt_dom_max_memory_set(VALUE s, VALUE max_memory) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainSetMaxMemory(dom, NUM2ULONG(max_memory));
    _E(r < 0, create_error(e_DefinitionError, "virDomainSetMaxMemory", "", conn(s)));

    return ULONG2NUM(max_memory);
}

/*
 * call-seq:
 *   dom.memory_set -> void
 *
 * Call +virDomainSetMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetMemory]
 */
static VALUE libvirt_dom_memory_set(VALUE s, VALUE memory) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainSetMemory(dom, NUM2ULONG(memory));
    _E(r < 0, create_error(e_DefinitionError, "virDomainSetMemory", "", conn(s)));

    return ULONG2NUM(memory);
}

/*
 * call-seq:
 *   dom.max_vcpus -> fixnum
 *
 * Call +virDomainGetMaxVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetMaxVcpus]
 */
static VALUE libvirt_dom_max_vcpus(VALUE s) {
    virDomainPtr dom = domain_get(s);
    int vcpus;

    vcpus = virDomainGetMaxVcpus(dom);
    _E(vcpus < 0, create_error(e_RetrieveError, "virDomainGetMaxVcpus", "", conn(s)));

    return INT2NUM(vcpus);
}


/*
 * call-seq:
 *   dom.vcpus_set -> nil
 *
 * Call +virDomainSetVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetVcpus]
 */
static VALUE libvirt_dom_vcpus_set(VALUE s, VALUE nvcpus) {
    gen_call_void(virDomainSetVcpus, conn(s), domain_get(s), NUM2UINT(nvcpus));
}

/*
 * call-seq:
 *   dom.pin_vcpu -> nil
 *
 * Call +virDomainPinVcpu+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainPinVcpu]
 */
static VALUE libvirt_dom_pin_vcpu(VALUE s, VALUE vcpu, VALUE cpulist) {
    virDomainPtr dom = domain_get(s);
    int r, i, len, maplen;
    unsigned char *cpumap;
    virNodeInfo nodeinfo;
    virConnectPtr c = conn(s);

    r = virNodeGetInfo(c, &nodeinfo);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", "", c));

    maplen = VIR_CPU_MAPLEN(nodeinfo.cpus);
    cpumap = ALLOC_N(unsigned char, maplen);
    MEMZERO(cpumap, unsigned char, maplen);

    len = RARRAY(cpulist)->len;
    for(i = 0; i < len; i++) {
        VALUE e = rb_ary_entry(cpulist, i);
        VIR_USE_CPU(cpumap, NUM2UINT(e));
    }

    r = virDomainPinVcpu(dom, NUM2UINT(vcpu), cpumap, maplen);
    free(cpumap);
    _E(r < 0, create_error(e_RetrieveError, "virDomainPinVcpu", "", c));

    return Qnil;
}

/*
 * call-seq:
 *   dom.xml_desc -> string
 *
 * Call +virDomainGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetXMLDesc]
 */
static VALUE libvirt_dom_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virDomainGetXMLDesc, conn(s), 1, domain_get(s),
                    NUM2INT(flags));
}

/*
 * call-seq:
 *   dom.undefine -> nil
 *
 * Call +virDomainUndefine+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainUndefine]
 */
static VALUE libvirt_dom_undefine(VALUE s) {
    gen_call_void(virDomainUndefine, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.create -> nil
 *
 * Call +virDomainCreate+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCreate]
 */
static VALUE libvirt_dom_create(VALUE s) {
    gen_call_void(virDomainCreate, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.autostart -> [true|false]
 *
 * Call +virDomainGetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetAutostart]
 */
static VALUE libvirt_dom_autostart(VALUE s){
    virDomainPtr dom = domain_get(s);
    int r, autostart;

    r = virDomainGetAutostart(dom, &autostart);
    _E(r < 0, create_error(e_RetrieveError, "virDomainAutostart", "", conn(s)));

    return autostart ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   dom.autostart_set -> nil
 *
 * Call +virDomainSetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetAutostart]
 */
static VALUE libvirt_dom_autostart_set(VALUE s, VALUE autostart) {
    gen_call_void(virDomainSetAutostart, conn(s),
                  domain_get(s), RTEST(autostart) ? 1 : 0);
}

/*
 * call-seq:
 *   dom.attach_device -> nil
 *
 * Call +virDomainAttachDevice+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainAttachDevice]
 */
static VALUE libvirt_dom_attach_device(VALUE s, VALUE xml) {
    gen_call_void(virDomainAttachDevice, conn(s), domain_get(s),
                  StringValueCStr(xml));
}

/*
 * call-seq:
 *   dom.detach_device -> nil
 *
 * Call +virDomainDetachDevice+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainDetachDevice]
 */
static VALUE libvirt_dom_detach_device(VALUE s, VALUE xml) {
    gen_call_void(virDomainDetachDevice, conn(s), domain_get(s),
                  StringValueCStr(xml));
}

/*
 * call-seq:
 *   dom.free -> nil
 *
 * Call +virDomainFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainFree]
 */
static VALUE libvirt_dom_free(VALUE s) {
    gen_call_free(Domain, s);
}

#if HAVE_TYPE_VIRDOMAINSNAPSHOTPTR
static void domain_snapshot_free(void *d) {
    generic_free(DomainSnapshot, d);
}

static VALUE domain_snapshot_new(virDomainSnapshotPtr d, VALUE domain) {
    VALUE result;
    result = Data_Wrap_Struct(c_domain_snapshot, NULL, domain_snapshot_free, d);
    rb_iv_set(result, "@domain", domain);
    return result;
}

static virDomainSnapshotPtr domain_snapshot_get(VALUE s) {
    generic_get(DomainSnapshot, s);
}

/*
 * call-seq:
 *   dom.snapshot_create_xml -> Libvirt::Domain::Snapshot
 *
 * Call +virDomainSnapshotCreateXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotCreateXML]
 */
static VALUE libvirt_dom_snapshot_create_xml(int argc, VALUE *argv, VALUE d) {
    VALUE xmlDesc, flags;
    virDomainSnapshotPtr ret;

    rb_scan_args(argc, argv, "11", &xmlDesc, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    ret = virDomainSnapshotCreateXML(domain_get(d), StringValueCStr(xmlDesc),
                                     NUM2UINT(flags));

    _E(ret == NULL, create_error(e_Error, "virDomainSnapshotCreateXML", "", conn(d)));

    return domain_snapshot_new(ret, d);
}

/*
 * call-seq:
 *   dom.num_of_snapshots -> fixnum
 *
 * Call +virDomainSnapshotNum+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotNum]
 */
static VALUE libvirt_dom_num_of_snapshots(int argc, VALUE *argv, VALUE d) {
    int result;
    virDomainPtr dom = domain_get(d);
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    result = virDomainSnapshotNum(dom, NUM2UINT(flags));
    _E(result < 0, create_error(e_RetrieveError, "virDomainSnapshotNum", "", conn(d)));
                                                                        \
    return INT2NUM(result);                                             \
}

/*
 * call-seq:
 *   dom.list_snapshots -> list
 *
 * Call +virDomainSnapshotListNames+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotListNames]
 */
static VALUE libvirt_dom_list_snapshots(int argc, VALUE *argv, VALUE d) {
    VALUE flags;
    int r, i;
    int num;
    virDomainPtr dom = domain_get(d);
    char **names;
    VALUE result;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    num = virDomainSnapshotNum(dom, 0);
    _E(num < 0, create_error(e_RetrieveError, "virDomainSnapshotNum", "", conn(d)));
    if (num == 0) {
        /* if num is 0, don't call virDomainSnapshotListNames function */
        result = rb_ary_new2(num);
        return result;
    }
    names = ALLOC_N(char *, num);

    r = virDomainSnapshotListNames(domain_get(d), names, num,
                                   NUM2UINT(flags));
    if (r < 0) {
        free(names);
        rb_raise_exc(create_error(e_RetrieveError, "virDomainSnapshotListNames",
                                  "", conn(d)));
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
 *   dom.lookup_snapshot_by_name -> Libvirt::Domain::Snapshot
 *
 * Call +virDomainSnapshotLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotLookupByName]
 */
static VALUE libvirt_dom_lookup_snapshot_by_name(int argc, VALUE *argv, VALUE d) {
    virDomainPtr dom = domain_get(d);
    virDomainSnapshotPtr snap;
    VALUE name, flags;

    rb_scan_args(argc, argv, "11", &name, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    snap = virDomainSnapshotLookupByName(dom, StringValueCStr(name),
                                         NUM2UINT(flags));
    _E(dom == NULL, create_error(e_RetrieveError, "virDomainSnapshotLookupByName", "", conn(d)));

    return domain_snapshot_new(snap, d);
}

/*
 * call-seq:
 *   dom.has_current_snapshot? -> [true|false]
 *
 * Call +virDomainHasCurrentSnapshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainHasCurrentSnapshot]
 */
static VALUE libvirt_dom_has_current_snapshot_p(int argc, VALUE *argv, VALUE d) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_truefalse(virDomainHasCurrentSnapshot, conn(d), domain_get(d),
                       NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.revert_to_snapshot -> nil
 *
 * Call +virDomainRevertToSnapshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainRevertToSnapshot]
 */
static VALUE libvirt_dom_revert_to_snapshot(int argc, VALUE *argv, VALUE d) {
    VALUE snap, flags;
    int r;

    rb_scan_args(argc, argv, "11", &snap, &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    r = virDomainRevertToSnapshot(domain_snapshot_get(snap), NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virDomainRevertToSnapshot", "", conn(d)));

    return Qnil;
}

/*
 * call-seq:
 *   dom.current_snapshot -> Libvirt::Domain::Snapshot
 *
 * Call +virDomainCurrentSnapshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCurrentSnapshot]
 */
static VALUE libvirt_dom_current_snapshot(int argc, VALUE *argv, VALUE d) {
    VALUE flags;
    virDomainSnapshotPtr snap;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    snap = virDomainSnapshotCurrent(domain_get(d), NUM2UINT(flags));
    _E(snap == NULL, create_error(e_RetrieveError, "virDomainSnapshotCurrent", "", conn(d)));

    return domain_snapshot_new(snap, d);
}

/*
 * call-seq:
 *   snapshot.xml_desc -> string
 *
 * Call +virDomainSnapshotGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotGetXMLDesc]
 */
static VALUE libvirt_dom_snapshot_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_string(virDomainSnapshotGetXMLDesc, conn(s), 1,
                    domain_snapshot_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   snapshot.delete -> nil
 *
 * Call +virDomainSnapshotDelete+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotDelete]
 */
static VALUE libvirt_dom_snapshot_delete(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2FIX(0);

    gen_call_void(virDomainSnapshotDelete, conn(s),
                    domain_snapshot_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   snapshot.free -> nil
 *
 * Call +virDomainSnapshotFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotFree]
 */
static VALUE libvirt_dom_snapshot_free(VALUE s) {
    gen_call_free(DomainSnapshot, s);
}

#endif

#if HAVE_TYPE_VIRDOMAINJOBINFOPTR
/*
 * call-seq:
 *   dom.job_info -> Libvirt::Domain::JobInfo
 *
 * Call +virDomainGetJobInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetJobInfo]
 */
static VALUE libvirt_dom_job_info(VALUE d) {
    int r;
    virDomainJobInfo info;
    VALUE result;

    r = virDomainGetJobInfo(domain_get(d), &info);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetJobInfo", "", conn(d)));

    result = rb_class_new_instance(0, NULL, c_domain_job_info);
    rb_iv_set(result, "@type", INT2NUM(info.type));
    rb_iv_set(result, "@time_elapsed", ULL2NUM(info.timeElapsed));
    rb_iv_set(result, "@time_remaining", ULL2NUM(info.timeRemaining));
    rb_iv_set(result, "@data_total", ULL2NUM(info.dataTotal));
    rb_iv_set(result, "@data_processed", ULL2NUM(info.dataProcessed));
    rb_iv_set(result, "@data_remaining", ULL2NUM(info.dataRemaining));
    rb_iv_set(result, "@mem_total", ULL2NUM(info.memTotal));
    rb_iv_set(result, "@mem_processed", ULL2NUM(info.memProcessed));
    rb_iv_set(result, "@mem_remaining", ULL2NUM(info.memRemaining));
    rb_iv_set(result, "@file_total", ULL2NUM(info.fileTotal));
    rb_iv_set(result, "@file_processed", ULL2NUM(info.fileProcessed));
    rb_iv_set(result, "@file_remaining", ULL2NUM(info.fileRemaining));

    return result;
}

/*
 * call-seq:
 *   dom.abort_job -> nil
 *
 * Call +virDomainAbortJob+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainAbortJob]
 */
static VALUE libvirt_dom_abort_job(VALUE d) {
    gen_call_void(virDomainAbortJob, conn(d), domain_get(d));
}

#endif

/*
 * Class Libvirt::Domain
 */
void init_domain()
{
    c_domain = rb_define_class_under(m_libvirt, "Domain", rb_cObject);

#define DEF_DOMSTATE(name) \
    rb_define_const(c_domain, #name, INT2NUM(VIR_DOMAIN_##name))
    /* virDomainState */
    DEF_DOMSTATE(NOSTATE);
    DEF_DOMSTATE(RUNNING);
    DEF_DOMSTATE(BLOCKED);
    DEF_DOMSTATE(PAUSED);
    DEF_DOMSTATE(SHUTDOWN);
    DEF_DOMSTATE(SHUTOFF);
    DEF_DOMSTATE(CRASHED);
#undef DEF_DOMSTATE

    /* virDomainMigrateFlags */
#ifdef VIR_MIGRATE_LIVE
    rb_define_const(c_domain, "MIGRATE_LIVE", INT2NUM(VIR_MIGRATE_LIVE));
#endif
#ifdef VIR_MIGRATE_PEER2PEER
    rb_define_const(c_domain, "MIGRATE_PEER2PEER",
                    INT2NUM(VIR_MIGRATE_PEER2PEER));
#endif
#ifdef VIR_MIGRATE_TUNNELLED
    rb_define_const(c_domain, "MIGRATE_TUNNELLED",
                    INT2NUM(VIR_MIGRATE_TUNNELLED));
#endif
#ifdef VIR_MIGRATE_PERSIST_DEST
    rb_define_const(c_domain, "MIGRATE_PERSIST_DEST",
                    INT2NUM(VIR_MIGRATE_PERSIST_DEST));
#endif
#ifdef VIR_MIGRATE_UNDEFINE_SOURCE
    rb_define_const(c_domain, "MIGRATE_UNDEFINE_SOURCE",
                    INT2NUM(VIR_MIGRATE_UNDEFINE_SOURCE));
#endif
#ifdef VIR_MIGRATE_PAUSED
    rb_define_const(c_domain, "MIGRATE_PAUSED", INT2NUM(VIR_MIGRATE_PAUSED));
#endif
#ifdef VIR_MIGRATE_NON_SHARED_DISK
    rb_define_const(c_domain, "MIGRATE_NON_SHARED_DISK",
                    INT2NUM(VIR_MIGRATE_NON_SHARED_DISK));
#endif
#ifdef VIR_MIGRATE_NON_SHARED_INC
    rb_define_const(c_domain, "MIGRATE_NON_SHARED_INC",
                    INT2NUM(VIR_MIGRATE_NON_SHARED_INC));
#endif
    /* DomainGetXMLDesc flags */
    rb_define_const(c_domain, "DOMAIN_XML_SECURE",
                    INT2NUM(VIR_DOMAIN_XML_SECURE));
    rb_define_const(c_domain, "DOMAIN_XML_INACTIVE",
                    INT2NUM(VIR_DOMAIN_XML_INACTIVE));
#ifdef VIR_DOMAIN_XML_UPDATE_CPU
    rb_define_const(c_domain, "DOMAIN_XML_UPDATE_CPU",
                    INT2NUM(VIR_DOMAIN_XML_UPDATE_CPU));
#endif
    rb_define_const(c_domain, "MEMORY_VIRTUAL", INT2NUM(VIR_MEMORY_VIRTUAL));
#ifdef VIR_MEMORY_PHYSICAL
    rb_define_const(c_domain, "MEMORY_PHYSICAL", INT2NUM(VIR_MEMORY_PHYSICAL));
#endif

    // Domain creation/lookup
    rb_define_method(c_connect, "num_of_domains",
                     libvirt_conn_num_of_domains, 0);
    rb_define_method(c_connect, "list_domains", libvirt_conn_list_domains, 0);
    rb_define_method(c_connect, "num_of_defined_domains",
                     libvirt_conn_num_of_defined_domains, 0);
    rb_define_method(c_connect, "list_defined_domains",
                     libvirt_conn_list_defined_domains, 0);
    rb_define_method(c_connect, "create_domain_linux",
                     libvirt_conn_create_linux, -1);
    rb_define_method(c_connect, "lookup_domain_by_name",
                     libvirt_conn_lookup_domain_by_name, 1);
    rb_define_method(c_connect, "lookup_domain_by_id",
                     libvirt_conn_lookup_domain_by_id, 1);
    rb_define_method(c_connect, "lookup_domain_by_uuid",
                     libvirt_conn_lookup_domain_by_uuid, 1);
    rb_define_method(c_connect, "define_domain_xml",
                     libvirt_conn_define_domain_xml, 1);

#if HAVE_VIRCONNECTDOMAINXMLFROMNATIVE
    rb_define_method(c_connect, "domain_xml_from_native",
                     libvirt_conn_domain_xml_from_native, -1);
#endif
#if HAVE_VIRCONNECTDOMAINXMLTONATIVE
    rb_define_method(c_connect, "domain_xml_to_native",
                     libvirt_conn_domain_xml_to_native, -1);
#endif

    rb_define_method(c_domain, "migrate", libvirt_dom_migrate, -1);
#if HAVE_VIRDOMAINMIGRATETOURI
    rb_define_method(c_domain, "migrate_to_uri",
                     libvirt_dom_migrate_to_uri, -1);
#endif
#if HAVE_VIRDOMAINMIGRATESETMAXDOWNTIME
    rb_define_method(c_domain, "migrate_set_max_downtime",
                     libvirt_dom_migrate_set_max_downtime, -1);
#endif
    rb_define_attr(c_domain, "connection", 1, 0);
    rb_define_method(c_domain, "shutdown", libvirt_dom_shutdown, 0);
    rb_define_method(c_domain, "reboot", libvirt_dom_reboot, -1);
    rb_define_method(c_domain, "destroy", libvirt_dom_destroy, 0);
    rb_define_method(c_domain, "suspend", libvirt_dom_suspend, 0);
    rb_define_method(c_domain, "resume", libvirt_dom_resume, 0);
    rb_define_method(c_domain, "save", libvirt_dom_save, 1);
    rb_define_singleton_method(c_domain, "restore", libvirt_dom_s_restore, 2);
    rb_define_method(c_domain, "core_dump", libvirt_dom_core_dump, -1);
    rb_define_method(c_domain, "info", libvirt_dom_info, 0);
    rb_define_method(c_domain, "ifinfo", libvirt_dom_if_stats, 1);
    rb_define_method(c_domain, "name", libvirt_dom_name, 0);
    rb_define_method(c_domain, "id", libvirt_dom_id, 0);
    rb_define_method(c_domain, "uuid", libvirt_dom_uuid, 0);
    rb_define_method(c_domain, "os_type", libvirt_dom_os_type, 0);
    rb_define_method(c_domain, "max_memory", libvirt_dom_max_memory, 0);
    rb_define_method(c_domain, "max_memory=", libvirt_dom_max_memory_set, 1);
    rb_define_method(c_domain, "memory=", libvirt_dom_memory_set, 1);
    rb_define_method(c_domain, "max_vcpus", libvirt_dom_max_vcpus, 0);
    rb_define_method(c_domain, "vcpus=", libvirt_dom_vcpus_set, 1);
    rb_define_method(c_domain, "pin_vcpu", libvirt_dom_pin_vcpu, 2);
    rb_define_method(c_domain, "xml_desc", libvirt_dom_xml_desc, -1);
    rb_define_method(c_domain, "undefine", libvirt_dom_undefine, 0);
    rb_define_method(c_domain, "create", libvirt_dom_create, 0);
    rb_define_method(c_domain, "autostart", libvirt_dom_autostart, 0);
    rb_define_method(c_domain, "autostart?", libvirt_dom_autostart, 0);
    rb_define_method(c_domain, "autostart=", libvirt_dom_autostart_set, 1);
    rb_define_method(c_domain, "free", libvirt_dom_free, 0);
    /* FIXME: we should probably allow a "flags" parameter to
     * {attach,detach}_device, and then call
     * virDomain{Attach,Detach}DeviceFlags, where appropriate
     *
     * We should also make the VIR_DOMAIN_DEVICE_MODIFY_* flags consts
     */
    rb_define_method(c_domain, "attach_device", libvirt_dom_attach_device, 1);
    rb_define_method(c_domain, "detach_device", libvirt_dom_detach_device, 1);
    /* FIXME: implement this */
    // rb_define_method(c_domain, "update_device", libvirt_dom_update_device, -1);
    /* FIXME: we should probably do scheduler parameters as hashes.  That is
     * virDomainGetSchedulerParameters should return a hash with all of the
     * parameters, and virDomainSetSchedulerParameters should take a hash
     * of parameters in
     */
    //rb_define_method(c_domain, "get_scheduler_params", libvirt_dom_get_scheduler_params, 0);
    //rb_define_method(c_domain, "set_scheduler_params", libvirt_dom_set_scheduler_params, 0)
#if HAVE_VIRDOMAINMANAGEDSAVE
    rb_define_method(c_domain, "managed_save", libvirt_dom_managed_save, -1);
    rb_define_method(c_domain, "has_managed_save?",
                     libvirt_dom_has_managed_save, -1);
    rb_define_method(c_domain, "managed_save_remove",
                     libvirt_dom_managed_save_remove, -1);
#endif
    rb_define_method(c_domain, "security_label",
                     libvirt_dom_security_label, 0);
    rb_define_method(c_domain, "block_stats", libvirt_dom_block_stats, 1);
#if HAVE_TYPE_VIRDOMAINMEMORYSTATPTR
    rb_define_method(c_domain, "memory_stats", libvirt_dom_memory_stats, -1);
#endif
    rb_define_method(c_domain, "block_peek", libvirt_dom_block_peek, -1);
#if HAVE_TYPE_VIRDOMAINBLOCKINFOPTR
    rb_define_method(c_domain, "blockinfo", libvirt_dom_block_info, -1);
#endif
    rb_define_method(c_domain, "memory_peek", libvirt_dom_memory_peek, -1);
    /* FIXME: implement these */
    //rb_define_method(c_domain, "get_vcpus", libvirt_dom_get_vcpus, 0);
#if HAVE_VIRDOMAINISACTIVE
    rb_define_method(c_domain, "active?", libvirt_dom_active_p, 0);
#endif
#if HAVE_VIRDOMAINISPERSISTENT
    rb_define_method(c_domain, "persistent?", libvirt_dom_persistent_p, 0);
#endif
#if HAVE_TYPE_VIRDOMAINSNAPSHOTPTR
    rb_define_method(c_domain, "snapshot_create_xml",
                     libvirt_dom_snapshot_create_xml, -1);
    rb_define_method(c_domain, "num_of_snapshots",
                     libvirt_dom_num_of_snapshots, -1);
    rb_define_method(c_domain, "list_snapshots",
                     libvirt_dom_list_snapshots, -1);
    rb_define_method(c_domain, "lookup_snapshot_by_name",
                     libvirt_dom_lookup_snapshot_by_name, -1);
    rb_define_method(c_domain, "has_current_snapshot?",
                     libvirt_dom_has_current_snapshot_p, -1);
    rb_define_method(c_domain, "revert_to_snapshot",
                     libvirt_dom_revert_to_snapshot, -1);
    rb_define_method(c_domain, "current_snapshot",
                     libvirt_dom_current_snapshot, -1);
#endif

    /*
     * Class Libvirt::Domain::Info
     */
    c_domain_info = rb_define_class_under(c_domain, "Info", rb_cObject);
    rb_define_attr(c_domain_info, "state", 1, 0);
    rb_define_attr(c_domain_info, "max_mem", 1, 0);
    rb_define_attr(c_domain_info, "memory", 1, 0);
    rb_define_attr(c_domain_info, "nr_virt_cpu", 1, 0);
    rb_define_attr(c_domain_info, "cpu_time", 1, 0);

    /*
     * Class Libvirt::Domain::InterfaceInfo
     */
    c_domain_ifinfo = rb_define_class_under(c_domain, "InterfaceInfo",
                                            rb_cObject);
    rb_define_attr(c_domain_ifinfo, "rx_bytes", 1, 0);
    rb_define_attr(c_domain_ifinfo, "rx_packets", 1, 0);
    rb_define_attr(c_domain_ifinfo, "rx_errs", 1, 0);
    rb_define_attr(c_domain_ifinfo, "rx_drop", 1, 0);
    rb_define_attr(c_domain_ifinfo, "tx_bytes", 1, 0);
    rb_define_attr(c_domain_ifinfo, "tx_packets", 1, 0);
    rb_define_attr(c_domain_ifinfo, "tx_errs", 1, 0);
    rb_define_attr(c_domain_ifinfo, "tx_drop", 1, 0);

    /*
     * Class Libvirt::Domain::SecurityLabel
     */
    c_domain_security_label = rb_define_class_under(c_domain, "SecurityLabel",
                                                    rb_cObject);
    rb_define_attr(c_domain_security_label, "label", 1, 0);
    rb_define_attr(c_domain_security_label, "enforcing", 1, 0);

    /*
     * Class Libvirt::Domain::BlockStats
     */
    c_domain_block_stats = rb_define_class_under(c_domain, "BlockStats",
                                                 rb_cObject);
    rb_define_attr(c_domain_block_stats, "rd_req", 1, 0);
    rb_define_attr(c_domain_block_stats, "rd_bytes", 1, 0);
    rb_define_attr(c_domain_block_stats, "wr_req", 1, 0);
    rb_define_attr(c_domain_block_stats, "wr_bytes", 1, 0);
    rb_define_attr(c_domain_block_stats, "errs", 1, 0);

#if HAVE_TYPE_VIRDOMAINMEMORYSTATPTR
    /*
     * Class Libvirt::Domain::MemoryStats
     */
    c_domain_memory_stats = rb_define_class_under(c_domain, "MemoryStats",
                                                  rb_cObject);
    rb_define_attr(c_domain_memory_stats, "tag", 1, 0);
    rb_define_attr(c_domain_memory_stats, "value", 1, 0);
#endif

#if HAVE_TYPE_VIRDOMAINBLOCKINFOPTR
    /*
     * Class Libvirt::Domain::BlockInfo
     */
    c_domain_block_info = rb_define_class_under(c_domain, "BlockInfo",
                                                rb_cObject);
    rb_define_attr(c_domain_block_info, "capacity", 1, 0);
    rb_define_attr(c_domain_block_info, "allocation", 1, 0);
    rb_define_attr(c_domain_block_info, "physical", 1, 0);
#endif

#if HAVE_TYPE_VIRDOMAINSNAPSHOTPTR
    /*
     * Class Libvirt::Domain::Snapshot
     */
    c_domain_snapshot = rb_define_class_under(c_domain, "Snapshot", rb_cObject);
    rb_define_const(c_domain_snapshot, "DELETE_CHILDREN",
                    INT2NUM(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN));
    rb_define_method(c_domain_snapshot, "xml_desc",
                     libvirt_dom_snapshot_xml_desc, -1);
    rb_define_method(c_domain_snapshot, "delete",
                     libvirt_dom_snapshot_delete, -1);
    rb_define_method(c_domain_snapshot, "free", libvirt_dom_snapshot_free, 0);
#endif

#if HAVE_TYPE_VIRDOMAINJOBINFOPTR
    /*
     * Class Libvirt::Domain::JobInfo
     */
    c_domain_job_info = rb_define_class_under(c_domain, "JobInfo", rb_cObject);
    rb_define_const(c_domain_job_info, "NONE", INT2NUM(VIR_DOMAIN_JOB_NONE));
    rb_define_const(c_domain_job_info, "BOUNDED",
                    INT2NUM(VIR_DOMAIN_JOB_BOUNDED));
    rb_define_const(c_domain_job_info, "UNBOUNDED",
                    INT2NUM(VIR_DOMAIN_JOB_UNBOUNDED));
    rb_define_const(c_domain_job_info, "COMPLETED",
                    INT2NUM(VIR_DOMAIN_JOB_COMPLETED));
    rb_define_const(c_domain_job_info, "FAILED",
                    INT2NUM(VIR_DOMAIN_JOB_FAILED));
    rb_define_const(c_domain_job_info, "CANCELLED",
                    INT2NUM(VIR_DOMAIN_JOB_CANCELLED));
    rb_define_attr(c_domain_job_info, "type", 1, 0);
    rb_define_attr(c_domain_job_info, "time_elapsed", 1, 0);
    rb_define_attr(c_domain_job_info, "time_remaining", 1, 0);
    rb_define_attr(c_domain_job_info, "data_total", 1, 0);
    rb_define_attr(c_domain_job_info, "data_processed", 1, 0);
    rb_define_attr(c_domain_job_info, "data_remaining", 1, 0);
    rb_define_attr(c_domain_job_info, "mem_total", 1, 0);
    rb_define_attr(c_domain_job_info, "mem_processed", 1, 0);
    rb_define_attr(c_domain_job_info, "mem_remaining", 1, 0);
    rb_define_attr(c_domain_job_info, "file_total", 1, 0);
    rb_define_attr(c_domain_job_info, "file_processed", 1, 0);
    rb_define_attr(c_domain_job_info, "file_remaining", 1, 0);

    rb_define_method(c_domain, "job_info", libvirt_dom_job_info, 0);
    rb_define_method(c_domain, "abort_job", libvirt_dom_abort_job, 0);
#endif
}
