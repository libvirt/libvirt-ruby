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

#include <stdint.h>
#include <ruby.h>
#include <st.h>
#include <libvirt/libvirt.h>
#if HAVE_VIRDOMAINQEMUMONITORCOMMAND
#include <libvirt/libvirt-qemu.h>
#endif
#include <libvirt/virterror.h>
#include "common.h"
#include "connect.h"
#include "extconf.h"
#include "stream.h"

#ifndef HAVE_TYPE_VIRTYPEDPARAMETERPTR
#define VIR_TYPED_PARAM_INT VIR_DOMAIN_SCHED_FIELD_INT
#define VIR_TYPED_PARAM_UINT VIR_DOMAIN_SCHED_FIELD_UINT
#define VIR_TYPED_PARAM_LLONG VIR_DOMAIN_SCHED_FIELD_LLONG
#define VIR_TYPED_PARAM_ULLONG VIR_DOMAIN_SCHED_FIELD_ULLONG
#define VIR_TYPED_PARAM_DOUBLE VIR_DOMAIN_SCHED_FIELD_DOUBLE
#define VIR_TYPED_PARAM_BOOLEAN VIR_DOMAIN_SCHED_FIELD_BOOLEAN

#define VIR_TYPED_PARAM_FIELD_LENGTH 80
typedef struct _virTypedParameter virTypedParameter;
struct _virTypedParameter {
    char field[VIR_TYPED_PARAM_FIELD_LENGTH];  /* parameter name */
    int type;   /* parameter type, virTypedParameterType */
    union {
        int i;                      /* type is INT */
        unsigned int ui;            /* type is UINT */
        long long int l;            /* type is LLONG */
        unsigned long long int ul;  /* type is ULLONG */
        double d;                   /* type is DOUBLE */
        char b;                     /* type is BOOLEAN */
    } value; /* parameter value */
};
typedef virTypedParameter *virTypedParameterPtr;

#endif

static VALUE c_domain;
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
static VALUE c_domain_vcpuinfo;
#if HAVE_VIRDOMAINGETCONTROLINFO
static VALUE c_domain_control_info;
#endif

static void domain_free(void *d) {
    generic_free(Domain, d);
}

VALUE domain_new(virDomainPtr d, VALUE conn) {
    return generic_new(c_domain, d, conn, domain_free);
}

virDomainPtr domain_get(VALUE s) {
    generic_get(Domain, s);
}

/*
 * call-seq:
 *   dom.migrate(dconn, flags=0, dname=nil, uri=nil, bandwidth=0) -> Libvirt::Domain
 *
 * Call +virDomainMigrate+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrate]
 * to migrate a domain from the host on this connection to the connection
 * referenced in dconn.
 */
static VALUE libvirt_dom_migrate(int argc, VALUE *argv, VALUE s) {
    VALUE dconn, flags, dname_val, uri_val, bandwidth;
    virDomainPtr ddom = NULL;

    rb_scan_args(argc, argv, "14", &dconn, &flags, &dname_val, &uri_val,
                 &bandwidth);

    if (NIL_P(bandwidth))
        bandwidth = INT2NUM(0);
    if (NIL_P(flags))
        flags = INT2NUM(0);

    ddom = virDomainMigrate(domain_get(s), conn(dconn), NUM2ULONG(flags),
                            get_string_or_nil(dname_val),
                            get_string_or_nil(uri_val), NUM2ULONG(bandwidth));

    _E(ddom == NULL, create_error(e_Error, "virDomainMigrate", conn(s)));

    return domain_new(ddom, dconn);
}

#if HAVE_VIRDOMAINMIGRATETOURI
/*
 * call-seq:
 *   dom.migrate_to_uri(duri, flags=0, dname=nil, bandwidth=0) -> nil
 *
 * Call +virDomainMigrateToURI+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrateToURI]
 * to migrate a domain from the host on this connection to the host whose
 * libvirt URI is duri.
 */
static VALUE libvirt_dom_migrate_to_uri(int argc, VALUE *argv, VALUE s) {
    VALUE duri, flags, dname, bandwidth;

    rb_scan_args(argc, argv, "13", &duri, &flags, &dname, &bandwidth);

    if (NIL_P(bandwidth))
        bandwidth = INT2NUM(0);
    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainMigrateToURI, conn(s), domain_get(s),
                  StringValueCStr(duri), NUM2ULONG(flags),
                  get_string_or_nil(dname), NUM2ULONG(bandwidth));
}
#endif

#if HAVE_VIRDOMAINMIGRATESETMAXDOWNTIME
/*
 * call-seq:
 *   dom.migrate_set_max_downtime(downtime, flags=0) -> nil
 *
 * Call +virDomainMigrateSetMaxDowntime+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrateSetMaxDowntime]
 * to set the maximum downtime desired for live migration.
 */
static VALUE libvirt_dom_migrate_set_max_downtime(int argc, VALUE *argv,
                                                  VALUE s) {
    VALUE downtime, flags;

    rb_scan_args(argc, argv, "11", &downtime, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainMigrateSetMaxDowntime, conn(s), domain_get(s),
                  NUM2ULL(downtime), NUM2UINT(flags));
}
#endif

#if HAVE_VIRDOMAINMIGRATE2
/*
 * call-seq:
 *   dom.migrate2(dconn, dxml=nil, flags=0, dname=nil, uri=nil, bandwidth=0) -> Libvirt::Domain
 *
 * Call +virDomainMigrate2+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrate2]
 * to migrate a domain from the host on this connection to the connection
 * referenced in dconn.
 */
static VALUE libvirt_dom_migrate2(int argc, VALUE *argv, VALUE s) {
    VALUE dconn, dxml, flags, dname_val, uri_val, bandwidth;
    virDomainPtr ddom = NULL;

    rb_scan_args(argc, argv, "15", &dconn, &dxml, &flags, &dname_val, &uri_val,
                 &bandwidth);

    if (NIL_P(bandwidth))
        bandwidth = INT2NUM(0);
    if (NIL_P(flags))
        flags = INT2NUM(0);

    ddom = virDomainMigrate2(domain_get(s), conn(dconn),
                             get_string_or_nil(dxml), NUM2ULONG(flags),
                             get_string_or_nil(dname_val),
                             get_string_or_nil(uri_val), NUM2ULONG(bandwidth));

    _E(ddom == NULL, create_error(e_Error, "virDomainMigrate2", conn(s)));

    return domain_new(ddom, dconn);
}

/*
 * call-seq:
 *   dom.migrate_to_uri2(duri=nil, migrate_uri=nil, dxml=nil, flags=0, dname=nil, bandwidth=0) -> nil
 *
 * Call +virDomainMigrateToURI2+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrateToURI2]
 * to migrate a domain from the host on this connection to the host whose
 * libvirt URI is duri.
 */
static VALUE libvirt_dom_migrate_to_uri2(int argc, VALUE *argv, VALUE s) {
    VALUE duri, migrate_uri, dxml, flags, dname, bandwidth;

    rb_scan_args(argc, argv, "06", &duri, &migrate_uri, &dxml, &flags, &dname,
                 &bandwidth);

    if (NIL_P(bandwidth))
        bandwidth = INT2NUM(0);
    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainMigrateToURI2, conn(s), domain_get(s),
                  get_string_or_nil(duri), get_string_or_nil(migrate_uri),
                  get_string_or_nil(dxml), NUM2ULONG(flags),
                  get_string_or_nil(dname), NUM2ULONG(bandwidth));
}

/*
 * call-seq:
 *   dom.migrate_set_max_speed(bandwidth, flags=0) -> nil
 *
 * Call +virDomainMigrateSetMaxSpeed+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMigrateSetMaxSpeed]
 * to set the maximum bandwidth allowed for live migration.
 */
static VALUE libvirt_dom_migrate_set_max_speed(int argc, VALUE *argv, VALUE s) {
    VALUE bandwidth, flags;

    rb_scan_args(argc, argv, "11", &bandwidth, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainMigrateSetMaxSpeed, conn(s), domain_get(s),
                  NUM2ULONG(bandwidth), NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   dom.shutdown -> nil
 *
 * Call +virDomainShutdown+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainShutdown]
 * to do a soft shutdown of the domain.  The mechanism for doing the shutdown
 * is hypervisor specific, and may require software running inside the domain
 * to succeed.
 */
static VALUE libvirt_dom_shutdown(VALUE s) {
    gen_call_void(virDomainShutdown, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.reboot(flags=0) -> nil
 *
 * Call +virDomainReboot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainReboot]
 * to do a reboot of the domain.
 */
static VALUE libvirt_dom_reboot(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainReboot, conn(s), domain_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.destroy -> nil
 *
 * Call +virDomainDestroy+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainDestroy]
 * to do a hard power-off of the domain.
 */
static VALUE libvirt_dom_destroy(VALUE s) {
    gen_call_void(virDomainDestroy, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.suspend -> nil
 *
 * Call +virDomainSuspend+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSuspend]
 * to stop the domain from executing.  The domain will still continue to
 * consume memory, but will not take any CPU time.
 */
static VALUE libvirt_dom_suspend(VALUE s) {
    gen_call_void(virDomainSuspend, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.resume -> nil
 *
 * Call +virDomainResume+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainResume]
 * to resume a suspended domain.  After this call the domain will start
 * consuming CPU resources again.
 */
static VALUE libvirt_dom_resume(VALUE s) {
    gen_call_void(virDomainResume, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.save(filename) -> nil
 *
 * Call +virDomainSave+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSave]
 * to save the domain state to filename.  After this call, the domain will no
 * longer be consuming any resources.
 */
static VALUE libvirt_dom_save(VALUE s, VALUE to) {
    gen_call_void(virDomainSave, conn(s), domain_get(s), StringValueCStr(to));
}

#if HAVE_VIRDOMAINMANAGEDSAVE
/*
 * call-seq:
 *   dom.managed_save(flags=0) -> nil
 *
 * Call +virDomainManagedSave+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainManagedSave]
 * to do a managed save of the domain.  The domain will be saved to a place
 * of libvirt's choosing.
 */
static VALUE libvirt_dom_managed_save(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainManagedSave, conn(s), domain_get(s),
                  NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.has_managed_save?(flags=0) -> [True|False]
 *
 * Call +virDomainHasManagedSaveImage+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainHasManagedSaveImage]
 * to determine if a particular domain has a managed save image.
 */
static VALUE libvirt_dom_has_managed_save(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_truefalse(virDomainHasManagedSaveImage, conn(s), domain_get(s),
                       NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.managed_save_remove(flags=0) -> nil
 *
 * Call +virDomainManagedSaveRemove+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainManagedSaveRemove]
 * to remove the managed save image for a domain.
 */
static VALUE libvirt_dom_managed_save_remove(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainManagedSaveRemove, conn(s), domain_get(s),
                  NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   dom.core_dump(filename, flags=0) -> nil
 *
 * Call +virDomainCoreDump+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCoreDump]
 * to do a full memory dump of the domain to filename.
 */
static VALUE libvirt_dom_core_dump(int argc, VALUE *argv, VALUE s) {
    VALUE to, flags;

    rb_scan_args(argc, argv, "11", &to, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainCoreDump, conn(s), domain_get(s),
                  StringValueCStr(to), NUM2INT(flags));
}

/*
 * call-seq:
 *   dom.restore(filename) -> nil
 *
 * Call +virDomainRestore+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainRestore]
 * to restore the domain from the filename.
 */
static VALUE libvirt_dom_restore(VALUE s, VALUE from) {
    gen_call_void(virDomainRestore, conn(s), connect_get(s),
                  StringValueCStr(from));
}

/*
 * call-seq:
 *   Libvirt::Domain::restore(conn, filename) -> nil
 *
 * Call +virDomainRestore+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainRestore]
 * to restore the domain from the filename.
 */
static VALUE libvirt_dom_s_restore(VALUE klass, VALUE c, VALUE from) {
    gen_call_void(virDomainRestore, conn(c), connect_get(c),
                  StringValueCStr(from));
}

/*
 * call-seq:
 *   dom.info -> Libvirt::Domain::Info
 *
 * Call +virDomainGetInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetInfo]
 * to retrieve domain information.
 */
static VALUE libvirt_dom_info(VALUE s) {
    virDomainPtr dom = domain_get(s);
    virDomainInfo info;
    int r;
    VALUE result;

    r = virDomainGetInfo(dom, &info);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetInfo", conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_info);
    rb_iv_set(result, "@state", CHR2FIX(info.state));
    rb_iv_set(result, "@max_mem", ULONG2NUM(info.maxMem));
    rb_iv_set(result, "@memory", ULONG2NUM(info.memory));
    rb_iv_set(result, "@nr_virt_cpu", INT2NUM((int) info.nrVirtCpu));
    rb_iv_set(result, "@cpu_time", ULL2NUM(info.cpuTime));

    return result;
}

#if HAVE_VIRDOMAINGETSECURITYLABEL
/*
 * call-seq:
 *   dom.security_label -> Libvirt::Domain::SecurityLabel
 *
 * Call +virDomainGetSecurityLabel+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetSecurityLabel]
 * to retrieve the security label applied to this domain.
 */
static VALUE libvirt_dom_security_label(VALUE s) {
    virDomainPtr dom = domain_get(s);
    virSecurityLabel seclabel;
    int r;
    VALUE result;

    r = virDomainGetSecurityLabel(dom, &seclabel);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetSecurityLabel",
                           conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_security_label);
    rb_iv_set(result, "@label", rb_str_new2(seclabel.label));
    rb_iv_set(result, "@enforcing", INT2NUM(seclabel.enforcing));

    return result;
}
#endif

/*
 * call-seq:
 *   dom.block_stats(path) -> Libvirt::Domain::BlockStats
 *
 * Call +virDomainBlockStats+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainBlockStats]
 * to retrieve statistics about domain block device path.
 */
static VALUE libvirt_dom_block_stats(VALUE s, VALUE path) {
    virDomainPtr dom = domain_get(s);
    virDomainBlockStatsStruct stats;
    int r;
    VALUE result;

    r = virDomainBlockStats(dom, StringValueCStr(path), &stats, sizeof(stats));
    _E(r < 0, create_error(e_RetrieveError, "virDomainBlockStats", conn(s)));

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
 *   dom.memory_stats(flags=0) -> [ Libvirt::Domain::MemoryStats ]
 *
 * Call +virDomainMemoryStats+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMemoryStats]
 * to retrieve statistics about the amount of memory consumed by a domain.
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
        flags = INT2NUM(0);

    r = virDomainMemoryStats(dom, stats, 6, NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virDomainMemoryStats", conn(s)));

    /* FIXME: the right rubyish way to have done this would have been to
     * create a hash with the values, something like:
     *
     * { 'SWAP_IN' => 0, 'SWAP_OUT' => 98, 'MAJOR_FAULT' => 45,
     *   'MINOR_FAULT' => 55, 'UNUSED' => 455, 'AVAILABLE' => 98 }
     *
     * Unfortunately this has already been released with the array version
     * so we have to maintain compatibility with that.  We should probably add
     * a new memory_stats-like call that properly creates the hash.
     */
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
 *   dom.blockinfo(path, flags=0) -> Libvirt::Domain::BlockInfo
 *
 * Call +virDomainGetBlockInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetBlockInfo]
 * to retrieve information about the backing file path for the domain.
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
        flags = INT2NUM(0);

    r = virDomainGetBlockInfo(dom, StringValueCStr(path), &info,
                              NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetBlockInfo", conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_block_info);
    rb_iv_set(result, "@capacity", ULL2NUM(info.capacity));
    rb_iv_set(result, "@allocation", ULL2NUM(info.allocation));
    rb_iv_set(result, "@physical", ULL2NUM(info.physical));

    return result;
}
#endif

#if HAVE_VIRDOMAINBLOCKPEEK
/*
 * call-seq:
 *   dom.block_peek(path, offset, size, flags=0) -> string
 *
 * Call +virDomainBlockPeek+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainBlockPeek]
 * to read size number of bytes, starting at offset offset from domain backing
 * file path.  Due to limitations of the libvirt remote protocol, the user
 * should never request more than 64k bytes.
 */
static VALUE libvirt_dom_block_peek(int argc, VALUE *argv, VALUE s) {
    virDomainPtr dom = domain_get(s);
    VALUE path_val, offset_val, size_val, flags_val;
    char *buffer;
    int r;
    VALUE ret;
    char *path;
    unsigned int size, flags;
    unsigned long long offset;
    struct rb_str_new_arg args;
    int exception = 0;

    rb_scan_args(argc, argv, "31", &path_val, &offset_val, &size_val,
                 &flags_val);

    if (NIL_P(flags_val))
        flags_val = INT2NUM(0);

    path = StringValueCStr(path_val);
    offset = NUM2ULL(offset_val);
    size = NUM2UINT(size_val);
    flags = NUM2UINT(flags_val);

    buffer = ALLOC_N(char, size);

    r = virDomainBlockPeek(dom, path, offset, size, buffer, flags);

    if (r < 0) {
        xfree(buffer);
        rb_exc_raise(create_error(e_RetrieveError, "virDomainBlockPeek",
                                  conn(s)));
    }

    args.val = buffer;
    args.size = size;
    ret = rb_protect(rb_str_new_wrap, (VALUE)&args, &exception);
    xfree(buffer);
    if (exception)
        rb_jump_tag(exception);

    return ret;
}
#endif

#if HAVE_VIRDOMAINMEMORYPEEK
/*
 * call-seq:
 *   dom.memory_peek(start, size, flags=Libvirt::Domain::MEMORY_VIRTUAL) -> string
 *
 * Call +virDomainMemoryPeek+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainMemoryPeek]
 * to read size number of bytes from offset start from the domain memory.
 * Due to limitations of the libvirt remote protocol, the user
 * should never request more than 64k bytes.
 */
static VALUE libvirt_dom_memory_peek(int argc, VALUE *argv, VALUE s) {
    virDomainPtr dom = domain_get(s);
    VALUE start_val, size_val, flags_val;
    char *buffer;
    int r;
    VALUE ret;
    unsigned int size, flags;
    unsigned long long start;
    struct rb_str_new_arg args;
    int exception = 0;

    rb_scan_args(argc, argv, "21", &start_val, &size_val, &flags_val);

    if (NIL_P(flags_val))
        flags_val = INT2NUM(VIR_MEMORY_VIRTUAL);

    start = NUM2UINT(start_val);
    size = NUM2UINT(size_val);
    flags = NUM2UINT(flags_val);

    buffer = ALLOC_N(char, size);

    r = virDomainMemoryPeek(dom, start, size, buffer, flags);

    if (r < 0) {
        xfree(buffer);
        rb_exc_raise(create_error(e_RetrieveError, "virDomainMemoryPeek",
                                  conn(s)));
    }

    args.val = buffer;
    args.size = size;
    ret = rb_protect(rb_str_new_wrap, (VALUE)&args, &exception);
    xfree(buffer);
    if (exception)
        rb_jump_tag(exception);

    return ret;
}
#endif

struct create_vcpu_array_args {
    virVcpuInfoPtr cpuinfo;
    unsigned char *cpumap;
    int nr_virt_cpu;
    int maxcpus;
};

static VALUE create_vcpu_array(VALUE input) {
    struct create_vcpu_array_args *args;
    VALUE result;
    int i;
    VALUE vcpuinfo;
    VALUE p2vcpumap;
    int j;

    args = (struct create_vcpu_array_args *)input;

    result = rb_ary_new();

    for (i = 0; i < args->nr_virt_cpu; i++) {
        vcpuinfo = rb_class_new_instance(0, NULL, c_domain_vcpuinfo);
        rb_iv_set(vcpuinfo, "@number", UINT2NUM((args->cpuinfo)[i].number));
        rb_iv_set(vcpuinfo, "@state", INT2NUM((args->cpuinfo)[i].state));
        rb_iv_set(vcpuinfo, "@cpu_time", ULL2NUM((args->cpuinfo)[i].cpuTime));
        rb_iv_set(vcpuinfo, "@cpu", INT2NUM((args->cpuinfo)[i].cpu));

        p2vcpumap = rb_ary_new();

        for (j = 0; j < args->maxcpus; j++)
            rb_ary_push(p2vcpumap,
                        (VIR_CPU_USABLE(args->cpumap,
                                        VIR_CPU_MAPLEN(args->maxcpus), i, j)) ? Qtrue : Qfalse);
        rb_iv_set(vcpuinfo, "@cpumap", p2vcpumap);

        rb_ary_push(result, vcpuinfo);
    }

    return result;
}

/* call-seq:
 *   dom.get_vcpus -> [ Libvirt::Domain::VCPUInfo ]
 *
 * Call +virDomainGetVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetVcpus]
 * to retrieve detailed information about the state of a domain's virtual CPUs.
 */
static VALUE libvirt_dom_get_vcpus(VALUE s) {
    virDomainPtr dom = domain_get(s);
    virNodeInfo nodeinfo;
    virDomainInfo dominfo;
    virVcpuInfoPtr cpuinfo;
    unsigned char *cpumap;
    int cpumaplen;
    int r;
    VALUE result;
    int exception = 0;
    struct create_vcpu_array_args args;

    r = virNodeGetInfo(conn(s), &nodeinfo);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", conn(s)));

    r = virDomainGetInfo(dom, &dominfo);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetInfo", conn(s)));

    cpuinfo = ALLOC_N(virVcpuInfo, dominfo.nrVirtCpu);

    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));

    /* we use malloc instead of ruby_xmalloc here to avoid a memory leak
     * if ruby_xmalloc raises an exception
     */
    cpumap = malloc(dominfo.nrVirtCpu * cpumaplen);
    if (cpumap == NULL) {
        xfree(cpuinfo);
        rb_memerror();
    }

    r = virDomainGetVcpus(dom, cpuinfo, dominfo.nrVirtCpu, cpumap, cpumaplen);
    if (r < 0) {
        xfree(cpuinfo);
        free(cpumap);
        rb_exc_raise(create_error(e_RetrieveError, "virDomainGetVcpus",
                                  conn(s)));
    }

    args.cpuinfo = cpuinfo;
    args.cpumap = cpumap;
    args.nr_virt_cpu = dominfo.nrVirtCpu;
    args.maxcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    result = rb_protect(create_vcpu_array, (VALUE)&args, &exception);
    if (exception) {
        xfree(cpuinfo);
        free(cpumap);
        rb_jump_tag(exception);
    }

    free(cpumap);
    xfree(cpuinfo);

    return result;
}

#if HAVE_VIRDOMAINISACTIVE
/*
 * call-seq:
 *   dom.active? -> [true|false]
 *
 * Call +virDomainIsActive+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainIsActive]
 * to determine if this domain is currently active.
 */
static VALUE libvirt_dom_active_p(VALUE d) {
    gen_call_truefalse(virDomainIsActive, conn(d), domain_get(d));
}
#endif

#if HAVE_VIRDOMAINISPERSISTENT
/*
 * call-seq:
 *   dom.persistent? -> [true|false]
 *
 * Call +virDomainIsPersistent+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainIsPersistent]
 * to determine if this is a persistent domain.
 */
static VALUE libvirt_dom_persistent_p(VALUE d) {
    gen_call_truefalse(virDomainIsPersistent, conn(d), domain_get(d));
}
#endif

/*
 * call-seq:
 *   dom.ifinfo(if) -> Libvirt::Domain::IfInfo
 *
 * Call +virDomainInterfaceStats+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainInterfaceStats]
 * to retrieve statistics about domain interface if.
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
        _E(r < 0, create_error(e_RetrieveError, "virDomainInterfaceStats",
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
 * to retrieve the name of this domain.
 */
static VALUE libvirt_dom_name(VALUE s) {
    gen_call_string(virDomainGetName, conn(s), 0, domain_get(s));
}

/*
 * call-seq:
 *   dom.id -> fixnum
 *
 * Call +virDomainGetID+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetID]
 * to retrieve the ID of this domain.  If the domain isn't running, this will
 * be -1.
 */
static VALUE libvirt_dom_id(VALUE s) {
    virDomainPtr dom = domain_get(s);
    unsigned int id;
    int out;

    id = virDomainGetID(dom);

    /* we need to cast the unsigned int id to a signed int out to handle the
     * -1 case
     */
    out = id;
    _E(out == -1, create_error(e_RetrieveError, "virDomainGetID", conn(s)));

    return INT2NUM(out);
}

/*
 * call-seq:
 *   dom.uuid -> string
 *
 * Call +virDomainGetUUIDString+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetUUIDString]
 * to retrieve the UUID of this domain.
 */
static VALUE libvirt_dom_uuid(VALUE s) {
    virDomainPtr dom = domain_get(s);
    char uuid[VIR_UUID_STRING_BUFLEN];
    int r;

    r = virDomainGetUUIDString(dom, uuid);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetUUIDString", conn(s)));

    return rb_str_new2((char *) uuid);
}

/*
 * call-seq:
 *   dom.os_type -> string
 *
 * Call +virDomainGetOSType+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetOSType]
 * to retrieve the os_type of this domain.  In libvirt terms, os_type determines
 * whether this domain is fully virtualized, paravirtualized, or a container.
 */
static VALUE libvirt_dom_os_type(VALUE s) {
    gen_call_string(virDomainGetOSType, conn(s), 1, domain_get(s));
}

/*
 * call-seq:
 *   dom.max_memory -> fixnum
 *
 * Call +virDomainGetMaxMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetMaxMemory]
 * to retrieve the maximum amount of memory this domain is allowed to access.
 * Note that the current amount of memory this domain is allowed to access may
 * be different (see dom.memory_set).
 */
static VALUE libvirt_dom_max_memory(VALUE s) {
    virDomainPtr dom = domain_get(s);
    unsigned long max_memory;

    max_memory = virDomainGetMaxMemory(dom);
    _E(max_memory == 0, create_error(e_RetrieveError, "virDomainGetMaxMemory",
                                     conn(s)));

    return ULONG2NUM(max_memory);
}

/*
 * call-seq:
 *   dom.max_memory = Fixnum
 *
 * Call +virDomainSetMaxMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetMaxMemory]
 * to set the maximum amount of memory (in kilobytes) this domain should be
 * allowed to access.
 */
static VALUE libvirt_dom_max_memory_set(VALUE s, VALUE max_memory) {
    virDomainPtr dom = domain_get(s);
    int r;

    r = virDomainSetMaxMemory(dom, NUM2ULONG(max_memory));
    _E(r < 0, create_error(e_DefinitionError, "virDomainSetMaxMemory",
                           conn(s)));

    return ULONG2NUM(max_memory);
}

/*
 * call-seq:
 *   dom.memory = Fixnum,flags=0
 *
 * Call +virDomainSetMemory+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetMemory]
 * to set the amount of memory (in kilobytes) this domain should currently
 * have.  Note this will only succeed if both the hypervisor and the domain on
 * this connection support ballooning.
 */
static VALUE libvirt_dom_memory_set(VALUE s, VALUE in) {
    VALUE memory;
    VALUE flags;
    virDomainPtr dom = domain_get(s);
    int r;

    if (TYPE(in) == T_FIXNUM) {
        memory = in;
        flags = INT2NUM(0);
    }
    else if (TYPE(in) == T_ARRAY) {
        if (RARRAY_LEN(in) != 2)
            rb_raise(rb_eArgError, "wrong number of arguments (%d for 1 or 2)",
                     RARRAY_LEN(in));
        memory = rb_ary_entry(in, 0);
        flags = rb_ary_entry(in, 1);
    }
    else
        rb_raise(rb_eTypeError,
                 "wrong argument type (expected Number or Array)");

#if HAVE_VIRDOMAINSETMEMORYFLAGS
    r = virDomainSetMemoryFlags(dom, NUM2ULONG(memory), NUM2UINT(flags));
    _E(r < 0, create_error(e_DefinitionError, "virDomainSetMemoryFlags",
                           conn(s)));
#else
    if (NUM2UINT(flags) != 0)
        rb_raise(e_NoSupportError, "Non-zero flags not supported");
    r = virDomainSetMemory(dom, NUM2ULONG(memory));
    _E(r < 0, create_error(e_DefinitionError, "virDomainSetMemory", conn(s)));
#endif

    return ULONG2NUM(memory);
}

/*
 * call-seq:
 *   dom.max_vcpus -> fixnum
 *
 * Call +virDomainGetMaxVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetMaxVcpus]
 * to retrieve the maximum number of virtual CPUs this domain can use.
 */
static VALUE libvirt_dom_max_vcpus(VALUE s) {
    gen_call_int(virDomainGetMaxVcpus, conn(s), domain_get(s));
}

#if HAVE_VIRDOMAINGETVCPUSFLAGS
/* call-seq:
 *   dom.num_vcpus(flags) -> fixnum
 *
 * Call +virDomainGetVcpusFlags+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetVcpusFlags]
 * to retrieve the number of virtual CPUs assigned to this domain.
 */
static VALUE libvirt_dom_num_vcpus(VALUE d, VALUE flags) {
    gen_call_int(virDomainGetVcpusFlags, conn(d), domain_get(d),
                 NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   dom.vcpus = Fixnum
 *
 * Call +virDomainSetVcpus+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetVcpus]
 * to set the current number of virtual CPUs this domain should have.  Note
 * that this will only work if both the hypervisor and domain on this
 * connection support virtual CPU hotplug/hot-unplug.
 */
static VALUE libvirt_dom_vcpus_set(VALUE s, VALUE nvcpus) {
    gen_call_void(virDomainSetVcpus, conn(s), domain_get(s), NUM2UINT(nvcpus));
}

#if HAVE_VIRDOMAINSETVCPUSFLAGS
/*
 * call-seq:
 *   dom.vcpus_flags = Fixnum,flags
 *
 * Call +virDomainSetVcpusFlags+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetVcpusFlags]
 * to set the current number of virtual CPUs this domain should have.  The
 * flags parameter controls whether the change is made to the running domain
 * the domain configuration, or both, and must not be 0.
 */
static VALUE libvirt_dom_vcpus_set_flags(VALUE s, VALUE vcpus) {
    VALUE nvcpus;
    VALUE flags;

    Check_Type(vcpus, T_ARRAY);

    if (RARRAY_LEN(vcpus) != 2)
        rb_raise(rb_eArgError, "wrong number of arguments (%d for 2)",
                 RARRAY_LEN(vcpus));

    nvcpus = rb_ary_entry(vcpus, 0);
    flags = rb_ary_entry(vcpus, 1);

    gen_call_void(virDomainSetVcpusFlags, conn(s), domain_get(s),
                  NUM2UINT(nvcpus), NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   dom.pin_vcpu(vcpu, cpulist) -> nil
 *
 * Call +virDomainPinVcpu+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainPinVcpu]
 * to pin a particular virtual CPU to a range of physical processors.  The
 * cpulist should be an array of Fixnums representing the physical processors
 * this virtual CPU should be allowed to be scheduled on.
 */
static VALUE libvirt_dom_pin_vcpu(VALUE s, VALUE vcpu, VALUE cpulist) {
    virDomainPtr dom = domain_get(s);
    int r, i, len, maplen;
    unsigned char *cpumap;
    virNodeInfo nodeinfo;
    virConnectPtr c = conn(s);
    unsigned int vcpunum;

    vcpunum = NUM2UINT(vcpu);
    Check_Type(cpulist, T_ARRAY);

    r = virNodeGetInfo(c, &nodeinfo);
    _E(r < 0, create_error(e_RetrieveError, "virNodeGetInfo", c));

    maplen = VIR_CPU_MAPLEN(nodeinfo.cpus);
    cpumap = ALLOC_N(unsigned char, maplen);
    MEMZERO(cpumap, unsigned char, maplen);

    len = RARRAY_LEN(cpulist);
    for(i = 0; i < len; i++) {
        VALUE e = rb_ary_entry(cpulist, i);
        VIR_USE_CPU(cpumap, NUM2UINT(e));
    }

    r = virDomainPinVcpu(dom, vcpunum, cpumap, maplen);
    xfree(cpumap);
    _E(r < 0, create_error(e_RetrieveError, "virDomainPinVcpu", c));

    return Qnil;
}

/*
 * call-seq:
 *   dom.xml_desc(flags=0) -> string
 *
 * Call +virDomainGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetXMLDesc]
 * to retrieve the XML describing this domain.
 */
static VALUE libvirt_dom_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_string(virDomainGetXMLDesc, conn(s), 1, domain_get(s),
                    NUM2INT(flags));
}

/*
 * call-seq:
 *   dom.undefine -> nil
 *
 * Call +virDomainUndefine+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainUndefine]
 * to undefine the domain.  After this call, the domain object is no longer
 * valid.
 */
static VALUE libvirt_dom_undefine(VALUE s) {
    gen_call_void(virDomainUndefine, conn(s), domain_get(s));
}

/*
 * call-seq:
 *   dom.create(flags=0) -> nil
 *
 * Call +virDomainCreate+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCreate]
 * to start an already defined domain.
 */
static VALUE libvirt_dom_create(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

#if HAVE_VIRDOMAINCREATEWITHFLAGS
    gen_call_void(virDomainCreateWithFlags, conn(s), domain_get(s),
                  NUM2UINT(flags));
#else
    if (NUM2UINT(flags) != 0)
        rb_raise(e_NoSupportError, "Non-zero flags not supported");
    gen_call_void(virDomainCreate, conn(s), domain_get(s));
#endif
}

/*
 * call-seq:
 *   dom.autostart -> [true|false]
 *
 * Call +virDomainGetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetAutostart]
 * to find out the state of the autostart flag for a domain.
 */
static VALUE libvirt_dom_autostart(VALUE s){
    virDomainPtr dom = domain_get(s);
    int r, autostart;

    r = virDomainGetAutostart(dom, &autostart);
    _E(r < 0, create_error(e_RetrieveError, "virDomainAutostart", conn(s)));

    return autostart ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   dom.autostart = [true|false]
 *
 * Call +virDomainSetAutostart+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetAutostart]
 * to make this domain autostart when libvirtd starts up.
 */
static VALUE libvirt_dom_autostart_set(VALUE s, VALUE autostart) {
    if (autostart != Qtrue && autostart != Qfalse)
		rb_raise(rb_eTypeError,
                 "wrong argument type (expected TrueClass or FalseClass)");

    gen_call_void(virDomainSetAutostart, conn(s),
                  domain_get(s), RTEST(autostart) ? 1 : 0);
}

/*
 * call-seq:
 *   dom.attach_device(device_xml, flags=0) -> nil
 *
 * Call +virDomainAttachDevice+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainAttachDevice]
 * to attach the device described by the device_xml to the domain.
 */
static VALUE libvirt_dom_attach_device(int argc, VALUE *argv, VALUE s) {
    VALUE xml;
    VALUE flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

#if HAVE_VIRDOMAINATTACHDEVICEFLAGS
    gen_call_void(virDomainAttachDeviceFlags, conn(s), domain_get(s),
                  StringValueCStr(xml), NUM2UINT(flags));
#else
    if (NUM2UINT(flags) != 0)
        rb_raise(e_NoSupportError, "Non-zero flags not supported");
    gen_call_void(virDomainAttachDevice, conn(s), domain_get(s),
                  StringValueCStr(xml));
#endif
}

/*
 * call-seq:
 *   dom.detach_device(device_xml, flags=0) -> nil
 *
 * Call +virDomainDetachDevice+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainDetachDevice]
 * to detach the device described by the device_xml from the domain.
 */
static VALUE libvirt_dom_detach_device(int argc, VALUE *argv, VALUE s) {
    VALUE xml;
    VALUE flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

#if HAVE_VIRDOMAINDETACHDEVICEFLAGS
    gen_call_void(virDomainDetachDeviceFlags, conn(s), domain_get(s),
                  StringValueCStr(xml), NUM2UINT(flags));
#else
    if (NUM2UINT(flags) != 0)
        rb_raise(e_NoSupportError, "Non-zero flags not supported");
    gen_call_void(virDomainDetachDevice, conn(s), domain_get(s),
                  StringValueCStr(xml));
#endif
}

#if HAVE_VIRDOMAINUPDATEDEVICEFLAGS
/*
 * call-seq:
 *   dom.update_device(device_xml, flags=0) -> nil
 *
 * Call +virDomainUpdateDeviceFlags+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainUpdateDeviceFlags]
 * to update the device described by the device_xml.
 */
static VALUE libvirt_dom_update_device(int argc, VALUE *argv, VALUE s) {
    VALUE xml;
    VALUE flags;

    rb_scan_args(argc, argv, "11", &xml, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainUpdateDeviceFlags, conn(s), domain_get(s),
                  StringValueCStr(xml), NUM2UINT(flags));
}
#endif

/*
 * call-seq:
 *   dom.free -> nil
 *
 * Call +virDomainFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainFree]
 * to free a domain object.
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
 *   dom.snapshot_create_xml(snapshot_xml, flags=0) -> Libvirt::Domain::Snapshot
 *
 * Call +virDomainSnapshotCreateXML+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotCreateXML]
 * to create a new snapshot based on snapshot_xml.
 */
static VALUE libvirt_dom_snapshot_create_xml(int argc, VALUE *argv, VALUE d) {
    VALUE xmlDesc, flags;
    virDomainSnapshotPtr ret;

    rb_scan_args(argc, argv, "11", &xmlDesc, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    ret = virDomainSnapshotCreateXML(domain_get(d), StringValueCStr(xmlDesc),
                                     NUM2UINT(flags));

    _E(ret == NULL, create_error(e_Error, "virDomainSnapshotCreateXML",
                                 conn(d)));

    return domain_snapshot_new(ret, d);
}

/*
 * call-seq:
 *   dom.num_of_snapshots(flags=0) -> fixnum
 *
 * Call +virDomainSnapshotNum+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotNum]
 * to retrieve the number of available snapshots for this domain.
 */
static VALUE libvirt_dom_num_of_snapshots(int argc, VALUE *argv, VALUE d) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_int(virDomainSnapshotNum, conn(d), domain_get(d),
                 NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.list_snapshots(flags=0) -> list
 *
 * Call +virDomainSnapshotListNames+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotListNames]
 * to retrieve a list of snapshot names available for this domain.
 */
static VALUE libvirt_dom_list_snapshots(int argc, VALUE *argv, VALUE d) {
    VALUE flags_val;
    int r;
    int num;
    virDomainPtr dom = domain_get(d);
    char **names;
    unsigned int flags;

    rb_scan_args(argc, argv, "01", &flags_val);

    if (NIL_P(flags_val))
        flags = 0;
    else
        flags = NUM2UINT(flags_val);

    num = virDomainSnapshotNum(dom, 0);
    _E(num < 0, create_error(e_RetrieveError, "virDomainSnapshotNum", conn(d)));
    if (num == 0)
        /* if num is 0, don't call virDomainSnapshotListNames function */
        return rb_ary_new2(num);

    names = ALLOC_N(char *, num);

    r = virDomainSnapshotListNames(domain_get(d), names, num, flags);
    if (r < 0) {
        xfree(names);
        rb_exc_raise(create_error(e_RetrieveError, "virDomainSnapshotListNames",
                                  conn(d)));
    }

    return gen_list(num, &names);
}

/*
 * call-seq:
 *   dom.lookup_snapshot_by_name(name, flags=0) -> Libvirt::Domain::Snapshot
 *
 * Call +virDomainSnapshotLookupByName+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotLookupByName]
 * to retrieve a snapshot object corresponding to snapshot name.
 */
static VALUE libvirt_dom_lookup_snapshot_by_name(int argc, VALUE *argv, VALUE d) {
    virDomainPtr dom = domain_get(d);
    virDomainSnapshotPtr snap;
    VALUE name, flags;

    rb_scan_args(argc, argv, "11", &name, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    snap = virDomainSnapshotLookupByName(dom, StringValueCStr(name),
                                         NUM2UINT(flags));
    _E(dom == NULL, create_error(e_RetrieveError,
                                 "virDomainSnapshotLookupByName", conn(d)));

    return domain_snapshot_new(snap, d);
}

/*
 * call-seq:
 *   dom.has_current_snapshot?(flags=0) -> [true|false]
 *
 * Call +virDomainHasCurrentSnapshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainHasCurrentSnapshot]
 * to find out if this domain has a snapshot active.
 */
static VALUE libvirt_dom_has_current_snapshot_p(int argc, VALUE *argv, VALUE d) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_truefalse(virDomainHasCurrentSnapshot, conn(d), domain_get(d),
                       NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.revert_to_snapshot(snapshot_object, flags=0) -> nil
 *
 * Call +virDomainRevertToSnapshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainRevertToSnapshot]
 * to restore this domain to a previously saved snapshot.
 */
static VALUE libvirt_dom_revert_to_snapshot(int argc, VALUE *argv, VALUE d) {
    VALUE snap, flags;

    rb_scan_args(argc, argv, "11", &snap, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainRevertToSnapshot, conn(d),
                  domain_snapshot_get(snap), NUM2UINT(flags));
}

/*
 * call-seq:
 *   dom.current_snapshot(flags=0) -> Libvirt::Domain::Snapshot
 *
 * Call +virDomainCurrentSnapshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainCurrentSnapshot]
 * to retrieve the current snapshot for this domain (if any).
 */
static VALUE libvirt_dom_current_snapshot(int argc, VALUE *argv, VALUE d) {
    VALUE flags;
    virDomainSnapshotPtr snap;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    snap = virDomainSnapshotCurrent(domain_get(d), NUM2UINT(flags));
    _E(snap == NULL, create_error(e_RetrieveError, "virDomainSnapshotCurrent",
                                  conn(d)));

    return domain_snapshot_new(snap, d);
}

/*
 * call-seq:
 *   snapshot.xml_desc(flags=0) -> string
 *
 * Call +virDomainSnapshotGetXMLDesc+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotGetXMLDesc]
 * to retrieve the xml description for this snapshot.
 */
static VALUE libvirt_dom_snapshot_xml_desc(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_string(virDomainSnapshotGetXMLDesc, conn(s), 1,
                    domain_snapshot_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   snapshot.delete(flags=0) -> nil
 *
 * Call +virDomainSnapshotDelete+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotDelete]
 * to delete this snapshot.
 */
static VALUE libvirt_dom_snapshot_delete(int argc, VALUE *argv, VALUE s) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainSnapshotDelete, conn(s),
                  domain_snapshot_get(s), NUM2UINT(flags));
}

/*
 * call-seq:
 *   snapshot.free -> nil
 *
 * Call +virDomainSnapshotFree+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSnapshotFree]
 * to free up the snapshot object.  After this call the snapshot object is
 * no longer valid.
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
 * to retrieve the current state of the running domain job.
 */
static VALUE libvirt_dom_job_info(VALUE d) {
    int r;
    virDomainJobInfo info;
    VALUE result;

    r = virDomainGetJobInfo(domain_get(d), &info);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetJobInfo", conn(d)));

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
 * to abort the currently running job on this domain.
 */
static VALUE libvirt_dom_abort_job(VALUE d) {
    gen_call_void(virDomainAbortJob, conn(d), domain_get(d));
}

#endif

struct create_sched_type_args {
    char *type;
    int nparams;
};

static VALUE create_sched_type_array(VALUE input) {
    struct create_sched_type_args *args;
    VALUE result;

    args = (struct create_sched_type_args *)input;

    result = rb_ary_new();
    rb_ary_push(result, rb_str_new2(args->type));
    rb_ary_push(result, INT2NUM(args->nparams));

    return result;
}

/*
 * call-seq:
 *   dom.scheduler_type -> [type, #params]
 *
 * Call +virDomainGetSchedulerType+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetSchedulerType]
 * to retrieve the scheduler type used on this domain.
 */
static VALUE libvirt_dom_scheduler_type(VALUE d) {
    int nparams;
    char *type;
    VALUE result;
    int exception = 0;
    struct create_sched_type_args args;

    type = virDomainGetSchedulerType(domain_get(d), &nparams);

    _E(type == NULL, create_error(e_RetrieveError, "virDomainGetSchedulerType",
                                  conn(d)));

    args.type = type;
    args.nparams = nparams;
    result = rb_protect(create_sched_type_array, (VALUE)&args, &exception);
    if (exception) {
        free(type);
        rb_jump_tag(exception);
    }

    return result;
}

#if HAVE_VIRDOMAINQEMUMONITORCOMMAND
/*
 * call-seq:
 *   dom.qemu_monitor_command(cmd, flags=0) -> string
 *
 * Call virDomainQemuMonitorCommand
 * to send a qemu command directly to the monitor.  Note that this will only
 * work on qemu hypervisors, and the input and output formats are not
 * guaranteed to be stable.  Also note that using this command can severly
 * impede libvirt's ability to manage the domain; use with caution!
 */
static VALUE libvirt_dom_qemu_monitor_command(int argc, VALUE *argv, VALUE d) {
    VALUE cmd, flags;
    char *result;
    VALUE ret;
    int exception;
    virConnectPtr c;
    const char *type;
    int r;

    rb_scan_args(argc, argv, "11", &cmd, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    c = conn(d);
    type = virConnectGetType(c);
    _E(type == NULL, create_error(e_Error, "virConnectGetType", c));
    if (strcmp(type, "QEMU") != 0)
        rb_raise(rb_eTypeError,
                 "Tried to use virDomainQemuMonitor command on %s connection",
                 type);

    r = virDomainQemuMonitorCommand(domain_get(d), StringValueCStr(cmd),
                                    &result, NUM2UINT(flags));
    _E(r < 0, create_error(e_RetrieveError, "virDomainQemuMonitorCommand", c));

    ret = rb_protect(rb_str_new2_wrap, (VALUE)&result, &exception);
    free(result);
    if (exception)
        rb_jump_tag(exception);

    return ret;
}
#endif

#if HAVE_VIRDOMAINISUPDATED
/*
 * call-seq:
 *   dom.updated? ->  [True|False]
 * Call +virDomainIsUpdated+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainIsUpdated]
 * to determine whether the definition for this domain has been updated.
 */
static VALUE libvirt_dom_is_updated(VALUE d) {
    gen_call_truefalse(virDomainIsUpdated, conn(d), domain_get(d));
}
#endif

struct field_to_value {
    VALUE result;
    virTypedParameterPtr param;
};

static VALUE typed_field_to_value(VALUE input) {
    struct field_to_value *ftv = (struct field_to_value *)input;
    VALUE val;

    switch(ftv->param->type) {
    case VIR_TYPED_PARAM_INT:
        val = INT2NUM(ftv->param->value.i);
        break;
    case VIR_TYPED_PARAM_UINT:
        val = UINT2NUM(ftv->param->value.ui);
        break;
    case VIR_TYPED_PARAM_LLONG:
        val = LL2NUM(ftv->param->value.l);
        break;
    case VIR_TYPED_PARAM_ULLONG:
        val = ULL2NUM(ftv->param->value.ul);
        break;
    case VIR_TYPED_PARAM_DOUBLE:
        val = rb_float_new(ftv->param->value.d);
        break;
    case VIR_TYPED_PARAM_BOOLEAN:
        val = (ftv->param->value.b == 0) ? Qfalse : Qtrue;
        break;
    default:
        rb_raise(rb_eArgError, "Invalid parameter type");
    }

    rb_hash_aset(ftv->result, rb_str_new2(ftv->param->field), val);

    return Qnil;
}

static VALUE internal_get_parameters(int argc, VALUE *argv, VALUE d,
                                     int (*nparams_cb)(VALUE d,
                                                       unsigned int flags),
                                     char *(*get_cb)(VALUE d,
                                                     unsigned int flags,
                                                     virTypedParameterPtr params,
                                                     int *nparams)) {
    int nparams;
    virTypedParameterPtr params;
    VALUE result;
    int i;
    int exception;
    char *errname;
    struct field_to_value ftv;
    unsigned int flags;
    VALUE flags_val;

    rb_scan_args(argc, argv, "01", &flags_val);

    if (NIL_P(flags_val))
        flags = 0;
    else
        flags = NUM2UINT(flags_val);

    nparams = nparams_cb(d, flags);

    result = rb_hash_new();

    if (nparams == 0)
        return result;

    params = ALLOC_N(virTypedParameter, nparams);

    errname = get_cb(d, flags, params, &nparams);
    if (errname != NULL) {
        xfree(params);
        rb_exc_raise(create_error(e_RetrieveError, errname, conn(d)));
    }

    for (i = 0; i < nparams; i++) {
        ftv.result = result;
        ftv.param = &params[i];
        rb_protect(typed_field_to_value, (VALUE)&ftv, &exception);
        if (exception) {
            xfree(params);
            rb_jump_tag(exception);
        }
    }

    xfree(params);

    return result;
}

struct value_to_field {
    virTypedParameterPtr param;
    VALUE input;
};

static VALUE typed_value_to_field(VALUE in) {
    struct value_to_field *vtf = (struct value_to_field *)in;
    VALUE val;

    val = rb_hash_aref(vtf->input, rb_str_new2(vtf->param->field));
    if (NIL_P(val))
        return Qnil;

    switch(vtf->param->type) {
    case VIR_TYPED_PARAM_INT:
        vtf->param->value.i = NUM2INT(val);
        break;
    case VIR_TYPED_PARAM_UINT:
        vtf->param->value.ui = NUM2UINT(val);
        break;
    case VIR_TYPED_PARAM_LLONG:
        vtf->param->value.l = NUM2LL(val);
        break;
    case VIR_TYPED_PARAM_ULLONG:
        vtf->param->value.ul = NUM2ULL(val);
        break;
    case VIR_TYPED_PARAM_DOUBLE:
        vtf->param->value.d = NUM2DBL(val);
        break;
    case VIR_TYPED_PARAM_BOOLEAN:
        vtf->param->value.b = (val == Qtrue) ? 1 : 0;
        break;
    default:
        rb_raise(rb_eArgError, "Invalid parameter type");
    }

    return Qnil;
}

static VALUE internal_set_parameters(VALUE d, VALUE in,
                                     int (*nparams_cb)(VALUE d,
                                                       unsigned int flags),
                                     char *(*get_cb)(VALUE d,
                                                     unsigned int flags,
                                                     virTypedParameterPtr params,
                                                     int *nparams),
                                     char *(*set_cb)(VALUE d,
                                                     unsigned int flags,
                                                     virTypedParameterPtr params,
                                                     int nparams)) {
    int nparams;
    virTypedParameterPtr params;
    int exception;
    int i;
    char *errname;
    struct value_to_field vtf;
    VALUE input;
    VALUE flags_val;
    unsigned int flags;

    if (TYPE(in) == T_HASH) {
        input = in;
        flags_val = INT2NUM(0);
    }
    else if (TYPE(in) == T_ARRAY) {
        if (RARRAY_LEN(in) != 2)
            rb_raise(rb_eArgError, "wrong number of arguments (%d for 1 or 2)",
                     RARRAY_LEN(in));
        input = rb_ary_entry(in, 0);
        flags_val = rb_ary_entry(in, 1);
    }
    else
        rb_raise(rb_eTypeError, "wrong argument type (expected Hash or Array)");

    Check_Type(input, T_HASH);

    /* we do this up-front for proper argument error checking */
    flags = NUM2UINT(flags_val);

    if (RHASH_SIZE(input) == 0)
        return Qnil;

    /* Complicated.  The below all stems from the fact that we have no way to
     * have no way to discover what type each parameter should be based on the
     * be based on the input.  Instead, we ask libvirt to give us the current
     * us the current parameters and types, and then we replace the values with
     * the values with the new values.  That way we find out what the old types
     * what the old types were, and if the new types don't match, libvirt will
     * throw an error.
     */

    nparams = nparams_cb(d, flags);

    params = ALLOC_N(virTypedParameter, nparams);

    errname = get_cb(d, flags, params, &nparams);
    if (errname != NULL) {
        xfree(params);
        rb_exc_raise(create_error(e_RetrieveError, errname, conn(d)));
    }

    for (i = 0; i < nparams; i++) {
        vtf.param = &params[i];
        vtf.input = input;
        rb_protect(typed_value_to_field, (VALUE)&vtf, &exception);
        if (exception) {
            xfree(params);
            rb_jump_tag(exception);
        }
    }

    errname = set_cb(d, flags, params, nparams);
    if (errname != NULL) {
        xfree(params);
        rb_exc_raise(create_error(e_RetrieveError, errname, conn(d)));
    }

    xfree(params);

    return Qnil;
}

static int scheduler_nparams(VALUE d, unsigned int flags) {
    int nparams;
    char *type;

    type = virDomainGetSchedulerType(domain_get(d), &nparams);
    _E(type == NULL, create_error(e_RetrieveError, "virDomainGetSchedulerType",
                                  conn(d)));
    xfree(type);

    return nparams;
}

static char *scheduler_get(VALUE d, unsigned int flags,
                           virTypedParameterPtr params, int *nparams) {
#ifdef HAVE_TYPE_VIRTYPEDPARAMETERPTR
    if (virDomainGetSchedulerParametersFlags(domain_get(d), params, nparams,
                                             flags) < 0)
        return "virDomainGetSchedulerParameters";
#else
    if (flags != 0)
        rb_raise(e_NoSupportError, "Non-zero flags not supported");
    if (virDomainGetSchedulerParameters(domain_get(d),
                                        (virSchedParameterPtr)params,
                                        nparams) < 0)
        return "virDomainGetSchedulerParameters";
#endif

    return NULL;
}

static char *scheduler_set(VALUE d, unsigned int flags,
                           virTypedParameterPtr params, int nparams) {
#if HAVE_TYPE_VIRTYPEDPARAMETERPTR
    if (virDomainSetSchedulerParametersFlags(domain_get(d), params, nparams,
                                             flags) < 0)
        return "virDomainSetSchedulerParameters";
#else
    if (flags != 0)
        rb_raise(e_NoSupportError, "Non-zero flags not supported");
    if (virDomainSetSchedulerParameters(domain_get(d),
                                        (virSchedParameterPtr)params,
                                        nparams) < 0)
        return "virDomainSetSchedulerParameters";
#endif

    return NULL;
}

/*
 * call-seq:
 *   dom.scheduler_parameters(flags=0) -> Hash
 *
 * Call +virDomainGetSchedulerParameters+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetSchedulerParameters]
 * to retrieve all of the scheduler parameters for this domain.  The keys and
 * values in the hash that is returned are hypervisor specific.
 */
static VALUE libvirt_dom_get_scheduler_parameters(int argc, VALUE *argv,
                                                  VALUE d) {
    return internal_get_parameters(argc, argv, d, scheduler_nparams,
                                   scheduler_get);
}

/*
 * call-seq:
 *   dom.scheduler_parameters = Hash,flags=0
 *
 * Call +virDomainSetSchedulerParameters+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetSchedulerParameters]
 * to set the scheduler parameters for this domain.  The keys and values in
 * the input hash are hypervisor specific.  If an empty hash is given, no
 * changes are made (and no error is raised).
 */
static VALUE libvirt_dom_set_scheduler_parameters(VALUE d, VALUE input) {
    return internal_set_parameters(d, input, scheduler_nparams, scheduler_get,
                                   scheduler_set);
}

#if HAVE_VIRDOMAINSETMEMORYPARAMETERS
static int memory_nparams(VALUE d, unsigned int flags) {
    int nparams = 0;
    int ret;

    ret = virDomainGetMemoryParameters(domain_get(d), NULL, &nparams, flags);
    _E(ret < 0, create_error(e_RetrieveError, "virDomainGetMemoryParameters",
                             conn(d)));

    return nparams;
}

static char *memory_get(VALUE d, unsigned int flags,
                        virTypedParameterPtr params, int *nparams) {
#ifdef HAVE_TYPE_VIRTYPEDPARAMETERPTR
    if (virDomainGetMemoryParameters(domain_get(d), params, nparams, flags) < 0)
#else
    if (virDomainGetMemoryParameters(domain_get(d),
                                     (virMemoryParameterPtr)params, nparams,
                                     flags) < 0)
#endif
        return "virDomainGetMemoryParameters";

    return NULL;
}

static char *memory_set(VALUE d, unsigned int flags,
                        virTypedParameterPtr params, int nparams) {
#ifdef HAVE_TYPE_VIRTYPEDPARAMETERPTR
    if (virDomainSetMemoryParameters(domain_get(d), params, nparams, flags) < 0)
#else
    if (virDomainSetMemoryParameters(domain_get(d),
                                     (virMemoryParameterPtr)params, nparams,
                                     flags) < 0)
#endif
        return "virDomainSetMemoryParameters";

    return NULL;
}

/*
 * call-seq:
 *   dom.memory_parameters(flags=0) -> Hash
 *
 * Call +virDomainGetMemoryParameters+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetMemoryParameters]
 * to retrieve all of the memory parameters for this domain.  The keys and
 * values in the hash that is returned are hypervisor specific.
 */
static VALUE libvirt_dom_get_memory_parameters(int argc, VALUE *argv, VALUE d) {
    return internal_get_parameters(argc, argv, d, memory_nparams, memory_get);
}

/*
 * call-seq:
 *   dom.memory_parameters = Hash,flags=0
 *
 * Call +virDomainSetMemoryParameters+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetMemoryParameters]
 * to set the memory parameters for this domain.  The keys and values in
 * the input hash are hypervisor specific.
 */
static VALUE libvirt_dom_set_memory_parameters(VALUE d, VALUE in) {
    return internal_set_parameters(d, in, memory_nparams, memory_get,
                                   memory_set);
}
#endif

#if HAVE_VIRDOMAINSETBLKIOPARAMETERS
static int blkio_nparams(VALUE d, unsigned int flags) {
    int nparams = 0;
    int ret;

    ret = virDomainGetBlkioParameters(domain_get(d), NULL, &nparams, flags);
    _E(ret < 0, create_error(e_RetrieveError, "virDomainGetBlkioParameters",
                             conn(d)));

    return nparams;
}

static char *blkio_get(VALUE d, unsigned int flags, virTypedParameterPtr params,
                       int *nparams) {
#ifdef HAVE_TYPE_VIRTYPEDPARAMETERPTR
    if (virDomainGetBlkioParameters(domain_get(d), params, nparams, flags) < 0)
#else
    if (virDomainGetBlkioParameters(domain_get(d),
                                    (virBlkioParameterPtr)params, nparams,
                                    flags) < 0)
#endif
        return "virDomainGetBlkioParameters";

    return NULL;
}

static char *blkio_set(VALUE d, unsigned int flags, virTypedParameterPtr params,
                       int nparams) {
#ifdef HAVE_TYPE_VIRTYPEDPARAMETERPTR
    if (virDomainSetBlkioParameters(domain_get(d), params, nparams, flags) < 0)
#else
    if (virDomainSetBlkioParameters(domain_get(d),
                                    (virBlkioParameterPtr)params, nparams,
                                    flags) < 0)
#endif
        return "virDomainSetBlkioParameters";

    return NULL;
}

/*
 * call-seq:
 *   dom.blkio_parameters(flags=0) -> Hash
 *
 * Call +virDomainGetBlkioParameters+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetBlkioParameters]
 * to retrieve all of the blkio parameters for this domain.  The keys and
 * values in the hash that is returned are hypervisor specific.
 */
static VALUE libvirt_dom_get_blkio_parameters(int argc, VALUE *argv, VALUE d) {
    return internal_get_parameters(argc, argv, d, blkio_nparams, blkio_get);
}

/*
 * call-seq:
 *   dom.memory_parameters = Hash,flags=0
 *
 * Call +virDomainSetBlkioParameters+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainSetBlkioParameters]
 * to set the blkio parameters for this domain.  The keys and values in
 * the input hash are hypervisor specific.
 */
static VALUE libvirt_dom_set_blkio_parameters(VALUE d, VALUE in) {
    return internal_set_parameters(d, in, blkio_nparams, blkio_get, blkio_set);
}
#endif

#if HAVE_VIRDOMAINGETSTATE
/*
 * call-seq:
 *   dom.state(flags=0) -> state, reason
 *
 * Call +virDomainGetState+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetState]
 * to get the current state of the domain.
 */
static VALUE libvirt_dom_get_state(int argc, VALUE *argv, VALUE d) {
    VALUE flags;
    int state, reason;
    VALUE result;
    int retval;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    retval = virDomainGetState(domain_get(d), &state, &reason, NUM2INT(flags));
    _E(retval < 0, create_error(e_Error, "virDomainGetState", conn(d)));

    result = rb_ary_new();

    rb_ary_push(result, INT2NUM(state));
    rb_ary_push(result, INT2NUM(reason));

    return result;
}
#endif

#if HAVE_VIRDOMAINOPENCONSOLE
/*
 * call-seq:
 *   dom.open_console(device, stream, flags=0) -> nil
 *
 * Call +virDomainOpenConsole+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainOpenConsole]
 * to open up a console to device over stream.
 */
static VALUE libvirt_dom_open_console(int argc, VALUE *argv, VALUE d) {
    VALUE dev, st, flags;

    rb_scan_args(argc, argv, "21", &dev, &st, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainOpenConsole, conn(d), domain_get(d),
                  StringValueCStr(dev), stream_get(st), NUM2INT(flags));
}
#endif

#if HAVE_VIRDOMAINSCREENSHOT
/*
 * call-seq:
 *   dom.screenshot(stream, screen, flags=0) -> nil
 *
 * Call +virDomainScreenshot+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainScreenshot]
 * to take a screenshot of the domain console as a stream.
 */
static VALUE libvirt_dom_screenshot(int argc, VALUE *argv, VALUE d) {
    VALUE st, screen, flags;

    rb_scan_args(argc, argv, "21", &st, &screen, &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_string(virDomainScreenshot, conn(d), 1, domain_get(d),
                    stream_get(st), NUM2UINT(screen), NUM2UINT(flags));
}
#endif

#if HAVE_VIRDOMAININJECTNMI
/*
 * call-seq:
 *   dom.inject_nmi(flags=0) -> nil
 *
 * Call +virDomainInjectNMI+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainInjectNMI]
 * to send an NMI to the guest.
 */
static VALUE libvirt_dom_inject_nmi(int argc, VALUE *argv, VALUE d) {
    VALUE flags;

    rb_scan_args(argc, argv, "01", &flags);

    if (NIL_P(flags))
        flags = INT2NUM(0);

    gen_call_void(virDomainInjectNMI, conn(d), domain_get(d), NUM2UINT(flags));
}
#endif

#if HAVE_VIRDOMAINGETCONTROLINFO
/*
 * call-seq:
 *   dom.control_info(flags=0) -> nil
 *
 * Call +virDomainGetControlInfo+[http://www.libvirt.org/html/libvirt-libvirt.html#virDomainGetControlInfo]
 * to retrieve domain control interface information.
 */
static VALUE libvirt_dom_control_info(int argc, VALUE *argv, VALUE d) {
    VALUE flags;
    virDomainPtr dom = domain_get(d);
    virDomainControlInfo info;
    int r;
    VALUE result;

    rb_scan_args(argc, argv, "01", &flags);

    r = virDomainGetControlInfo(dom, &info);
    _E(r < 0, create_error(e_RetrieveError, "virDomainGetControlInfo",
                           conn(s)));

    result = rb_class_new_instance(0, NULL, c_domain_control_info);
    rb_iv_set(result, "@state", ULONG2NUM(info.state));
    rb_iv_set(result, "@details", ULONG2NUM(info.details));
    rb_iv_set(result, "@stateTime", ULL2NUM(info.stateTime));

    return result;
}
#endif

/*
 * Class Libvirt::Domain
 */
void init_domain()
{
    c_domain = rb_define_class_under(m_libvirt, "Domain", rb_cObject);

    rb_define_const(c_domain, "NOSTATE", INT2NUM(VIR_DOMAIN_NOSTATE));
    rb_define_const(c_domain, "RUNNING", INT2NUM(VIR_DOMAIN_RUNNING));
    rb_define_const(c_domain, "BLOCKED", INT2NUM(VIR_DOMAIN_BLOCKED));
    rb_define_const(c_domain, "PAUSED", INT2NUM(VIR_DOMAIN_PAUSED));
    rb_define_const(c_domain, "SHUTDOWN", INT2NUM(VIR_DOMAIN_SHUTDOWN));
    rb_define_const(c_domain, "SHUTOFF", INT2NUM(VIR_DOMAIN_SHUTOFF));
    rb_define_const(c_domain, "CRASHED", INT2NUM(VIR_DOMAIN_CRASHED));

    /* virDomainMigrateFlags */
#if HAVE_CONST_VIR_MIGRATE_LIVE
    rb_define_const(c_domain, "MIGRATE_LIVE", INT2NUM(VIR_MIGRATE_LIVE));
#endif
#if HAVE_CONST_VIR_MIGRATE_PEER2PEER
    rb_define_const(c_domain, "MIGRATE_PEER2PEER",
                    INT2NUM(VIR_MIGRATE_PEER2PEER));
#endif
#if HAVE_CONST_VIR_MIGRATE_TUNNELLED
    rb_define_const(c_domain, "MIGRATE_TUNNELLED",
                    INT2NUM(VIR_MIGRATE_TUNNELLED));
#endif
#if HAVE_CONST_VIR_MIGRATE_PERSIST_DEST
    rb_define_const(c_domain, "MIGRATE_PERSIST_DEST",
                    INT2NUM(VIR_MIGRATE_PERSIST_DEST));
#endif
#if HAVE_CONST_VIR_MIGRATE_UNDEFINE_SOURCE
    rb_define_const(c_domain, "MIGRATE_UNDEFINE_SOURCE",
                    INT2NUM(VIR_MIGRATE_UNDEFINE_SOURCE));
#endif
#if HAVE_CONST_VIR_MIGRATE_PAUSED
    rb_define_const(c_domain, "MIGRATE_PAUSED", INT2NUM(VIR_MIGRATE_PAUSED));
#endif
#if HAVE_CONST_VIR_MIGRATE_NON_SHARED_DISK
    rb_define_const(c_domain, "MIGRATE_NON_SHARED_DISK",
                    INT2NUM(VIR_MIGRATE_NON_SHARED_DISK));
#endif
#if HAVE_CONST_VIR_MIGRATE_NON_SHARED_INC
    rb_define_const(c_domain, "MIGRATE_NON_SHARED_INC",
                    INT2NUM(VIR_MIGRATE_NON_SHARED_INC));
#endif
    rb_define_const(c_domain, "DOMAIN_XML_SECURE",
                    INT2NUM(VIR_DOMAIN_XML_SECURE));
    rb_define_const(c_domain, "DOMAIN_XML_INACTIVE",
                    INT2NUM(VIR_DOMAIN_XML_INACTIVE));
#if HAVE_CONST_VIR_DOMAIN_XML_UPDATE_CPU
    rb_define_const(c_domain, "DOMAIN_XML_UPDATE_CPU",
                    INT2NUM(VIR_DOMAIN_XML_UPDATE_CPU));
#endif
#if HAVE_VIRDOMAINMEMORYPEEK
    rb_define_const(c_domain, "MEMORY_VIRTUAL", INT2NUM(VIR_MEMORY_VIRTUAL));
#endif
#if HAVE_CONST_VIR_MEMORY_PHYSICAL
    rb_define_const(c_domain, "MEMORY_PHYSICAL", INT2NUM(VIR_MEMORY_PHYSICAL));
#endif

#if HAVE_CONST_VIR_DOMAIN_START_PAUSED
    rb_define_const(c_domain, "START_PAUSED", INT2NUM(VIR_DOMAIN_START_PAUSED));
#endif

#if HAVE_CONST_VIR_DUMP_CRASH
    rb_define_const(c_domain, "DUMP_CRASH", INT2NUM(VIR_DUMP_CRASH));
#endif
#if HAVE_CONST_VIR_DUMP_LIVE
    rb_define_const(c_domain, "DUMP_LIVE", INT2NUM(VIR_DUMP_LIVE));
#endif

#if HAVE_VIRDOMAINGETVCPUSFLAGS
    rb_define_const(c_domain, "VCPU_LIVE", INT2NUM(VIR_DOMAIN_VCPU_LIVE));
    rb_define_const(c_domain, "VCPU_CONFIG", INT2NUM(VIR_DOMAIN_VCPU_CONFIG));
    rb_define_const(c_domain, "VCPU_MAXIMUM", INT2NUM(VIR_DOMAIN_VCPU_MAXIMUM));
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
#if HAVE_VIRDOMAINMIGRATE2
    rb_define_method(c_domain, "migrate2", libvirt_dom_migrate2, -1);
    rb_define_method(c_domain, "migrate_to_uri2",
                     libvirt_dom_migrate_to_uri2, -1);
    rb_define_method(c_domain, "migrate_set_max_speed",
                     libvirt_dom_migrate_set_max_speed, -1);
#endif

    rb_define_attr(c_domain, "connection", 1, 0);
    rb_define_method(c_domain, "shutdown", libvirt_dom_shutdown, 0);
    rb_define_method(c_domain, "reboot", libvirt_dom_reboot, -1);
    rb_define_method(c_domain, "destroy", libvirt_dom_destroy, 0);
    rb_define_method(c_domain, "suspend", libvirt_dom_suspend, 0);
    rb_define_method(c_domain, "resume", libvirt_dom_resume, 0);
    rb_define_method(c_domain, "save", libvirt_dom_save, 1);
    rb_define_singleton_method(c_domain, "restore", libvirt_dom_s_restore, 2);
    rb_define_method(c_domain, "restore", libvirt_dom_restore, 1);
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
#if HAVE_VIRDOMAINSETVCPUSFLAGS
    rb_define_method(c_domain, "vcpus_flags=", libvirt_dom_vcpus_set_flags, 1);
#endif
    rb_define_method(c_domain, "pin_vcpu", libvirt_dom_pin_vcpu, 2);
    rb_define_method(c_domain, "xml_desc", libvirt_dom_xml_desc, -1);
    rb_define_method(c_domain, "undefine", libvirt_dom_undefine, 0);
    rb_define_method(c_domain, "create", libvirt_dom_create, -1);
    rb_define_method(c_domain, "autostart", libvirt_dom_autostart, 0);
    rb_define_method(c_domain, "autostart?", libvirt_dom_autostart, 0);
    rb_define_method(c_domain, "autostart=", libvirt_dom_autostart_set, 1);
    rb_define_method(c_domain, "free", libvirt_dom_free, 0);

#if HAVE_CONST_VIR_DOMAIN_DEVICE_MODIFY_CURRENT
    rb_define_const(c_domain, "DEVICE_MODIFY_CURRENT",
                    INT2NUM(VIR_DOMAIN_DEVICE_MODIFY_CURRENT));
#endif
#if HAVE_CONST_VIR_DOMAIN_DEVICE_MODIFY_LIVE
    rb_define_const(c_domain, "DEVICE_MODIFY_LIVE",
                    INT2NUM(VIR_DOMAIN_DEVICE_MODIFY_LIVE));
#endif
#if HAVE_CONST_VIR_DOMAIN_DEVICE_MODIFY_CONFIG
    rb_define_const(c_domain, "DEVICE_MODIFY_CONFIG",
                    INT2NUM(VIR_DOMAIN_DEVICE_MODIFY_CONFIG));
#endif
#if HAVE_CONST_VIR_DOMAIN_DEVICE_MODIFY_FORCE
    rb_define_const(c_domain, "DEVICE_MODIFY_FORCE",
                    INT2NUM(VIR_DOMAIN_DEVICE_MODIFY_FORCE));
#endif
    rb_define_method(c_domain, "attach_device", libvirt_dom_attach_device, -1);
    rb_define_method(c_domain, "detach_device", libvirt_dom_detach_device, -1);
#if HAVE_VIRDOMAINUPDATEDEVICEFLAGS
    rb_define_method(c_domain, "update_device", libvirt_dom_update_device, -1);
#endif

    rb_define_method(c_domain, "scheduler_type", libvirt_dom_scheduler_type, 0);

#if HAVE_VIRDOMAINMANAGEDSAVE
    rb_define_method(c_domain, "managed_save", libvirt_dom_managed_save, -1);
    rb_define_method(c_domain, "has_managed_save?",
                     libvirt_dom_has_managed_save, -1);
    rb_define_method(c_domain, "managed_save_remove",
                     libvirt_dom_managed_save_remove, -1);
#endif
#if HAVE_VIRDOMAINGETSECURITYLABEL
    rb_define_method(c_domain, "security_label",
                     libvirt_dom_security_label, 0);
#endif
    rb_define_method(c_domain, "block_stats", libvirt_dom_block_stats, 1);
#if HAVE_TYPE_VIRDOMAINMEMORYSTATPTR
    rb_define_method(c_domain, "memory_stats", libvirt_dom_memory_stats, -1);
#endif
#if HAVE_VIRDOMAINBLOCKPEEK
    rb_define_method(c_domain, "block_peek", libvirt_dom_block_peek, -1);
#endif
#if HAVE_TYPE_VIRDOMAINBLOCKINFOPTR
    rb_define_method(c_domain, "blockinfo", libvirt_dom_block_info, -1);
#endif
#if HAVE_VIRDOMAINMEMORYPEEK
    rb_define_method(c_domain, "memory_peek", libvirt_dom_memory_peek, -1);
#endif
    rb_define_method(c_domain, "get_vcpus", libvirt_dom_get_vcpus, 0);
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

    rb_define_const(c_domain_memory_stats, "SWAP_IN",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_SWAP_IN));
    rb_define_const(c_domain_memory_stats, "SWAP_OUT",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_SWAP_OUT));
    rb_define_const(c_domain_memory_stats, "MAJOR_FAULT",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT));
    rb_define_const(c_domain_memory_stats, "MINOR_FAULT",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT));
    rb_define_const(c_domain_memory_stats, "UNUSED",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_UNUSED));
    rb_define_const(c_domain_memory_stats, "AVAILABLE",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_AVAILABLE));
    rb_define_const(c_domain_memory_stats, "NR",
                    INT2NUM(VIR_DOMAIN_MEMORY_STAT_NR));
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

    /*
     * Class Libvirt::Domain::VCPUInfo
     */
    c_domain_vcpuinfo = rb_define_class_under(c_domain, "VCPUInfo", rb_cObject);
    rb_define_const(c_domain_vcpuinfo, "OFFLINE", VIR_VCPU_OFFLINE);
    rb_define_const(c_domain_vcpuinfo, "RUNNING", VIR_VCPU_RUNNING);
    rb_define_const(c_domain_vcpuinfo, "BLOCKED", VIR_VCPU_BLOCKED);
    rb_define_attr(c_domain_vcpuinfo, "number", 1, 0);
    rb_define_attr(c_domain_vcpuinfo, "state", 1, 0);
    rb_define_attr(c_domain_vcpuinfo, "cpu_time", 1, 0);
    rb_define_attr(c_domain_vcpuinfo, "cpu", 1, 0);
    rb_define_attr(c_domain_vcpuinfo, "cpumap", 1, 0);

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

#if HAVE_VIRDOMAINQEMUMONITORCOMMAND
    rb_define_method(c_domain, "qemu_monitor_command",
                     libvirt_dom_qemu_monitor_command, -1);
#endif

#if HAVE_VIRDOMAINGETVCPUSFLAGS
    rb_define_method(c_domain, "num_vcpus", libvirt_dom_num_vcpus, 1);
#endif

#if HAVE_VIRDOMAINISUPDATED
    rb_define_method(c_domain, "updated?", libvirt_dom_is_updated, 0);
#endif

#ifdef VIR_DOMAIN_MEMORY_PARAM_UNLIMITED
    rb_define_const(c_domain, "MEMORY_PARAM_UNLIMITED",
                    VIR_DOMAIN_MEMORY_PARAM_UNLIMITED);
#endif

#if HAVE_VIRDOMAINSETMEMORYFLAGS
    rb_define_const(c_domain, "DOMAIN_MEM_LIVE", INT2NUM(VIR_DOMAIN_MEM_LIVE));
    rb_define_const(c_domain, "DOMAIN_MEM_CONFIG",
                    INT2NUM(VIR_DOMAIN_MEM_CONFIG));
#endif
#if HAVE_CONST_VIR_DOMAIN_MEM_CURRENT
    rb_define_const(c_domain, "DOMAIN_MEM_CURRENT",
                    INT2NUM(VIR_DOMAIN_MEM_CURRENT));
    rb_define_const(c_domain, "DOMAIN_MEM_MAXIMUM",
                    INT2NUM(VIR_DOMAIN_MEM_MAXIMUM));
#endif

    rb_define_method(c_domain, "scheduler_parameters",
                     libvirt_dom_get_scheduler_parameters, -1);
    rb_define_method(c_domain, "scheduler_parameters=",
                     libvirt_dom_set_scheduler_parameters, 1);

#if HAVE_VIRDOMAINSETMEMORYPARAMETERS
    rb_define_method(c_domain, "memory_parameters",
                     libvirt_dom_get_memory_parameters, -1);
    rb_define_method(c_domain, "memory_parameters=",
                     libvirt_dom_set_memory_parameters, 1);
#endif

#if HAVE_VIRDOMAINSETBLKIOPARAMETERS
    rb_define_method(c_domain, "blkio_parameters",
                     libvirt_dom_get_blkio_parameters, -1);
    rb_define_method(c_domain, "blkio_parameters=",
                     libvirt_dom_set_blkio_parameters, 1);
#endif

#if HAVE_VIRDOMAINGETSTATE
    rb_define_const(c_domain, "DOMAIN_RUNNING_UNKNOWN",
                    INT2NUM(VIR_DOMAIN_RUNNING_UNKNOWN));
    rb_define_const(c_domain, "DOMAIN_RUNNING_BOOTED",
                    INT2NUM(VIR_DOMAIN_RUNNING_BOOTED));
    rb_define_const(c_domain, "DOMAIN_RUNNING_MIGRATED",
                    INT2NUM(VIR_DOMAIN_RUNNING_MIGRATED));
    rb_define_const(c_domain, "DOMAIN_RUNNING_RESTORED",
                    INT2NUM(VIR_DOMAIN_RUNNING_RESTORED));
    rb_define_const(c_domain, "DOMAIN_RUNNING_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_RUNNING_FROM_SNAPSHOT));
    rb_define_const(c_domain, "DOMAIN_RUNNING_UNPAUSED",
                    INT2NUM(VIR_DOMAIN_RUNNING_UNPAUSED));
    rb_define_const(c_domain, "DOMAIN_RUNNING_MIGRATION_CANCELED",
                    INT2NUM(VIR_DOMAIN_RUNNING_MIGRATION_CANCELED));
    rb_define_const(c_domain, "DOMAIN_RUNNING_SAVE_CANCELED",
                    INT2NUM(VIR_DOMAIN_RUNNING_SAVE_CANCELED));
    rb_define_const(c_domain, "DOMAIN_BLOCKED_UNKNOWN",
                    INT2NUM(VIR_DOMAIN_BLOCKED_UNKNOWN));
    rb_define_const(c_domain, "DOMAIN_PAUSED_UNKNOWN",
                    INT2NUM(VIR_DOMAIN_PAUSED_UNKNOWN));
    rb_define_const(c_domain, "DOMAIN_PAUSED_USER",
                    INT2NUM(VIR_DOMAIN_PAUSED_USER));
    rb_define_const(c_domain, "DOMAIN_PAUSED_MIGRATION",
                    INT2NUM(VIR_DOMAIN_PAUSED_MIGRATION));
    rb_define_const(c_domain, "DOMAIN_PAUSED_SAVE",
                    INT2NUM(VIR_DOMAIN_PAUSED_SAVE));
    rb_define_const(c_domain, "DOMAIN_PAUSED_DUMP",
                    INT2NUM(VIR_DOMAIN_PAUSED_DUMP));
    rb_define_const(c_domain, "DOMAIN_PAUSED_IOERROR",
                    INT2NUM(VIR_DOMAIN_PAUSED_IOERROR));
    rb_define_const(c_domain, "DOMAIN_PAUSED_WATCHDOG",
                    INT2NUM(VIR_DOMAIN_PAUSED_WATCHDOG));
    rb_define_const(c_domain, "DOMAIN_PAUSED_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_PAUSED_FROM_SNAPSHOT));
#if HAVE_CONST_VIR_DOMAIN_PAUSED_SHUTTING_DOWN
    rb_define_const(c_domain, "DOMAIN_PAUSED_SHUTTING_DOWN",
                    INT2NUM(VIR_DOMAIN_PAUSED_SHUTTING_DOWN));
#endif
    rb_define_const(c_domain, "DOMAIN_SHUTDOWN_UNKNOWN",
                    INT2NUM(VIR_DOMAIN_SHUTDOWN_UNKNOWN));
    rb_define_const(c_domain, "DOMAIN_SHUTDOWN_USER",
                    INT2NUM(VIR_DOMAIN_SHUTDOWN_USER));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_UNKNOWN",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_UNKNOWN));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_SHUTDOWN",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_SHUTDOWN));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_DESTROYED",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_DESTROYED));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_CRASHED",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_CRASHED));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_MIGRATED",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_MIGRATED));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_SAVED",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_SAVED));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_FAILED",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_FAILED));
    rb_define_const(c_domain, "DOMAIN_SHUTOFF_FROM_SNAPSHOT",
                    INT2NUM(VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT));
    rb_define_const(c_domain, "DOMAIN_CRASHED_UNKNOWN",
                    INT2NUM(VIR_DOMAIN_CRASHED_UNKNOWN));

    rb_define_method(c_domain, "state", libvirt_dom_get_state, -1);
#endif

#if HAVE_CONST_VIR_DOMAIN_AFFECT_CURRENT
    rb_define_const(c_domain, "DOMAIN_AFFECT_CURRENT",
                    INT2NUM(VIR_DOMAIN_AFFECT_CURRENT));
    rb_define_const(c_domain, "DOMAIN_AFFECT_LIVE",
                    INT2NUM(VIR_DOMAIN_AFFECT_LIVE));
    rb_define_const(c_domain, "DOMAIN_AFFECT_CONFIG",
                    INT2NUM(VIR_DOMAIN_AFFECT_CONFIG));
#endif

#if HAVE_VIRDOMAINOPENCONSOLE
    rb_define_method(c_domain, "open_console", libvirt_dom_open_console, -1);
#endif

#if HAVE_VIRDOMAINSCREENSHOT
    rb_define_method(c_domain, "screenshot", libvirt_dom_screenshot, -1);
#endif

#if HAVE_VIRDOMAININJECTNMI
    rb_define_method(c_domain, "inject_nmi", libvirt_dom_inject_nmi, -1);
#endif

#if HAVE_VIRDOMAINGETCONTROLINFO
    /*
     * Class Libvirt::Domain::ControlInfo
     */
    c_domain_control_info = rb_define_class_under(c_domain, "ControlInfo",
                                                  rb_cObject);
    rb_define_attr(c_domain_control_info, "state", 1, 0);
    rb_define_attr(c_domain_control_info, "details", 1, 0);
    rb_define_attr(c_domain_control_info, "stateTime", 1, 0);

    rb_define_const(c_domain_control_info, "CONTROL_OK",
                    INT2NUM(VIR_DOMAIN_CONTROL_OK));
    rb_define_const(c_domain_control_info, "CONTROL_JOB",
                    INT2NUM(VIR_DOMAIN_CONTROL_JOB));
    rb_define_const(c_domain_control_info, "CONTROL_OCCUPIED",
                    INT2NUM(VIR_DOMAIN_CONTROL_OCCUPIED));
    rb_define_const(c_domain_control_info, "CONTROL_ERROR",
                    INT2NUM(VIR_DOMAIN_CONTROL_ERROR));

    rb_define_method(c_domain, "control_info", libvirt_dom_control_info, -1);
#endif
}
