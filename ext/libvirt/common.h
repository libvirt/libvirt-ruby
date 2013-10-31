#ifndef COMMON_H
#define COMMON_H

#ifndef HAVE_TYPE_VIRTYPEDPARAMETERPTR
#define VIR_TYPED_PARAM_INT VIR_DOMAIN_SCHED_FIELD_INT
#define VIR_TYPED_PARAM_UINT VIR_DOMAIN_SCHED_FIELD_UINT
#define VIR_TYPED_PARAM_LLONG VIR_DOMAIN_SCHED_FIELD_LLONG
#define VIR_TYPED_PARAM_ULLONG VIR_DOMAIN_SCHED_FIELD_ULLONG
#define VIR_TYPED_PARAM_DOUBLE VIR_DOMAIN_SCHED_FIELD_DOUBLE
#define VIR_TYPED_PARAM_BOOLEAN VIR_DOMAIN_SCHED_FIELD_BOOLEAN
#define VIR_TYPED_PARAM_STRING 7

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
        char *s;                    /* type is STRING, may not be NULL */
    } value; /* parameter value */
};
typedef virTypedParameter *virTypedParameterPtr;

#endif

/* Macros to ease some of the boilerplate */
VALUE ruby_libvirt_new_class(VALUE klass, void *ptr, VALUE conn,
                             RUBY_DATA_FUNC free_func);

#define RUBY_LIBVIRT_UNUSED(x) UNUSED_ ## x __attribute__((__unused__))

#define ruby_libvirt_get_struct(kind, v)                                \
    do {                                                                \
        vir##kind##Ptr ptr;                                             \
        Data_Get_Struct(v, vir##kind, ptr);                             \
        if (!ptr) {                                                     \
            rb_raise(rb_eArgError, #kind " has been freed");            \
        }                                                               \
        return ptr;                                                     \
    } while (0);

#define ruby_libvirt_free_struct(kind, p)                               \
    do {                                                                \
        int r;                                                          \
        r = vir##kind##Free((vir##kind##Ptr) p);                        \
        if (r < 0) {                                                    \
            rb_raise(rb_eSystemCallError, # kind " free failed");       \
        }                                                               \
    } while(0);

void ruby_libvirt_raise_error_if(const int condition, const char *method,
                                 virConnectPtr conn);

/*
 * Code generating macros.
 *
 * We only generate function bodies, not the whole function
 * declaration.
 */

/* Generate a call to a function FUNC which returns a string. The Ruby
 * function will return the string on success and throw an exception on
 * error. The string returned by FUNC is freed if dealloc is true.
 */
#define ruby_libvirt_generate_call_string(func, conn, dealloc, args...)  \
    do {                                                                 \
        const char *str;                                                 \
        VALUE result;                                                    \
        int exception;                                                   \
                                                                         \
        str = func(args);                                                \
        ruby_libvirt_raise_error_if(str == NULL, # func, conn);          \
        if (dealloc) {                                                   \
            result = rb_protect(ruby_libvirt_str_new2_wrap, (VALUE)&str, &exception); \
            xfree((void *) str);                                         \
            if (exception) {                                             \
                rb_jump_tag(exception);                                  \
            }                                                            \
        }                                                                \
        else {                                                           \
            result = rb_str_new2(str);                                   \
        }                                                                \
        return result;                                                   \
    } while(0)

/* Generate a call to vir##KIND##Free and return Qnil. Set the the embedded
 * vir##KIND##Ptr to NULL. If that pointer is already NULL, do nothing.
 */
#define ruby_libvirt_generate_call_free(kind, s)                        \
    do {                                                                \
        vir##kind##Ptr ptr;                                             \
        Data_Get_Struct(s, vir##kind, ptr);                             \
        if (ptr != NULL) {                                              \
            int r = vir##kind##Free(ptr);                               \
            ruby_libvirt_raise_error_if(r < 0, "vir" #kind "Free", ruby_libvirt_connect_get(s)); \
            DATA_PTR(s) = NULL;                                         \
        }                                                               \
        return Qnil;                                                    \
    } while (0)

/* Generate a call to a function FUNC which returns an int error, where -1
 * indicates error and 0 success. The Ruby function will return Qnil on
 * success and throw an exception on error.
 */
#define ruby_libvirt_generate_call_nil(func, conn, args...)             \
    do {                                                                \
        int _r_##func;                                                  \
        _r_##func = func(args);                                         \
        ruby_libvirt_raise_error_if(_r_##func < 0, #func, conn);        \
        return Qnil;                                                    \
    } while(0)

/* Generate a call to a function FUNC which returns an int; -1 indicates
 * error, 0 indicates Qfalse, and 1 indicates Qtrue.
 */
#define ruby_libvirt_generate_call_truefalse(func, conn, args...)       \
    do {                                                                \
        int _r_##func;                                                  \
        _r_##func = func(args);                                         \
        ruby_libvirt_raise_error_if(_r_##func < 0, #func, conn);        \
        return _r_##func ? Qtrue : Qfalse;                              \
    } while(0)

/* Generate a call to a function FUNC which returns an int error, where -1
 * indicates error and >= 0 success. The Ruby function will return the integer
 * success and throw an exception on error.
 */
#define ruby_libvirt_generate_call_int(func, conn, args...)             \
    do {                                                                \
        int _r_##func;                                                  \
        _r_##func = func(args);                                         \
        ruby_libvirt_raise_error_if(_r_##func < 0, #func, conn);        \
        return INT2NUM(_r_##func);                                      \
    } while(0)

#define ruby_libvirt_generate_uuid(func, conn, obj)                     \
    do {                                                                \
        char uuid[VIR_UUID_STRING_BUFLEN];                              \
        int _r_##func;                                                  \
        _r_##func = func(obj, uuid);                                    \
        ruby_libvirt_raise_error_if(_r_##func < 0, #func, conn);        \
        return rb_str_new2((char *) uuid);                              \
    } while (0)


#define ruby_libvirt_generate_call_list_all(type, argc, argv, listfunc, object, val, newfunc, freefunc) \
    do {                                                                \
        VALUE flags;                                                    \
        type *list;                                                     \
        int i;                                                          \
        int ret;                                                        \
        VALUE result;                                                   \
        int exception = 0;                                              \
        struct ruby_libvirt_ary_push_arg arg;                           \
                                                                        \
        rb_scan_args(argc, argv, "01", &flags);                         \
        ret = listfunc(object, &list, ruby_libvirt_value_to_uint(flags)); \
        ruby_libvirt_raise_error_if(ret < 0, #listfunc, ruby_libvirt_connect_get(val)); \
        result = rb_protect(ruby_libvirt_ary_new2_wrap, (VALUE)&ret, &exception); \
        if (exception) {                                                \
            goto exception;                                             \
        }                                                               \
        for (i = 0; i < ret; i++) {                                     \
            arg.arr = result;                                           \
            arg.value = newfunc(list[i], val);                          \
            rb_protect(ruby_libvirt_ary_push_wrap, (VALUE)&arg, &exception); \
            if (exception) {                                            \
                goto exception;                                         \
            }                                                           \
        }                                                               \
                                                                        \
        free(list);                                                     \
                                                                        \
        return result;                                                  \
                                                                        \
    exception:                                                          \
        for (i = 0; i < ret; i++) {                                     \
            freefunc(list[i]);                                          \
        }                                                               \
        free(list);                                                     \
        rb_jump_tag(exception);                                         \
                                                                        \
        /* not needed, but here to shut the compiler up */              \
        return Qnil;                                                    \
    } while(0)

int ruby_libvirt_is_symbol_or_proc(VALUE handle);

extern VALUE e_NoSupportError;

extern VALUE m_libvirt;

char *ruby_libvirt_get_cstring_or_null(VALUE arg);

VALUE ruby_libvirt_generate_list(int num, char **list);

struct ruby_libvirt_typed_param {
    const char *name;
    int type;
};
struct ruby_libvirt_parameter_assign_args {
    struct ruby_libvirt_typed_param *allowed;
    unsigned int num_allowed;

    virTypedParameter *params;
    int i;
};
int ruby_libvirt_typed_parameter_assign(VALUE key, VALUE val, VALUE in);
void ruby_libvirt_typed_params_to_hash(virTypedParameter *params, int i,
                                       VALUE hash);

unsigned int ruby_libvirt_value_to_uint(VALUE in);
int ruby_libvirt_value_to_int(VALUE in);
unsigned long ruby_libvirt_value_to_ulong(VALUE in);
unsigned long long ruby_libvirt_value_to_ulonglong(VALUE in);

VALUE ruby_libvirt_ary_new2_wrap(VALUE arg);

struct ruby_libvirt_ary_push_arg {
    VALUE arr;
    VALUE value;
};
VALUE ruby_libvirt_ary_push_wrap(VALUE arg);

struct ruby_libvirt_ary_store_arg {
    VALUE arr;
    long index;
    VALUE elem;
};
VALUE ruby_libvirt_ary_store_wrap(VALUE arg);

VALUE ruby_libvirt_str_new2_wrap(VALUE arg);

struct ruby_libvirt_str_new_arg {
    char *val;
    size_t size;
};
VALUE ruby_libvirt_str_new_wrap(VALUE arg);

struct ruby_libvirt_hash_aset_arg {
    VALUE hash;
    const char *name;
    VALUE val;
};
VALUE ruby_libvirt_hash_aset_wrap(VALUE arg);

struct ruby_libvirt_str_new2_and_ary_store_arg {
    VALUE arr;
    long index;
    char *value;
};
VALUE ruby_libvirt_str_new2_and_ary_store_wrap(VALUE arg);

#ifndef RARRAY_LEN
#define RARRAY_LEN(ar) (RARRAY(ar)->len)
#endif

#ifndef RSTRING_PTR
#define RSTRING_PTR(str) (RSTRING(str)->ptr)
#endif

#ifndef RSTRING_LEN
#define RSTRING_LEN(str) (RSTRING(str)->len)
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif
