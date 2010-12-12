#ifndef COMMON_H
#define COMMON_H

/* Macros to ease some of the boilerplate */
VALUE generic_new(VALUE klass, void *ptr, VALUE conn,
                  RUBY_DATA_FUNC free_func);

#define generic_get(kind, v)                                            \
    do {                                                                \
        vir##kind##Ptr ptr;                                             \
        Data_Get_Struct(v, vir##kind, ptr);                             \
        if (!ptr)                                                       \
            rb_raise(rb_eArgError, #kind " has been freed");            \
        return ptr;                                                     \
    } while (0);

#define generic_free(kind, p)                                           \
    do {                                                                \
        int r;                                                          \
        r = vir##kind##Free((vir##kind##Ptr) p);                        \
        if (r < 0)                                                      \
            rb_raise(rb_eSystemCallError, # kind " free failed");       \
    } while(0);

VALUE create_error(VALUE error, const char* method, virConnectPtr conn);

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
#define gen_call_string(func, conn, dealloc, args...)                   \
    do {                                                                \
        const char *str;                                                \
        VALUE result;                                                   \
                                                                        \
        str = func(args);                                               \
        _E(str == NULL, create_error(e_Error, # func, conn));           \
                                                                        \
        result = rb_str_new2(str);                                      \
        if (dealloc)                                                    \
            xfree((void *) str);                                        \
        return result;                                                  \
    } while(0)

/* Generate a call to vir##KIND##Free and return Qnil. Set the the embedded
 * vir##KIND##Ptr to NULL. If that pointer is already NULL, do nothing.
 */
#define gen_call_free(kind, s)                                          \
    do {                                                                \
        vir##kind##Ptr ptr;                                             \
        Data_Get_Struct(s, vir##kind, ptr);                             \
        if (ptr != NULL) {                                              \
            int r = vir##kind##Free(ptr);                               \
            _E(r < 0, create_error(e_Error, "vir" #kind "Free", conn(s))); \
            DATA_PTR(s) = NULL;                                         \
        }                                                               \
        return Qnil;                                                    \
    } while (0)

/* Generate a call to a function FUNC which returns an int error, where -1
 * indicates error and 0 success. The Ruby function will return Qnil on
 * success and throw an exception on error.
 */
#define gen_call_void(func, conn, args...)                              \
    do {                                                                \
        int _r_##func;                                                  \
        _r_##func = func(args);                                         \
        _E(_r_##func < 0, create_error(e_Error, #func, conn));          \
        return Qnil;                                                    \
    } while(0)

/*
 * Generate a call to a virConnectNumOf... function. C is the Ruby VALUE
 * holding the connection and OBJS is a token indicating what objects to
 * get the number of, e.g. 'Domains'
 */
#define gen_conn_num_of(c, objs)                                        \
    do {                                                                \
        int result;                                                     \
        virConnectPtr conn = connect_get(c);                            \
                                                                        \
        result = virConnectNumOf##objs(conn);                           \
        _E(result < 0, create_error(e_RetrieveError, "virConnectNumOf" # objs, conn));                \
                                                                        \
        return INT2NUM(result);                                         \
    } while(0)


VALUE gen_list(int num, char ***list);

/*
 * Generate a call to a virConnectList... function. S is the Ruby VALUE
 * holding the connection and OBJS is a token indicating what objects to
 * get the number of, e.g. 'Domains' The list function must return an array
 * of strings, which is returned as a Ruby array
 */
#define gen_conn_list_names(s, objs)                                    \
    do {                                                                \
        int r, num;                                                     \
        char **names;                                                   \
        virConnectPtr conn = connect_get(s);                            \
                                                                        \
        num = virConnectNumOf##objs(conn);                              \
        _E(num < 0, create_error(e_RetrieveError, "virConnectNumOf" # objs, conn));   \
        if (num == 0) {                                                 \
            /* if num is 0, don't call virConnectList* function */      \
            return rb_ary_new2(num);                                    \
        }                                                               \
        names = ALLOC_N(char *, num);                                   \
        r = virConnectList##objs(conn, names, num);                     \
        if (r < 0) {                                                    \
            xfree(names);                                               \
            _E(r < 0, create_error(e_RetrieveError, "virConnectList" # objs, conn));  \
        }                                                               \
                                                                        \
        return gen_list(num, &names);                                   \
    } while(0)

/* Generate a call to a function FUNC which returns an int; -1 indicates
 * error, 0 indicates Qfalse, and 1 indicates Qtrue.
 */
#define gen_call_truefalse(func, conn, args...)                         \
    do {                                                                \
        int _r_##func;                                                  \
        _r_##func = func(args);                                         \
        _E(_r_##func < 0, create_error(e_Error, #func, conn));          \
        return _r_##func ? Qtrue : Qfalse;                              \
    } while(0)

/* Error handling */
#define _E(cond, excep) \
    do { if (cond) rb_exc_raise(excep); } while(0)

int is_symbol_or_proc(VALUE handle);

extern VALUE e_RetrieveError;
extern VALUE e_Error;
extern VALUE e_DefinitionError;
extern VALUE e_NoSupportError;

extern VALUE m_libvirt;

char *get_string_or_nil(VALUE arg);

VALUE rb_str_new2_wrap(VALUE arg);
struct rb_ary_entry_arg {
    VALUE arr;
    int elem;
};
VALUE rb_ary_entry_wrap(VALUE arg);
struct rb_str_new_arg {
    char *val;
    size_t size;
};
VALUE rb_str_new_wrap(VALUE arg);
VALUE rb_ary_new_wrap(VALUE arg);
struct rb_ary_push_arg {
    VALUE arr;
    VALUE value;
};
VALUE rb_ary_push_wrap(VALUE arg);
VALUE rb_ary_new2_wrap(VALUE arg);
struct rb_iv_set_arg {
    VALUE klass;
    char *member;
    VALUE value;
};
VALUE rb_iv_set_wrap(VALUE arg);
struct rb_class_new_instance_arg {
    int argc;
    VALUE *argv;
    VALUE klass;
};
VALUE rb_class_new_instance_wrap(VALUE arg);
VALUE rb_string_value_cstr_wrap(VALUE arg);

#ifndef RARRAY_LEN
#define RARRAY_LEN(ar) (RARRAY(ar)->len)
#endif

#ifndef RSTRING_PTR
#define RSTRING_PTR(str) (RSTRING(str)->ptr)
#endif

#ifndef RSTRING_LEN
#define RSTRING_LEN(str) (RSTRING(str)->len)
#endif

#endif
