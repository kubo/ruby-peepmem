/* -*- c-file-style: "ruby"; indent-tabs-mode: nil -*-
 *
 * peepmem  -  Peep memory of other process
 * https://github.com/kubo/ruby-peepmem
 *
 * Copyright (C) 2015 Kubo Takehiro <kubo@jiubao.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * official policies, either expressed or implied, of the authors.
 */
#include <ruby.h>
#include <ruby/encoding.h>
#include <stdint.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* Use this macro not to be parsed by yard. */
#define rb_define_method_nodoc rb_define_method

static VALUE cHandle;
static VALUE cPointer;
static rb_encoding *utf16le_encoding;

#ifdef WIN32
typedef HANDLE mem_handle_t;
#define INVALID_MEM_HANDLE (NULL)
#else
typedef int mem_handle_t;
#define INVALID_MEM_HANDLE (-1)
#endif

typedef struct peepmem_handle peepmem_handle_t;
typedef struct peepmem_pointer peepmem_pointer_t;

struct peepmem_handle {
    VALUE self;
    mem_handle_t mem_handle;
    size_t (*read_mem)(peepmem_handle_t *, size_t, void *, size_t, int);
    pid_t pid;
    size_t addr;
    size_t len;
    char buf[4096];
};

struct peepmem_pointer {
    peepmem_handle_t *handle;
    size_t address;
};

static size_t read_mem_no_buffering(peepmem_handle_t *hndl, size_t address, void *buf, size_t buflen, int full);
static size_t read_mem_buffering(peepmem_handle_t *hndl, size_t address, void *buf, size_t buflen, int full);

/*
 * call-seq:
 *   open(process_id)
 *
 * @param [Integer] process_id
 * @return [Peepmem::Handle]
 */
static VALUE peepmem_s_open(VALUE klass, VALUE process_id)
{
    VALUE argv[1];

    argv[0] = process_id;
    return rb_class_new_instance(1, argv, cHandle);
}

static void peepmem_handle_free(peepmem_handle_t *hndl)
{
    if (hndl->mem_handle != INVALID_MEM_HANDLE) {
#ifdef WIN32
        CloseHandle(hndl->mem_handle);
#else
        close(hndl->mem_handle);
#endif
        hndl->mem_handle = INVALID_MEM_HANDLE;
    }
    hndl->pid = -1;
}

static VALUE peepmem_handle_s_allocate(VALUE klass)
{
    peepmem_handle_t *hndl;
    VALUE obj;

    obj = Data_Make_Struct(klass, peepmem_handle_t, NULL, peepmem_handle_free, hndl);
    hndl->self = obj;
    hndl->mem_handle = INVALID_MEM_HANDLE;
    hndl->read_mem = read_mem_no_buffering;
    hndl->pid = -1;
    return obj;
}

/*
 * call-seq:
 *   initialize(process_id)
 *
 * @private
 */
static VALUE peepmem_handle_initialize(VALUE self, VALUE process_id)
{
    peepmem_handle_t *hndl = DATA_PTR(self);
    pid_t pid = NUM2INT(process_id);

#ifdef WIN32
    static BOOL se_debug_is_enabled = 0;

    if (!se_debug_is_enabled) {
        /* Enable SE_DEBUG_NAME privilege */
        HANDLE hToken;
        LUID luid;
        TOKEN_PRIVILEGES tp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            rb_raise(rb_eRuntimeError, "Failed to get the process token");
        }
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            rb_raise(rb_eRuntimeError, "Failed to get SE_DEDUG_NAME privilege");
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            CloseHandle(hToken);
            rb_raise(rb_eRuntimeError, "Failed to set SE_DEDUG_NAME privilege");
        }
        CloseHandle(hToken);
        se_debug_is_enabled = 1;
    }

    hndl->mem_handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (hndl->mem_handle == NULL) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            rb_raise(rb_eRuntimeError, "You need root privilege to open process %lu.", pid);
        }
        rb_raise(rb_eRuntimeError, "OpenProcess(pid = %d): %s", pid, rb_w32_strerror(-1));
    }
#else
    char buf[64];

    sprintf(buf, "/proc/%d/mem", pid);
    hndl->mem_handle = open(buf, O_RDONLY);
    if (hndl->mem_handle == -1) {
        if (errno == EACCES && getuid() != 1) {
            rb_raise(rb_eRuntimeError, "You need root privilege to open '%s'.", buf);
        }
        rb_sys_fail("open");
    }
    fcntl(hndl->mem_handle, F_SETFD, fcntl(hndl->mem_handle, F_GETFD) | FD_CLOEXEC);
#endif
    hndl->pid = pid;
    return self;
}

/*
 * call-seq:
 *   handle.process_id -> integer
 *
 */
static VALUE peepmem_handle_get_process_id(VALUE self)
{
    peepmem_handle_t *hndl = DATA_PTR(self);
    return LONG2FIX(hndl->pid);
}

/*
 * call-seq:
 *   handle[integer] -> Peepmem::Pointer
 *
 */
static VALUE peepmem_handle_aref(VALUE self, VALUE pointer)
{
    VALUE argv[2];

    argv[0] = self;
    argv[1] = pointer;
    return rb_class_new_instance(2, argv, cPointer);
}

/*
 * call-seq:
 *   handle.buffering -> Boolean
 *
 * @see buffering=
 */
static VALUE peepmem_handle_get_buffering(VALUE self)
{
    peepmem_handle_t *hndl = DATA_PTR(self);

    if (hndl->read_mem == read_mem_buffering) {
        return Qtrue;
    } else {
        return Qfalse;
    }
}

/*
 * call-seq:
 *   handle.buffering = Boolean
 *
 */
static VALUE peepmem_handle_set_buffering(VALUE self, VALUE bool_val)
{
    peepmem_handle_t *hndl = DATA_PTR(self);

    if (RTEST(bool_val)) {
        hndl->read_mem = read_mem_buffering;
        hndl->len = 0;
    } else {
        hndl->read_mem = read_mem_no_buffering;
    }
    return bool_val;
}

/*
 * call-seq:
 *   handle.inspect -> String
 *
 * @private
 */
static VALUE peepmem_handle_inspect(VALUE self)
{
    peepmem_handle_t *hndl = DATA_PTR(self);

    return rb_sprintf("#<%s: PID=%ld>", rb_obj_classname(self), (long)hndl->pid);
}

/*
 * call-seq:
 *   handle.close
 *
 */
static VALUE peepmem_handle_close(VALUE self)
{
    peepmem_handle_t *hndl = DATA_PTR(self);

    peepmem_handle_free(hndl);
    return Qnil;
}

static void peepmem_pointer_mark(peepmem_pointer_t *ptr)
{
    rb_gc_mark(ptr->handle->self);
}

static VALUE peepmem_pointer_s_allocate(VALUE klass)
{
    peepmem_pointer_t *ptr;

    return Data_Make_Struct(klass, peepmem_pointer_t, peepmem_pointer_mark, NULL, ptr);
}

/*
 * call-seq:
 *   pointer.initialize(handle, address)
 *
 */
static VALUE peepmem_pointer_initialize(VALUE self, VALUE handle, VALUE address)
{
    peepmem_pointer_t *ptr = DATA_PTR(self);
    peepmem_handle_t *hndl;

    if (!rb_obj_is_instance_of(handle, cHandle)) {
        rb_raise(rb_eArgError, "wrong argument type %s (expected %s)",
                 rb_obj_classname(handle), rb_class2name(cHandle));
    }
    Data_Get_Struct(handle, peepmem_handle_t, hndl);
    ptr->handle = hndl;
    ptr->address = NUM2SIZET(address);
    return self;
}

/*
 * call-seq:
 *   pointer.to_i -> address
 *
 * Returns address as a integer.
 *
 * @example
 *   handle = Peepmem.open(7658)
 *   pointer = handle[0x00400000]
 *   pointer.to_i # => 4194304
 *
 * @return [Integer]
 */
static VALUE peepmem_pointer_to_i(VALUE self)
{
    peepmem_pointer_t *ptr = DATA_PTR(self);

    return SIZET2NUM(ptr->address);
}

/*
 * call-seq:
 *   pointer.to_s -> hex_string
 *
 * Returns address as a hexadecimal string.
 *
 * @example
 *   handle = Peepmem.open(7658)
 *   pointer = handle[0x00400000]
 *   pointer.to_s # => "0x00000000400000"
 *
 * @return [String]
 */
static VALUE peepmem_pointer_to_s(VALUE self)
{
    peepmem_pointer_t *ptr = DATA_PTR(self);

    return rb_sprintf("%p", (void*)ptr->address);
}

/*
 * call-seq:
 *   pointer.inspect -> string
 *
 */
static VALUE peepmem_pointer_inspect(VALUE self)
{
    peepmem_pointer_t *ptr = DATA_PTR(self);

    return rb_sprintf("#<%s:%p PID=%ld>", rb_obj_classname(self), (void*)ptr->address, (long)ptr->handle->pid);
}

/*
 * call-seq:
 *   self + integer
 *
 * Returns a pointer which shifts to upper address.
 *
 * @example
 *   handle = Peepmem.open(7658)
 *   pointer = handle[0x00400000]
 *   pointer + 0x10 # => #<Peepmem::Pointer:0x00000000400010 PID=7658>
 *
 * @return [Peepmem::Pointer]
 */
static VALUE peepmem_pointer_add(VALUE lhs, VALUE rhs)
{
    peepmem_pointer_t *ptr = DATA_PTR(lhs);
    VALUE argv[2];

    argv[0] = ptr->handle->self;
    argv[1] = SIZET2NUM(ptr->address + NUM2SSIZET(rhs));
    return rb_class_new_instance(2, argv, cPointer);
}

/*
 * call-seq:
 *   self - integer
 *
 * Returns a pointer which shifts to lower address.
 *
 * @example
 *   handle = Peepmem.open(7658)
 *   pointer = handle[0x00400000]
 *   pointer - 0x10 # => #<Peepmem::Pointer:0x000000003ffff0 PID=7658>
 *
 * @return [Peepmem::Pointer]
 */
static VALUE peepmem_pointer_sub(VALUE lhs, VALUE rhs)
{
    peepmem_pointer_t *ptr = DATA_PTR(lhs);
    VALUE argv[2];

    argv[0] = ptr->handle->self;
    argv[1] = SIZET2NUM(ptr->address - NUM2SSIZET(rhs));
    return rb_class_new_instance(2, argv, cPointer);
}

/* read process memory without buffering */
static size_t read_mem_no_buffering(peepmem_handle_t *hndl, size_t address, void *buf, size_t buflen, int full)
{
#ifdef WIN32
    size_t readlen;
    if (!ReadProcessMemory(hndl->mem_handle, (void*)address, buf, buflen, &readlen)) {
        readlen = 0;
    }
    if (full && readlen != buflen) {
        rb_raise(rb_eRuntimeError, "Cannot read the specified memory region");
    }
    return readlen;
#else
    ssize_t readlen = pread(hndl->mem_handle, buf, buflen, address);
    if (full && readlen != buflen) {
        rb_raise(rb_eRuntimeError, "Cannot read the specified memory region");
    }
    return (readlen != -1) ? readlen : 0;
#endif
}

/* read process memory with buffering */
static size_t read_mem_buffering(peepmem_handle_t *hndl, size_t address, void *buf, size_t buflen, int full)
{
    size_t readlen = 0;
    size_t copylen;

    if (hndl->addr <= address && address < hndl->addr + hndl->len) {
        size_t offset = address - hndl->addr;
        size_t copylen = MIN(buflen, hndl->len - offset);

        memcpy(buf, hndl->buf + offset, copylen);
        if (buflen == copylen) {
            return copylen;
        }
        readlen = copylen;
        address += copylen;
        buf = (char*)buf + copylen;
        buflen -= copylen;
    }
    if (buflen > sizeof(hndl->buf)) {
        return readlen + read_mem_no_buffering(hndl, address, buf, buflen, full);
    }
    hndl->len = read_mem_no_buffering(hndl, address, hndl->buf, sizeof(hndl->buf), 0);
    hndl->addr = address;
    if (buflen <= hndl->len) {
        copylen = buflen;
    } else {
        if (full) {
            rb_raise(rb_eRuntimeError, "Cannot read the specified memory region");
        }
        copylen = hndl->len;
    }
    memcpy(buf, hndl->buf, copylen);
    return readlen + copylen;
}

static int get_num(const char **fmt, const char *fmt_end, int default_value)
{
    int has_number = 0;
    int num = 0;

    while (*fmt < fmt_end) {
        switch (**fmt) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            num *= 10;
            num += **fmt - '0';
            (*fmt)++;
            has_number = 1;
            continue;
        }
        break;
    }
    if (has_number) {
        return num;
    } else {
        return default_value;
    }
}

static VALUE read_object(peepmem_handle_t *hndl, size_t *address, char type, int length)
{
    VALUE obj = Qnil;
    VALUE ptr = Qnil;
    union {
        int8_t d8;
        int16_t d16;
        int32_t d32;
        int64_t d64;
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        float flt;
        double dbl;
    } val;

    switch (type) {
    case 'd':
        hndl->read_mem(hndl, *address, &val, length, 1);
        switch (length) {
        case 1:
            obj = INT2FIX(val.d8);
            break;
        case 2:
            obj = INT2FIX(val.d16);
            break;
        case 4:
            obj = INT2NUM(val.d32);
            break;
        case 8:
            obj = LL2NUM(val.d64);
            break;
        }
        break;
    case 'u':
        hndl->read_mem(hndl, *address, &val, length, 1);
        switch (length) {
        case 1:
            obj = INT2FIX(val.u8);
            break;
        case 2:
            obj = INT2FIX(val.u16);
            break;
        case 4:
            obj = UINT2NUM(val.u32);
            break;
        case 8:
            obj = ULL2NUM(val.u64);
            break;
        }
        break;
    case 'f':
        hndl->read_mem(hndl, *address, &val, length, 1);
        switch (length) {
        case 4:
            obj = DBL2NUM(val.flt);
            break;
        case 8:
            obj = DBL2NUM(val.dbl);
            break;
        }
        break;
    case 's':
        if (length == 0) {
            char c;
            obj = rb_str_buf_new(64);
            hndl->read_mem(hndl, *address, &c, 1, 1);
            *address += 1;
            while (c != 0) {
                rb_str_buf_cat(obj, &c, 1);
                hndl->read_mem(hndl, *address, &c, 1, 1);
                *address += 1;
            }
        } else {
            obj = rb_str_buf_new(length);
            rb_str_set_len(obj, length);
            hndl->read_mem(hndl, *address, RSTRING_PTR(obj), length, 1);
        }
        OBJ_TAINT(obj);
        break;
    case 'w':
        if (length == 0) {
            uint16_t c;
            obj = rb_str_buf_new(64);
            hndl->read_mem(hndl, *address, &c, 2, 1);
            *address += 2;
            while (c != 0) {
                rb_str_buf_cat(obj, (char*)&c, 2);
                hndl->read_mem(hndl, *address, &c, 2, 1);
                *address += 2;
            }
        } else {
            obj = rb_str_buf_new(length);
            rb_str_set_len(obj, length);
            hndl->read_mem(hndl, *address, RSTRING_PTR(obj), length, 1);
        }
        OBJ_TAINT(obj);
        rb_enc_associate(obj, utf16le_encoding);
        break;
    case 'p':
        hndl->read_mem(hndl, *address, &val, length, 1);
        switch (length) {
        case 4:
            ptr = UINT2NUM(val.u32);
            break;
        case 8:
            ptr = ULL2NUM(val.u64);
            break;
        }
        obj = peepmem_pointer_s_allocate(cPointer);
        peepmem_pointer_initialize(obj, hndl->self, ptr);
        break;
    }
    *address += length;
    return obj;
}

static VALUE read_directive(peepmem_handle_t *hndl, size_t *address, const char **fmt, const char *fmt_end)
{
    char type;
    int count;
    int length;

read_again:
    count = get_num(fmt, fmt_end, 0);
    type = **fmt;
    switch (type) {
    case 'd':
    case 'u':
        (*fmt)++;
        if (*fmt < fmt_end && **fmt == 'L') {
            (*fmt)++;
            length = sizeof(long);
        } else if (*fmt < fmt_end && **fmt == 'P') {
            (*fmt)++;
            length = sizeof(void *);
        } else {
            length = get_num(fmt, fmt_end, 4);
        }
        switch (length) {
        case 1:
        case 2:
        case 4:
        case 8:
            break;
        default:
            rb_raise(rb_eArgError, "wrong format");
        }
        break;
    case 'f':
        (*fmt)++;
        length = get_num(fmt, fmt_end, 8);
        switch (length) {
        case 4:
        case 8:
            break;
        default:
            rb_raise(rb_eArgError, "wrong format");
        }
        break;
    case 's':
        (*fmt)++;
        length = get_num(fmt, fmt_end, 0);
        break;
    case 'w':
        if (utf16le_encoding == NULL) {
            utf16le_encoding = rb_enc_find("UTF-16LE");
        }
        (*fmt)++;
        length = get_num(fmt, fmt_end, 0) * 2;
        break;
    case 'p':
        (*fmt)++;
        length = get_num(fmt, fmt_end, sizeof(size_t));
        switch (length) {
        case 4:
        case 8:
            break;
        default:
            rb_raise(rb_eArgError, "wrong format");
        }
        break;
    case '>':
        (*fmt)++;
        length = get_num(fmt, fmt_end, 1);
        break;
    default:
        rb_raise(rb_eArgError, "wrong format");
    }

    while (*fmt < fmt_end) {
        switch (**fmt) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            (*fmt)++;
            continue;
        }
        break;
    }
    if (type == '>') {
        if (*fmt == fmt_end) {
            return Qundef;
        }
        if (count == 0) {
            *address += length;
        } else {
            *address += count * length;
        }
        goto read_again;
    }

    if (count == 0) {
        return read_object(hndl, address, type, length);
    } else {
        VALUE ary = rb_ary_new2(count);
        int i;

        for (i = 0; i < count; i++) {
            rb_ary_push(ary, read_object(hndl, address, type, length));
        }
        return ary;
    }
}

/*
 * call-seq:
 *   pointer[format]
 *
 * Reads memory according to the format string. The format string consists
 * of one or more directives separated by spaces. A directive consists of
 * (optional) <tt>count</tt>, <tt>data type</tt> and (optional) <tt>data
 * length</tt>. If a format string conststs of one directive without
 * <tt>count</tt>, it returns an object. Otherwise, it returns an array.
 *
 *   Directive    | Returns           | Meaning
 *   -----------------------------------------------------------------
 *      d1        | Integer           | 8-bit signed integer
 *      d2        | Integer           | 16-bit signed integer
 *      d4        | Integer           | 32-bit signed integer
 *      d8        | Integer           | 64-bit signed integer
 *      dL        | Integer           | signed integer whose length is same with long
 *      dP        | Integer           | signed integer whose length is same with poiner
 *      u1        | Integer           | 8-bit unsigned integer
 *      u2        | Integer           | 16-bit unsigned integer
 *      u4        | Integer           | 32-bit unsigned integer
 *      u8        | Integer           | 64-bit unsigned integer
 *      uL        | Integer           | unsigned integer whose length is same with long
 *      uP        | Integer           | unsigned integer whose length is same with pointer
 *      f4        | Double            | 32-bit floating point number (float)
 *      f8        | Double            | 64-bit floating point number (double)
 *      s         | String            | null-terminated string
 *      s(number) | String            | string whose length is specified by (number)
 *      w         | String            | null-terminated string, UTF16-LE encoding
 *      w(number) | String            | string whose length is specified by (number), UTF16-LE encoding
 *      p         | Peepmem::Pointer  | pointer
 *      >         |                   | skip one byte
 *      >(number) |                   | skip bytes specified by (number)
 *
 * @example
 *    pointer = Peepmem.open(7658)[0x00400000]
 *    pointer['d4']
 *    # => 32-bit signed integer
 *    pointer['1d4']
 *    # => [32-bit signed integer]
 *    pointer['2d4']
 *    # => [32-bit signed integer, 32-bit signed integer]
 *    pointer['u4 u2 >2 f8'] # '>2': skip two-byte padding
 *    # => [32-bit unsigned integer, 16-bit unsigned integer, double]
 */
static VALUE peepmem_pointer_aref(VALUE self, VALUE format)
{
    peepmem_pointer_t *ptr = DATA_PTR(self);
    const char *fmt, *fmt_end;
    size_t address = ptr->address;
    volatile VALUE rv;
    VALUE obj;

    SafeStringValue(format);

    fmt = RSTRING_PTR(format);
    fmt_end = fmt + RSTRING_LEN(format);
    obj = read_directive(ptr->handle, &address, &fmt, fmt_end);
    if (fmt >= fmt_end) {
        if (obj == Qundef) {
            rb_raise(rb_eArgError, "wrong format");
        }
        return obj;
    }
    rv = rb_ary_new4(1, &obj);
    do {
        obj = read_directive(ptr->handle, &address, &fmt, fmt_end);
        if (RB_TYPE_P(obj, T_ARRAY)) {
            rb_ary_concat(rv, obj);
        } else if (obj != Qundef) {
            rb_ary_push(rv, obj);
        }
    } while (fmt < fmt_end);

    return rv;
}

void Init_peepmem(void)
{
    VALUE mPeepmem = rb_define_module("Peepmem");

    cHandle = rb_define_class_under(mPeepmem, "Handle", rb_cObject);
    cPointer = rb_define_class_under(mPeepmem, "Pointer", rb_cObject);

    rb_define_singleton_method(mPeepmem, "open", peepmem_s_open, 1);

    rb_define_alloc_func(cHandle, peepmem_handle_s_allocate);
    rb_define_private_method(cHandle, "initialize", peepmem_handle_initialize, 1);
    rb_define_method(cHandle, "process_id", peepmem_handle_get_process_id, 0);
    rb_define_method(cHandle, "[]", peepmem_handle_aref, 1);
    rb_define_method(cHandle, "buffering", peepmem_handle_get_buffering, 0);
    rb_define_method(cHandle, "buffering=", peepmem_handle_set_buffering, 1);
    rb_define_method_nodoc(cHandle, "inspect", peepmem_handle_inspect, 0);
    rb_define_method(cHandle, "close", peepmem_handle_close, 0);

    rb_define_alloc_func(cPointer, peepmem_pointer_s_allocate);
    rb_define_private_method(cPointer, "initialize", peepmem_pointer_initialize, 2);
    rb_define_method(cPointer, "to_i", peepmem_pointer_to_i, 0);
    rb_define_method(cPointer, "to_s", peepmem_pointer_to_s, 0);
    rb_define_method_nodoc(cPointer, "inspect", peepmem_pointer_inspect, 0);
    rb_define_method(cPointer, "+", peepmem_pointer_add, 1);
    rb_define_method(cPointer, "-", peepmem_pointer_sub, 1);
    rb_define_method(cPointer, "[]", peepmem_pointer_aref, 1);
}
