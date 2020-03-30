# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
'''
Python bindings for OpenOnload oobpf library,
a library to manage Onload's BPF programs and data.
See onload/oobpf.h for detailed description of function calls and
data structures.
'''

from ctypes import *
import os


drv_name = '/dev/onload_bpf'

BPF_PROG_TYPE_XDP = 6 # from 'uapi/linux/bpf.h'

bpflib = CDLL('oobpfintf0.so', use_errno=1)


def open_driver():
    return open(drv_name, "r")


class Exception(Exception):
    def __init__(self, rc_, msg=None, errno_ = None):
        assert rc_ == -1
        if errno_ is None:
            errno_ = get_errno()
        self.errno = errno_
        self.msg = msg

    def __str__(self):
        if not self.msg and not self.errno:
            return 'Unknown error'
        msg = self.msg or ''
        if self.errno:
            if msg:
                msg += ' '
            try:
                msg += '%s (%d)' % (os.strerror(self.errno), self.errno)
            except ValueError:
                msg += str(self.errno)
        return msg


class Flags:
    NO_PREALLOC = 0x0001
    RDONLY =      0x0008
    WRONLY =      0x0010
    PROG_ALL = RDONLY | WRONLY
    MAP_ALL = RDONLY | WRONLY | NO_PREALLOC

class AttachPoint:
    XDP_INGRESS = 0
    MAX = 1

class Elf(Structure):
    pass

class ElfSection(Structure):
    pass

class ElfProg(Structure):
    _fields_ = [("section", POINTER(ElfSection)),
    ]

class ElfLoadAttrs(Structure):
    _fields_ = [("struct_size", c_ulong),
                ("flags", c_uint),
                ("log_level", c_uint),
                ("log_size", c_ulong),
                ("log_buf", POINTER(c_char)),
    ]

class MapInfo(Structure):
    _fields_ = [("type", c_uint),
                ("id", c_uint),
                ("key_size", c_uint),
                ("value_size", c_uint),
                ("max_entries", c_uint),
                ("map_flags", c_uint),
    ]

class ElfMap(Structure):
    _fields_ = [("info", POINTER(MapInfo)),
                ("fd", c_int),
                ("name", c_char_p),
    ]


BPF_OBJ_NAME_LEN = 16
CI_CFG_STACK_NAME_LEN = 64

stack_name_t = c_char * CI_CFG_STACK_NAME_LEN
bpf_name_t = c_char * BPF_OBJ_NAME_LEN

map_name_t = bpf_name_t

class MapCreateArg(Structure):
    _fields_ = [("map_type", c_uint),
                ("key_size", c_uint),
                ("value_size", c_uint),
                ("max_entries", c_uint),
                ("map_flags", c_uint),
                ("numa_node", c_uint),
                ("map_name", map_name_t),
    ]

class ProgAttachFlags:
  REPLACE = 0x01

class ProgAttachArg(Structure):
    _fields_ = [("prog_fd", c_int),
                ("flags", c_uint),
                ("attach_point", c_uint),
                ("ifindex", c_uint),
                ('stack', stack_name_t),
               ]

class ProgTestRunArg(Structure):
    _fields_ = [("iterations", c_uint),
                ("result", c_uint),
                ("ticks", c_ulonglong),
                ("pkt_len", c_uint),
                ("max_pkt_len", c_uint),
                ('pkt', POINTER(c_char)),
               ]

class BpfInsn(Structure):
    _fields_ = [(('op'), c_uint64)]

class ProgLoadArgs(Structure):
    _fields_ = [
        ('prog_type', c_uint),
        ('insn_cnt', c_uint),
        ('insns', POINTER(BpfInsn)),
        ('license', c_char_p),
        ('log_level', c_uint),
        ('log_size', c_uint),
        ('log_buf', POINTER(c_char)),
        ('kern_version', c_uint),
        ('prog_flags', c_uint),
        ('prog_name', bpf_name_t),
        ('prog_ifindex', c_uint),
        ('expected_attach_type', c_uint),
    ]

class ProgInfo(Structure):
    _fields_ = [
        ('type', c_uint),
        ('jited_prog_len', c_uint),
        ('xlated_prog_len', c_uint),
        ('jited_prog_insns', POINTER(BpfInsn)),
        ('xlated_prog_insns', POINTER(BpfInsn)),
        ('nr_map_ids', c_uint),
        ('name', bpf_name_t),
    ]


def getdict(struct):
    return dict((field, getattr(struct, field)) for field, _ in struct._fields_)


def sizeof2(obj):
    # if this is a ctypes object
    if getattr(obj, '__sizeof__', None):
        return sizeof(obj)
    else:
        '''assume string buffer of sort'''
        return len(obj)


def open_elf(file_name):
    elf_obj = POINTER(Elf)()
    rc = bpflib.oo_bpf_open_elf(c_char_p(file_name), byref(elf_obj))
    if rc != 0:
        raise Exception(rc)
    return elf_obj


def open_elf_memory(image):
    elf_obj = POINTER(Elf)()
    rc = bpflib.oo_bpf_open_elf_memory(c_char_p(image), len(image), byref(elf_obj))
    if rc != 0:
        raise Exception(rc)
    return elf_obj


def close_elf(elf_obj):
    bpflib.oo_bpf_close_elf(elf_obj)


def elf_get_maps(elf_obj):
    null_ptr = POINTER(c_int)()
    cnt = bpflib.oo_bpf_elf_get_maps(elf_obj, null_ptr, 0, sizeof(ElfMap))
    if cnt == 0:
        return []
    if cnt < 0:
        raise Exception(cnt)
    maps = (cnt * ElfMap)()
    cnt = bpflib.oo_bpf_elf_get_maps(elf_obj, cast(maps, POINTER(ElfMap)), cnt,
                                     sizeof(ElfMap))
    if cnt < 0:
        raise Exception(cnt)

    # dereference info ptr
    return [dict(getdict(m), info=getdict(m.info.contents)) for m in list(maps)]


def elf_provide_map(drv_fd, elf_obj, name, fd):
    rc = bpflib.oo_bpf_elf_provide_map(drv_fd, elf_obj, c_char_p(name), fd)
    if rc != 0:
        raise Exception(rc)


def elf_get_progs(elf_obj):
    null_ptr = POINTER(c_int)()
    cnt = bpflib.oo_bpf_elf_get_progs(elf_obj, null_ptr, 0, sizeof(ElfProg))
    if cnt == 0:
        return []
    if cnt < 0:
        raise Exception(cnt)
    progs = (cnt * ElfProg)()
    cnt = bpflib.oo_bpf_elf_get_progs(elf_obj, cast(progs, POINTER(ElfProg)),
                                      cnt, sizeof(ElfProg))
    if cnt < 0:
        raise Exception(cnt)
    return [getdict(progs[i]) for i in range(cnt)]


def elf_load_prog(drv_fd, elf_obj, section_name, prog_type=BPF_PROG_TYPE_XDP,
                  flags=0, log_level=0, log_size=65536):
    log = (log_size * c_char)()
    attrs = ElfLoadAttrs(
            sizeof(ElfLoadAttrs), flags,
            log_level, log_size,
            cast(log, POINTER(c_char)))
    rc = bpflib.oo_bpf_elf_load_prog(
            drv_fd, elf_obj,
            c_char_p(section_name),
            prog_type,
            byref(attrs))
    if rc < 0:
        raise Exception(rc, msg=c_char_p(addressof(log)).value)
    return rc, c_char_p(addressof(log)).value


def elf_install(file_name, section_name,
                attach_point=AttachPoint.XDP_INGRESS,
                flags=Flags.PROG_ALL,
                log_level=0, log_size=65536):
    log = (log_size * c_byte)()
    attrs = ElfLoadAttrs(
            sizeof(ElfLoadAttrs), flags,
            log_level, log_size,
            cast(log, POINTER(c_char)))
    rc = bpflib.oo_bpf_elf_install(
            c_char_p(file_name),
            c_char_p(section_name),
            attach_point, byref(attrs))
    if rc < 0:
        raise Exception(rc, msg=c_char_p(addressof(log)).value)
    return c_char_p(addressof(log)).value


def elf_uninstall(attach_point=AttachPoint.XDP_INGRESS):
    bpflib.oo_bpf_elf_uninstall(attach_point)


def map_create(drv_fd, map_type, name, key_size, value_size,
               max_entries, map_flags=0, numa_node=0):
    ''' returns fd to newly created map '''
    attrs = MapCreateArg(
            map_type, key_size, value_size, max_entries, map_flags,
            numa_node, name)
    rc = bpflib.oo_bpf_map_create(
        drv_fd, byref(attrs))
    if rc < 0:
        raise Exception(rc)
    return rc


def map_get_info(drv_fd, map_fd):
    map_info = MapInfo()
    rc = bpflib.oo_bpf_map_get_info(drv_fd, map_fd, byref(map_info))
    if rc < 0:
        raise Exception(rc)
    return getdict(map_info)


def map_lookup_elem(drv_fd, map_fd, key, value, flags=0):
    '''
    value - ctype object to be filled in with content of the map at the key
    '''
    rc = bpflib.oo_bpf_map_lookup_elem(drv_fd, map_fd, byref(key),
                                        byref(value), flags)
    if rc < 0:
        raise Exception(rc)


def map_update_elem(drv_fd, map_fd, key, value, flags):
    rc = bpflib.oo_bpf_map_update_elem(drv_fd, map_fd, byref(key),
                                       byref(value), flags)
    if rc < 0:
        raise Exception(rc)


def map_delete_elem(drv_fd, map_fd, key, flags=0):
    rc = bpflib.oo_bpf_map_delete_elem(drv_fd, map_fd, byref(key), flags)
    if rc < 0:
        raise Exception(rc)


def map_get_next_key(drv_fd, map_fd, key, next_key, flags=0):
    '''
    next_key - ctype object to be filled in with content of the map at the key
    '''
    rc = bpflib.oo_bpf_map_get_next_key(
            drv_fd, map_fd,
            byref(key) if key is not None else 0,
            byref(next_key), flags)
    if rc < 0:
        raise Exception(rc)


def ctype_fixup(Type, v):
    if isinstance(v, Type):
        return v
    if isinstance(v, (list, tuple)):
        return Type(*v)
    if isinstance(v, dict):
        return Type(**v)

def map_info_compatible(a,b):
    a = ctype_fixup(MapInfo, a)
    b = ctype_fixup(MapInfo, b)
    rc = bpflib.oo_bpf_map_info_compatible(byref(a), byref(b))
    return rc


def check_version(drv_fd):
    return bpflib.oo_bpf_check_version(drv_fd)

def prog_load(drv_fd, **kwargs):
    '''
    see ProgLoadArgs,
    insn - object ctypes or byte buffer
    note ProgLoadArgs.insn_cnt is derived from insn type/len
    '''
    args = dict(prog_flags=0,
                log_level=0, log_size=65536, prog_type=0,
                insns=None, license=b'GPL')
    args.update(kwargs)
    log_buf = (args['log_size'] * c_char)()
    args['log_buf'] = cast(log_buf, POINTER(c_char))
    o_isns = args['insns']
    args['insns'] = cast(o_isns, POINTER(BpfInsn))
    args['insn_cnt'] = sizeof2(o_isns) // sizeof(BpfInsn)
    if args.get('license', None):
        args['license'] = c_char_p(args['license'])
    a = ProgLoadArgs(**args)
    rc = bpflib.oo_bpf_prog_load(drv_fd, byref(a))
    if rc < 0:
        raise Exception(rc, msg=c_char_p(addressof(log_buf)).value)
    return rc, c_char_p(addressof(log_buf)).value


def prog_get_by_attachment(drv_fd, **kwargs):
    ''' returns fd to prog '''
    args = dict(attach_point=AttachPoint.XDP_INGRESS)
    args.update(kwargs)
    a = ProgAttachArg(**args)
    rc = bpflib.oo_bpf_prog_get_by_attachment(drv_fd, byref(a))
    if rc < 0:
        raise Exception(rc)
    return rc


def prog_attach(drv_fd, **kwargs):
    args = dict(attach_point=AttachPoint.XDP_INGRESS)
    args.update(kwargs)
    a = ProgAttachArg(**args)
    rc = bpflib.oo_bpf_prog_attach(drv_fd, byref(a))
    if rc < 0:
        raise Exception(rc)


def prog_detach(drv_fd, **kwargs):
    args = dict(attach_point=AttachPoint.XDP_INGRESS, prog_fd=-1)
    args.update(kwargs)
    a = ProgAttachArg(**args)
    rc = bpflib.oo_bpf_prog_detach(drv_fd, byref(a))
    if rc < 0:
        raise Exception(rc)


def prog_test_run(prog, **kwargs):
    '''
    Params:
      pkt - ctypes buffer of size max_pkt_len
      pkt_len - size used by the packet
    On success (rc = 0):
      pkt - content potentially updated
      pkt_len - new pkt length
    '''
    args = dict(max_pkt_len=sizeof(kwargs['pkt']), pkt_len=sizeof(kwargs['pkt']),
                pkt=cast(kwargs['pkt'], POINTER(c_char)))
    args.update(kwargs)
    a = ProgTestRunArg(**args)
    rc = bpflib.oo_bpf_prog_test_run(prog, byref(a))
    if rc < 0:
        raise Exception(rc)
    return dict(iterations=a.iterations, ticks=a.ticks, pkt_len=a.pkt_len, result=a.result)


def prog_get_all(fd):
    nullptr = POINTER(ProgAttachArg)()
    rc = bpflib.oo_bpf_prog_get_all(fd, 0, nullptr)
    if rc < 0:
        raise Exception(rc)
    if rc == 0:
        return []
    cnt = rc
    attaches = (ProgAttachArg * cnt)()
    rc = bpflib.oo_bpf_prog_get_all(fd, cnt, cast(attaches, POINTER(ProgAttachArg)))
    if rc < 0:
        raise Exception(rc)
    return [getdict(a) for a in attaches]


def prog_get_info(fd):
    '''
    returns dictionary with information on the program,
    see ProgInfo, note that `*_prog_len` are encoded with type of
        `jited_prog_insns` and `xlated_prog_insns`
    '''
    info = ProgInfo()
    rc = bpflib.oo_bpf_prog_get_info(fd, byref(info))
    if rc < 0:
        raise Exception(rc)
    d = getdict(info)
    d['jited_prog_insns'] = cast(info.jited_prog_insns, POINTER(BpfInsn * info.jited_prog_len))
    d.pop('jited_prog_len')
    d['xlated_prog_insns'] = cast(info.xlated_prog_insns, POINTER(BpfInsn * info.xlated_prog_len))
    d.pop('xlated_prog_len')
    return d
