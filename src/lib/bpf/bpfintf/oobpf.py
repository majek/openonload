# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
'''
Python bindings for OpenOnload oobpf library,
a library to manage Onload's BPF programs and data.
See onload/oobpf.h for detailed description of function calls and
data structures.
'''

import oobpfll as ll
import ctypes as ct
import subprocess
import errno

# reexport useful symbols
AttachPoint = ll.AttachPoint
Exception = ll.Exception
elf_install = ll.elf_install
elf_uninstall = ll.elf_uninstall
sizeof2 = ll.sizeof2


_drv = ll.open_driver()
_drv_fd = _drv.fileno()
ll.check_version(_drv_fd)
_libc = ct.CDLL("libc.so.6")


def if_nametoindex(dev):
    ifindex = _libc.if_nametoindex(dev)
    if ifindex < 0:
        raise Exception(-1)
    return ifindex


def fixup_type(v, V):
    if not isinstance(v, V):
        return V(v)
    assert sizeof2(v) == sizeof2(V)
    return v


def redirect_ENOENT(Exception_class):
    def wrapper1(func):
        def wrapper2(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if e.errno != errno.ENOENT:
                    raise
                raise Exception_class()
        return wrapper2
    return wrapper1


class Elf(object):
    def __init__(self, file_name=None, image=None):
        if file_name:
            self.elf_obj = ll.open_elf(file_name)
        elif image:
            self.elf_obj = ll.open_elf_memory(image)
        else:
            raise Exception(-1, errno_=ENOENT)

    def __del__(self):
        ll.close_elf(self.elf_obj)

    def load_func(self, func_name, prog_type):
        fd, _ = ll.elf_load_prog(_drv_fd, self.elf_obj, func_name, prog_type,
                                 log_level=0xFFFFFFFF)
        return fd

    def provide_map(map_name, fd):
        ll.elf_provide_map(_drv_fd, self.elf_obj, map_name, fd)

    def get_progs():
        return ll.elf_get_progs(self.elf_obj)

    def get_maps(self):
        maps = ll.elf_get_maps(self.elf_obj)
        return maps


class Map(object):
    def __init__(self, elf, map_fd, table_name, Key, Value):
        # we keep reference to elf to make sure map_fd does not go away
        self.elf, self.table_name, self.map_fd, self.Key, self.Value = \
        elf,      table_name,      map_fd,      Key,      Value

    @redirect_ENOENT(StopIteration)
    def next(self, key):
        next_key = self.Key()
        ll.map_get_next_key(_drv_fd, self.map_fd, key, next_key)
        return next_key

    @redirect_ENOENT(KeyError)
    def __getitem__(self, key):
        key = fixup_type(key, self.Key)
        val = self.Value()
        ll.map_lookup_elem(_drv_fd, self.map_fd, key, val)
        return val

    @redirect_ENOENT(KeyError)
    def __delitem__(self, key):
        key = fixup_type(key, self.Key)
        ll.map_delete_elem(_drv_fd, self.map_fd, key)
        return val

    @redirect_ENOENT(KeyError)
    def __setitem__(self, key, val):
        key = fixup_type(key, self.Key)
        val = fixup_type(val, self.Value)
        ll.map_update_elem(_drv_fd, self.map_fd, key, val, flags=0)
        return val

    # boiler plate functions from bcc
    def itervalues(self):
        for key in self:
            # a map entry may be deleted in between discovering the key and
            # fetching the value, suppress such errors
            try:
                yield self[key]
            except KeyError:
                pass

    def iteritems(self):
        for key in self:
            try:
                yield (key, self[key])
            except KeyError:
                pass

    def items(self):
        return [item for item in self.iteritems()]

    def values(self):
        return [value for value in self.itervalues()]

    def clear(self):
        # default clear uses popitem, which can race with the bpf prog
        for k in self.keys():
            try:
                self.__delitem__(k)
            except KeyError:
                pass

    def zero(self):
        # Even though this is not very efficient, we grab the entire list of
        # keys before enumerating it. This helps avoid a potential race where
        # the value assignment changes a hash table bucket that is being
        # enumerated by the same loop, and may lead to a hang.
        for k in list(self.keys()):
            self[k] = self.Value()


    class Iter(object):
        def __init__(self, table):
            self.table = table
            self.key = None
        def __iter__(self):
            return self
        def __next__(self):
            return self.next()
        def next(self):
            self.key = self.table.next(self.key)
            return self.key

    def __iter__(self):
        return self.Iter(self)

    def iter(self): return self.__iter__()
    def keys(self): return self.__iter__()


class BPF(object):
    XDP = ll.BPF_PROG_TYPE_XDP

    class Function(object):
        def __init__(self, bpf, name, fd):
            self.bpf = bpf
            self.name = name
            self.fd = fd

    def __init__(self, file_name=None, image=None):
        self.elf = Elf(file_name=file_name, image=image)

    def load_func(self, func_name, prog_type):
        fd = self.elf.load_func(func_name, prog_type)
        return BPF.Function(self, func_name, fd)

    def attach_xdp(self, dev, fn, flags=0, stack_name=None, attach_point=AttachPoint.XDP_INGRESS):
        ifindex = 0
        if dev:
            ifindex = if_nametoindex(dev)
        ll.prog_attach(drv_fd=_drv_fd, prog_fd=fn.fd,
                       attach_point=attach_point,
                       ifindex=ifindex, stack_name=stack_name)

    def remove_xdp(self, dev, flags=0, stack_name=None, attach_point=AttachPoint.XDP_INGRESS):
        ifindex = 0
        if dev:
            ifindex = if_nametoindex(dev)
        ll.prog_detach(drv_fd=_drv_fd, attach_point=attach_point,
                        ifindex=ifindex, stack_name=stack_name)


    def get_table(self, table_name, Key=None, Value=None):
        maps = self.elf.get_maps()
        m = None
        for mi in maps:
            if mi['name'] == table_name:
                m = mi
                continue

        if not m:
            raise Exception(-1, errno_=errno.ENOENT, msg="No map %s"%(table_name,))

        fd, key_size, value_size = \
            m['fd'], m['info']['key_size'], m['info']['value_size']

        def get_default_type(size):
            default_types = {
              1: ct.c_byte,
              2: ct.c_ushort,
              4: ct.c_uint,
              8: ct.c_ulonglong,
            }
            return default_types.get(size, ct.c_byte * size)

        if Key is None:
            Key = get_default_type(key_size)
        if Value is None:
            Value = get_default_type(value_size)

        assert sizeof2(Key) == key_size
        assert sizeof2(Value) == value_size

        return Map(self.elf, fd, table_name, Key, Value)
