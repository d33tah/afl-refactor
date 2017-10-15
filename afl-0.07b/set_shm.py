#!/usr/bin/env python

import ctypes
import os
import sys


def main():
    shmat = ctypes.cdll.LoadLibrary("libc.so.6").shmat
    shmat.restype = ctypes.POINTER(ctypes.c_char * 4096)

    try:
        trace_bits = shmat(int(os.environ['__AFL_SHM_ID']), 0, 0)[0]
    except ValueError:
        # NULL pointer access
        raise RuntimeError('shmat failed, returning NULL pointer')

    trace_bits[0] = chr(0x01)
    sys.stderr.write('%r reporting in\n' % sys.argv)


if __name__ == '__main__':
    main()
