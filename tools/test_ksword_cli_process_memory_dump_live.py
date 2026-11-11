"""Dump this test process's own allocation through the production CLI.

The R0 case requires an already loaded KswordARK device; this test never loads
or changes the driver. Temporary output files are confined to a new directory.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli',required=True,type=Path)
    parser.add_argument('--backend',choices=('r0','r3','both'),default='r3')
    args=parser.parse_args()
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]
    kernel.VirtualAlloc.restype=ctypes.c_void_p
    kernel.VirtualFree.argtypes=[ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD]
    kernel.VirtualFree.restype=wintypes.BOOL
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4)]
    kernel.GetProcessTimes.restype=wintypes.BOOL
    created=wintypes.FILETIME(); exited=wintypes.FILETIME(); kernel_time=wintypes.FILETIME(); user_time=wintypes.FILETIME()
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(),ctypes.byref(created),ctypes.byref(exited),ctypes.byref(kernel_time),ctypes.byref(user_time)):
        raise ctypes.WinError(ctypes.get_last_error())
    creation=(created.dwHighDateTime<<32)|created.dwLowDateTime
    size=150000
    pointer=kernel.VirtualAlloc(None,size,0x3000,0x04) # MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE
    if not pointer: raise ctypes.WinError(ctypes.get_last_error())
    expected=bytes(i%251 for i in range(size))
    ctypes.memmove(pointer,expected,size)
    try:
        with tempfile.TemporaryDirectory(prefix='ksword-live-dump-') as temp:
            for backend in (('r0','r3') if args.backend=='both' else (args.backend,)):
                output=Path(temp)/(backend+'.bin')
                command=[str(args.cli.resolve()),'process','memory','dump','--pid',str(os.getpid()),
                         '--address',hex(pointer),'--size',str(size),'--output',str(output),'--backend',backend,'--json']
                if backend=='r0': command+=['--creation-time',str(creation)]
                result=subprocess.run(command,capture_output=True,timeout=60)
                try: data=json.loads(result.stdout.decode('utf-8'))
                except Exception: raise AssertionError((result.returncode,result.stdout,result.stderr))
                assert result.returncode==0 and data['backend']==backend and data['data']['complete'],(result.returncode,data,result.stderr)
                if backend=='r0': assert not data['data']['target']['r3HandleRetained'],data
                assert output.read_bytes()==expected
                # A second invocation must preserve the existing destination.
                repeat=subprocess.run(command,capture_output=True,timeout=60)
                repeat_data=json.loads(repeat.stdout.decode('utf-8'))
                assert repeat.returncode!=0 and not repeat_data['data']['published'] and output.read_bytes()==expected,(repeat.returncode,repeat_data)
                assert not list(Path(temp).glob('*.tmp'))
                print(f'PROCESS_MEMORY_DUMP_LIVE_PASS backend={backend} bytes={size} no_overwrite=true')
    finally:
        if not kernel.VirtualFree(pointer,0,0x8000): raise ctypes.WinError(ctypes.get_last_error())

if __name__=='__main__':main()
