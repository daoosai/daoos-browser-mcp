import asyncio, os, runpy, subprocess, sys, tempfile
from pathlib import Path
root=Path(tempfile.mkdtemp(prefix='session_',dir='/run/daoos-browser'));(root/'profile').mkdir()
xv=subprocess.Popen(['Xvfb',':99','-screen','0','1280x800x24','-nolisten','tcp','-ac'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
__import__('time').sleep(.3)
os.environ['DISPLAY']=':99'
sys.argv=['sandbox','--user-data-dir='+str(root/'profile')]
program='''import os,ctypes
print("uid",os.getuid(),"gid",os.getgid(),"profile",open("/proc/self/attr/current").read().strip(),flush=True)
print("uid_map",open("/proc/self/uid_map").read().strip(),flush=True)
libc=ctypes.CDLL(None,use_errno=True)
print("unshare user",libc.unshare(0x10000000),"errno",ctypes.get_errno(),flush=True)
'''
def execute(name,args):
    i=next(i for i,s in enumerate(args) if s.endswith('/chrome'))
    subprocess.run(args[:i]+['/usr/local/bin/python3','-c',program],check=False)
os.execvp=execute
try:runpy.run_path('/usr/local/bin/chromium-sandbox',run_name='__main__')
finally:xv.terminate();xv.wait();__import__('shutil').rmtree(root)
