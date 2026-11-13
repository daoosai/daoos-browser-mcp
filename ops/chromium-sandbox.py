#!/usr/local/bin/python3
"""Filesystem sandbox for the entire Chromium process, including its broker.
Chromium also keeps its native renderer sandbox. Profiles of other sessions,
the gateway environment, database passwords, vault keys and /data are absent.
"""
import os
from pathlib import Path
import sys

profile = next((x.split('=',1)[1] for x in sys.argv[1:] if x.startswith('--user-data-dir=')),None)
if not profile: raise SystemExit('Missing persistent profile')
profile = Path(profile).resolve()
runtime = Path('/run/daoos-browser').resolve()
if profile.parent.parent != runtime or not profile.parent.name.startswith('session_') or profile.name != 'profile':
    raise SystemExit('Invalid profile directory')
display = os.environ['DISPLAY']
if not display.startswith(':') or not display[1:].isdigit(): raise SystemExit('Invalid display')
xsock = '/tmp/.X11-unix/X'+display[1:]
args = ['bwrap','--die-with-parent','--new-session','--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts',
    '--clearenv','--setenv','HOME','/tmp','--setenv','DISPLAY',display,
    '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--proc','/proc','--dev','/dev',
    '--tmpfs','/tmp','--tmpfs','/run','--dir','/etc']
for path in ['/usr','/lib','/lib64','/bin','/sbin','/ms-playwright','/etc/fonts','/etc/ssl','/etc/passwd','/etc/group','/etc/nsswitch.conf','/etc/resolv.conf','/etc/hosts']:
    if Path(path).exists(): args += ['--ro-bind',path,path]
args += ['--bind',str(profile.parent),str(profile.parent),'--dir','/tmp/.X11-unix','--ro-bind',xsock,xsock,
    '--chdir','/tmp',str(Path(os.environ.get('CHROMIUM_BINARY','/ms-playwright/chromium-1248/chrome-linux64/chrome'))),*sys.argv[1:]]
os.execvp('bwrap',args)
