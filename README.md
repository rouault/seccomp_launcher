Purpose
-------

Run an executable under strict SECCOMP mode (http://en.wikipedia.org/wiki/Seccomp)
to avoid hostile input files to exploit software defects and lead to arbitrary
code execution, theft, tampering or destruction of data, unwanted Web access.

Mostly dedicated (and tested) to run the GDAL/OGR binaries : http://gdal.org/

Compatiblity
------------

Linux only. Requires Kernel strict SECCOMP support ( Linux >= 2.6.12 )

To check if your kernel supports SECCOMP, check that
"grep SECCOMP /boot/config-XXXXXXX" shows "CONFIG_SECCOMP=y"

How to build ?
--------------

$ make

How to use ?
------------

Usage: ./seccomp_launcher [-ro | -rw | -ro_extended | -rw_extended] a_binary binary_option1...

Options:
 -ro (default): set sandbox in read-only mode, restricted to files explicitely
                listed on the command line or white-listed in seccomp_launcher.
 -ro_extended : set sandbox in read-only mode (access to all files readable by
                the current user).
 -rw :          set sandbox in read/write mode, restricted to files explicitely
                listed on the command line or white-listed in seccomp_launcher.
 -rw_extended : set sandbox in full read/write mode (access to all files
                readable by the current user).

Examples
--------

$ ./seccomp_launcher gdalinfo some.tif

$ ./seccomp_launcher -rw gdal_translate some.tif target.tif

$ ./seccomp_launcher -rw ogr2ogr -f filegdb out.gdb poly.gdb -progress

$ ./seccomp_launcher python swig/python/samples/gdalinfo.py some.tif

Status
------

Quality: Alpha / proof-of-concept.

Limits
------

Do *NOT* use this software to run potentially hostile binaries. It is not meant
for that, and has known vulnerabilities (that are inherent to its design) if
you use it for that purpose.

It is meant at running "trusted" binaries (i.e. that do not contain code that
is designed to defeat libseccomp_preload.so), that potentially have defects that
could be exploited by hostile input data.

seccomp_launcher will only work against binaries that are dynamically linked
against the GNU libc, and that do not use directly system calls. This is the
case of typical Linux binaries. Binaries that would not follow those constraints
will be aborted by the SECCOMP mechanism.

Software architecture
---------------------

The seccomp_launcher software is made of two parts :

* the seccomp_launcher binary itself, which is a process that launches the
  user binary with the libseccomp_preload.so library loaded with LD_PRELOAD.
  It communicates with libseccomp_preload.so with a pipe, and executes the
  system calls that the user binaries want to execute, on its behalf.
  seccomp_launcher is where the security is implemented, and thus the part that
  must be carefully coded to avoid abuses. The commands received from the user
  binaries through the pipes are supposed to be hostile, and must be checked.

  The list of system calls that are delegated by the user process to
  seccomp_launcher is in the seccomp_launcher.h file.

  Note: seccomp_launcher can be edited to adjust the security policies. It
  could also likely been written in another language than C. A port to Python
  with the use of the os library would likely be doable.

* the libseccomp_preload.so dynamic library that is injected into the user binary
  thanks to LD_PRELOAD. It has an initializer function that will do a few actions
  while still in normal (unsecure mode), like preloading dynamic libraries used by
  Python or GDAL/OGR (e.g. the PROJ.4 library that is loaded with dlopen()
  mechanism). Once those initializations are done, the init function runs the
  prctl( PR_SET_SECCOMP, 1, 0, 0, 0 ) system call. From that point, the only
  system calls that are allowed in the current thread are read(), write(),
  exit() and sigreturn(). Any attempt to execute another system call causes the
  process to be immediately killed by the Linux kernel. As this is a particularly
  restricted set of operations, that would restrict severly what could be done,
  libseccomp_preload.so overrides most of the usual entry points of the GNU libc
  to provide an implementation compatible with the SECCOMP limits. Different
  implementation exists :

     - file oriented operations ( fopen(), fread(), etc... ) are passed to
       the seccomp_launcher binary (through the pipe it has created) that checks
       if they are legitim or not, according to the mode in which it has been
       launched, and run them on the behalf of the user process if they are
       authorized

     - other GNU libc functions related to threading, etc... have just a stub
       implementation that does nothing.

Author
------

Even Rouault, <even dot rouault at mines-paris dot org>

License
-------

X/MIT. See LICENSE.TXT

Related projects
----------------

A close project is seccompsandbox, the Google Seccomp Sandbox for Linux,
http://code.google.com/p/seccompsandbox/wiki/overview . seccompsandbox uses
much more clever techniques that seccomp_launcher. It runs probably faster, but
its correctness is also likely harder to verify due to the advanced
techniques used. seccomp_launcher uses absolutely no assembler code, and thus
can potentially be used on any hardware platform supported by Linux (e.g.
ARM, although at the time of writing only x86_64 has been tested).

What to contribute ?
--------------------

Reviews of seccomp_launcher.c for potential holes in the security checks are
welcome !

Missing overrides of GNU libc in seccomp_preload.c are also welcome.

