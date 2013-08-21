Purpose
-------

Run an executable under strict SECCOMP mode
(http://en.wikipedia.org/wiki/Seccomp)

Compatiblity
------------

Linux only. Requires Kernel strict SECCOMP support ( Linux >= 2.6.12 )

How to build ?
--------------

$ make

How to use ?
--------------

$ ./seccomp_launcher binary_name binary_option1 ...

e.g

$ ./seccomp_launcher gdalinfo some.tif

Caveats
-------

Quality: Alpha / proof-of-concept.

Mostly dedicated (and tested) to run the GDAL/OGR binaries :
http://gdal.org/

Security checks in the supervisor (seccomp_launcher binary) not completely
implemented.

Limits
------

Do *NOT* use this software to run potentially hostile binaries. It is not meant
for that, and has now vulnerabilities if you use it for that purpose.

It is meant at running "trusted" binaries (i.e. that do not contain code that
is designed to defeat libseccomp_launcher.so), that can have flows that could
be triggered by hostile input data.
