# `restore` utility fix from the dump/restore utilities

Background details on the [wiki](https://github.com/seborama/raspberrypi/wiki/Dump-Restore-crash-fix-update).

## Instructions

1. Download `dump-0.4b46.tar.gz (578.2 kB)` from the source code from the original official [repo](https://sourceforge.net/projects/dump/files/dump/0.4b46/).
1. Replace `restore/xattr.c` with the version in this [repo](xattr.c).
1. `./configure`
1. `make`
1. if all goes well, your new binary will be located at `restore/restore`
1. you can run `make install` if you want so.
