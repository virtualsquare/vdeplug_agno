# vdeplug\_agno

This is a libvdeplug plugin module to add encryption to a vde connection. It is based on the openssl library.

This module of libvdeplug4 can be used in any program supporting VDE like vde\_plug, kvm, qemu, user-mode-linux and virtualbox.

## install vdeplug\_agno

Requirements: [vdeplug4](https://github.com/rd235/vdeplug4) and openssl.

vdeplug\_agno uses the auto-tools, so the standard procedure to build and install this vdeplug plugin module is the following:
```
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```

## usage examples (tutorial)

The following examples are UVDELs (Unified VDE Locator) to be used with programs
supporting vde as specified by the syntax of those programs.

### Encrypt connection to the switch
```agno://{vde:///tmp/myswitch}```

### Encrypt connection using the specified key and type of the non encrypted packet
```agno:///tmp/my_keyfile[ethtype=copy]{vde:///tmp/myswitch}```

### Encrypt connection using random packets types
```agno://[ethtype=rand]{vxvde://234.0.0.1}```

## Create a vde namespace connected to a vxvde network with encrypted traffic
```vdens agno:///tmp/my_keyfile{vxvde://}```

See the man page (libvdeplug_agno) for further information.
