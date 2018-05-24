# vdeplug\_agno

This is a libvdeplug plugin module to add encryption to a vde connection. It is based on the openssl library.

This module of libvdeplug4 can be used in any program supporting VDE like vde\_plug, kvm, qemu, user-mode-linux and virtualbox.

## install vdeplug\_agno

Requirements: vdeplug4 and openssl.

vdeplug\_slirp uses the auto-tools, so the standard procedure to build and install this vdeplug plugin module is the following:
```
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```

## usage examples (tutorial)

### Encrypt connection to the switch
```vde_plug agno://{vde:///tmp/myswitch}```

### Encrypt connection using the specified key and type of the non encrypted packet
```vde_plug agno:///tmp/my_keyfile[ethtype=copy]{vde:///tmp/myswitch}```

### Encrypt connection using random packets types
```agno://[ethtype=rand]{vxvde://234.0.0.1}```
