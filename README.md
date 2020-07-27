# vdeplug\_agno

This is a libvdeplug plugin module to add encryption to a vde connection. It is based on the libwolfssl-dev library.

This module of libvdeplug4 can be used in any program supporting VDE like vde\_plug, kvm, qemu, user-mode-linux and virtualbox.

## install vdeplug\_agno

Requirements: [vdeplug4](https://github.com/rd235/vdeplug4) and libwolfssl-dev.

vdeplug\_agno uses cmake, so the standard procedure to build and install this vdeplug plugin module is the following:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## usage examples

The following examples are UVDELs (Unified VDE Locator) to be used with programs
supporting vde as specified by the syntax of those programs.

### Encrypt connection to the switch
```agno://{vde:///tmp/myswitch}```

### Encrypt connection using the specified key and type of the non encrypted packet
```agno:///tmp/my_keyfile[ethtype=copy]{vde:///tmp/myswitch}```

### Encrypt connection using random packets types
```agno://[ethtype=rand]{vxvde://234.0.0.1}```

### Create a vde namespace connected to a vxvde network with encrypted traffic
```vdens agno:///tmp/my_keyfile{vxvde://}```

See the man page (libvdeplug_agno) for further information.

## License

GNU Lesser General Public License v 2.1 or later.

It uses libwolfssl: see the [wolfssl FLOSS exception](https://www.wolfssl.com/docs/floss-exception/).