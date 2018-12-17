# vdeplug_agno

This is a libvdeplug cryptographic module that implements Layer 2 encryption. Layer 2 encryption  is  protocol  agnostic  (hence  agno), because all the traffic is  encrypted,  layer  2  protocol  packets included.

This implementation is based on the libsodium library. This module of libvdeplug4 can be used in any program  supporting  VDE, like vde_plug, kvm, qemu, user-mode-linux and virtualbox.

## Install vdeplug_agno

 Requirements: [vdeplug4](https://github.com/rd235/vdeplug4) and [libsodium](https://libsodium.gitbook.io/doc/).

vdeplug_agno uses the auto-tools, so the standard procedure to build and install this vdeplug plugin module is the following:
```
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```

## Vxvde and vxvdex

vxvde is a plug-in to join VXLAN. It encapsulate the Ethernet traffic of the VDE LAN in UDP packets sent to an IP multicast address. Any user can launch the plug-in without restrictions. Using only vxvde the system is secure only if users don't have shell access to the physical machine. The only kind of remote access that can be given is the access to VMs. The virtual network configuration of the VM can't be decided by the user. If we want to allow shell access to the real machine [vxvde](https://github.com/rd235/vxvdex) can be used. vxvdex however allows shell access only to a network namespace. If users access to the real network must be granted to the users the virtual traffic must be encrypted. Otherwise it would be possible for the user to connect to a vxvde network or to capture traffic directly from the the network interface.

## agno
agno is a nesting plug-in that implements this. It can be used to make sure that the traffic is encrypted and confidential when it leaves the physical machine through the network interface of the physical machines. In this way only users having the key used by agno to encrypt the traffic will be capable of decrypting the traffic and communicate with VMs using agno.
VMs send and receive plain traffic. The cryptography is completely transparent to the virtual hosts.

### agno details

When an Ethernet packet is encrypted by agno the output has its payload encrypted and all the packet (Ethernet header included) is authenticated.
The encrypted packet can't be routed without being decrypted first because the IP header would be encrypted and the MAC addresses can't be changed without breaking the integrity of the packet.
Please, read man page libvdeplug_agno(1) for more informations about the VDE URL syntax of agno.
agno uses XChaCha20-Poly1305 authenticated encryption algoritm.

## Key management
Key management is up to the user.

### Generation
Any method can be used to generate a key as long as it provides strong assurance that a key is fresh when it is generated.
The key must be 256-bit (32 bytes) long and must be encoded with hexadecimal characters.
A convenient way to do this is to use openssl random number generator.
```console
$ openssl rand -out keyfile -hex 32
```
Note: this command uses by default random data contained in ~/.rnd to seed the random number generator. This can be deleted without problems and, if it doesn’t exist, it is automatically generated. It is important to make sure that none of these files is reused.

### Transmission
Key files must be locally available on every host that uses agno. The exchange must be done in a manner that provides strong assurance of confidentiality and against "replay".
Suitable methods could be out-of-band methods, scp, shipping by secure e-mail, copy-and-paste from ssh session or FTPS.
If using NFS, the keys to share with other physical hosts could be put in a shared directory.
Otherwise keys could be put in a system directory as /etc/agno/, containing subdirectories like vxvde/, tap/, other/. The directory /etc/agno could be assigned to a user that handles the management of the keys (agno_root).

### Storage
The key owners must make sure that the key files can be read only by authorized users on every host by setting the right permissions.
We could also create groups for accessing key files, e.g. vxvde_234_0_0_1 or tap0.
The management of permissions becomes very similar to the one in vxvdex.

## agno + vxvde
One of the simplest usages of agno is with vxvde, which is, as said before, the reason why it is needed.
The administrators may decide to assign a key to a vxvde IP multicast so that to see all the authorized traffic it is enough to use agno with that key. All the VMs connected to that vxvde IP address must use agno with the specified key.
```console
vde_plug agno:///etc/agno/vxvde/234.0.0.1{vxvde://234.0.0.1}
```
In this example/etc/agno/vxvde/234.0.0.1 is the path of the file containing the key that should be used to connect with IP multicast address 234.0.0.1.
A user could of course define his own key to start encrypt the communication of his own VMs.
Of course, as we are not using vxvdex, a user could mistakenly use the wrong key; in this case it is almost as the VM started is on his own VLAN. In fact it won’t receive any traffic from the VMs using the other key.
All the VMs using the same "wrong" key will anyway be able to communicate; in this way we are creating a sort of agno VLAN. This is discouraged because it makes the network inefficient.

# agno + udp
agno can be used combined with the udp plug-in to create an encrypted connectionless point-to-point connection between two VDE-supporting tools. In this way we are creating an encrypted vde cable.

```console
# on host a
vde_plug switch:// agno://~udp_key{"udp://1000->hostb:2000"}
# on host b
vde_plug switch:// agno://~udp_key{"udp://2000->hosta:1000"}
```

![agno + udp](https://github.com/rd235/vdeplug_agno/blob/libsodium_static/img/agno%2Budp.png)

## agno + tap + brctl
Using a tap interface and the bridge of the Linux kernel (brctl) we can forward virtual traffic over the physical LAN. In this way we can make our virtual hosts appear on the physical LAN, merging physical and virtual LAN.
Using agno to encrypt the traffic sent to the bridged tap interface, allows us to secure the physical LAN too. In this way agno can be used as an user-space, end-to-end alternative to MACsec (802.1AE) for securing LANs.
Once the tap interface will be bridged over the Ethernet interface, the physical host will not be able anymore to access the physical network through the Ethernet interface. That could be done through the interface of the bridge (we must change routing options) or, more conveniently, using a vdens connected to the tap interface.
We can set up the bridge this way:
```console
# configure physical host network interfaces
# create a tap
sudo ip tuntap add name tap0 mode tap
# create a bridge
sudo brctl addbr br0
# assign eth0 and tap0 as bridge interfaces
sudo brctl addif br0 eth0
sudo brctl addif br0  tap0
# enable all the interfaces
sudo ip link set eth0 up
sudo ip link set br0 up
sudo ip link set tap0 up
```

Here we don’t need sudo anymore.
All the physical hosts that must be able to receive encrypted traffic must use agno, hence must have a tap.
The following is an example of how we can start a virtual host that uses agno and shows up on the physical LAN.

```console
# start vdens
vdens agno:///etc/agno/tap/LAN{tap://tap0}
ip link set vde0 up
# assign ip
ip addr add 10.0.0.2/24 dev vde0
# dhclient vde0 -v → to use a dynamic ip we must have a dhcp server in a vdens that uses agno
```

This vdens will be able to see only hosts using agno with his same key.
If the traffic is to be routed, the router has to use agno. In this case for a vdens we must define the address of the domain name server (e.g. -R 80.80.80.80).
This could be done doing Network Function Virtualization, i.e. using a host with multiple network interfaces as a router. Inside of this host we can run a vdens –multi that connects to the physical interfaces with an equal number of tap interfaces.

If we have an host with multiple Ethernet interfaces we can use it as a "cryptographic bridge".

![Cryptographic bridge](https://github.com/rd235/vdeplug_agno/blob/libsodium_static/img/cryptographic_bridge.png)
 
When using agno with taps you may want to increase the MTU of the tap. This is because agno adds 46 bytes (30 of header and 16 of authentication tag) to the packet.

If the tap is bridged over a physical network interface, the MTU should be increased even there.
This could be done with the following command:
```console
$ ip link set dev eth0 mtu 1546
```

Informations about the MTUs are recorded in the routing cache. To flush it use the command:
```console
$ ip route flush cache
```
If the hardware does not support MTU lengths greater than 1500 it is possible to reduce the MTU length on virtual hosts.
This could be done also when using vxvde to avoid packet fragmentation of UDP packets.
