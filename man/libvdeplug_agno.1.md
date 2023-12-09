<!--
.\" Copyright (C) 2020 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

`libvdeplug_agno` -- vdeplug module: add encryption to ethernet link plug

# SYNOPSIS
libvdeplug_agno.so

# DESCRIPTION

This is a libvdeplug cryptographic module that implements agnostic encryption over layer 2. Agnostic encryption is
an encryption method that doesn't need information about the vde network implementation.

This module of libvdeplug4 can be used in any program supporting vde like
`vde_plug`, `vdens`, `kvm`, `qemu`, `user-mode-linux` and `virtualbox`.

The vde_plug_url syntax of this module is the following:

   &nbsp; &nbsp; &nbsp; `agno://`[*/path/of/keyfile*][`[`*OPTIONS*`]`]`{`*vde nested url*`}`

*/path/of/keyfile*, if present, must be an absolute path or a path relative to the user's home (e.g. `~/example/path`).
If omitted the default path of the keyfile is `~/.vde_agno_key`. The keyfile must contain a 128-bit key in hexadecimal format.
Only hexadecimal characters are considered in both uppercase and lowercase, all the others are ignored (e.g. white-spaces,
newline characters, non-hexadecimal letters).

# OPTIONS

  `ethtype=`_TYPE_
: define the type of the Ethernet frame of the encrypted packet. TYPE can be the an exadecimal number or:

  ` `
: `copy`: same type of the non-encrypted packet

  ` `
: `ipv4`: ipv4 type (0x0800)

  ` `
: `ipv6`: ipv6 type (0x86dd)

  ` `
: `rand`: random number as type. The random number will be generated for each Ethernet packet sent.

# EXAMPLES

`agno://{vde:///tmp/myswitch}`

  agno uses the key stored in the default keyfile (~/.vde_agno_key) location to encrypt the traffic sent to the switch.
  The Ethernet frames have agno specific type (0xa6de) as type.

  `agno:///tmp/my_keyfile[ethtype=copy]{vde:///tmp/myswitch}`

  agno uses the key stored in file /tmp/my_keyfile to encrypt the traffic sent to the switch. The Ethernet frames will
  have the same type of the non-encrypted packet.

  `vdens agno://[ethtype=rand]{vxvde://234.0.0.1}`

  create a nanespace connected to a vxvde local area cloud. agno uses the key stored
  in the default keyfile (~/.vde_agno_key) location to encrypt the traffic sent to vxvde.

# NOTICE
Virtual Distributed Ethernet is not related in any way with www.vde.com ("Verband der Elektrotechnik, Elektronik
und Informationstechnik" i.e. the German "Association for Electrical, Electronic & Information Technologies").

# SEE ALSO
`vde_plug`(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli
