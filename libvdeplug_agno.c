/*
 * VDE - libvdeplug_agno agnostic encrypted vde net (aes encoded)
 * Copyright (C) 2017 Renzo Davoli VirtualSquare
 * contributions by Michele Nalli
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <libvdeplug.h>
#include <libvdeplug_mod.h>

   // 128-bit key
   // openssl enc -aes-128-cbc -k secret -P -md sha1

#define DEFAULT_KEYFILE ".vde_agno_key"

static VDECONN *vde_agno_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_agno_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_agno_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_agno_datafd(VDECONN *conn);
static int vde_agno_ctlfd(VDECONN *conn);
static int vde_agno_close(VDECONN *conn);

#define _AGNO_TAG 0x61676e6f
#define AGNO_TYPE 0xa6de
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define AGNO_TAG __bswap_constant_32(_AGNO_TAG)
#else
#define AGNO_TAG _AGNO_TAG
#endif
#define ETH_HEADER_SIZE sizeof(struct ether_header)

/* Structure of the header added by the module */
struct agno_hdr {
	uint16_t ether_type;
	unsigned char flags;	/* Size of padding */
	unsigned char unused;
	uint32_t tag;
	uint32_t time;			/* Time used to avoid record & playback */
	unsigned char rand[4];	/* Salt */
};

/* Declaration of the connection sructure of the module */
struct vde_agno_conn {
	void *handle;
	struct vdeplug_module *module;
	VDECONN *conn;
	uint16_t ether_type;
	AES_KEY ekey;			/* Encryption key */
	AES_KEY dkey;			/* Decryption key */
};

/* Declaration of the module sructure */
struct vdeplug_module vdeplug_ops={
	/* .flags is not initialized */
	.vde_open_real=vde_agno_open,
	.vde_recv=vde_agno_recv,
	.vde_send=vde_agno_send,
	.vde_datafd=vde_agno_datafd,
	.vde_ctlfd=vde_agno_ctlfd,
	.vde_close=vde_agno_close
};

/* keyfile  - path of the keyfile
	 cryptkey - buffer where the decrypted key will be placed; it should contain 16 elements.
	 Returns 0 on success, -1 on error. */
static int getcryptkey(char *keyfile, unsigned char *cryptkey) {
	/* passwd file entry */
	struct passwd pwd;
	/* passwd file entry pointer */
	struct passwd *result;
	/* The maximum size needed for the user information
		 buffer to be filled in by getpwuid_r(). */
	/* returns either -1, without changing errno, or an initial suggested size for buf. */
	size_t sc_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	/* set a large default sc_bufsize in the unlikely case sysconf fails */
	size_t bufsize = sc_bufsize < 0 ? 16384 : sc_bufsize;
	/* buffer used in getpwuid_r */
	char buf[bufsize];
	/* buffer for absolute path of the keyfile */
	char path[PATH_MAX+1];
	/* File pointer for reading from keyfile */
	FILE *fd;
	int i=0;
	/* Get password file from uid */
	/* result is initialized by getpwuid_r */
	if (getpwuid_r(geteuid(), &pwd, buf, bufsize, &result) != 0 || result == NULL) {
		return -1;
	}
	/* Get absolute path of keyfile */
	if (keyfile == NULL || *keyfile == 0)
		/* keyfile not specified */
		snprintf(path, PATH_MAX, "%s/" DEFAULT_KEYFILE, result->pw_dir);
	else if (*keyfile == '~')
		/* keyfile based on home directory */
		snprintf(path, PATH_MAX, "%s/%s", result->pw_dir, keyfile+1);
	else if (*keyfile == '/')
		/* keyfile is an absolute path */
		snprintf(path, PATH_MAX, "%s", keyfile);
	else {
		/* No other formats available */
		errno = EINVAL;
		return -1;
	}
	path[PATH_MAX]=0;
	memset(cryptkey, 0, 16);
	/* Open the keyfile */
	if ((fd = fopen(path, "r")) == NULL) {
		errno = ENOENT;
		return -1;
	}
	/* Change the key from string content to an array of bytes */
	for (; i < 32;) {
		int c;
		/* Get next char or break */
		if ((c = getc(fd)) == EOF)
			break;
		if (isxdigit(c)) {
			int val = c & 0xf;
			if (c > 'A') val += 9;
			if (i & 1)
				cryptkey[i >> 1] |= val;
			else
				cryptkey[i >> 1] = (val << 4);
			i++;
		}
	}
	fclose(fd);
	if (i<2) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static VDECONN *vde_agno_open(char *vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args)
{
	/* Return value on success; dynamically allocated */
	struct vde_agno_conn *newconn=NULL;
	char *nested_url;
	char *ethtype="";
	/* NULL-terminating array of struct vdeparms */
	struct vdeparms parms[] = {
		{"ethtype", &ethtype},
		{NULL, NULL}};
	unsigned char cryptkey[16];
	VDECONN *conn;

	nested_url = vde_parsenestparms(vde_url);
	if (vde_parsepathparms(vde_url, parms) != 0)
		return NULL;
	if (getcryptkey(vde_url, cryptkey) != 0)
		return NULL;
	/* Open connection with nested url */
	conn = vde_open(nested_url, descr, open_args);
	if (conn == NULL)
		return  NULL;
	if ((newconn=calloc(1,sizeof(struct vde_agno_conn)))==NULL) {
		errno = ENOMEM;
		goto error;
	}
	newconn->conn=conn;
	if (strcmp(ethtype,"copy") == 0)
		/* Mantain the type of the non-encrypted packet */
		newconn->ether_type = 0x0;
	/* htons() converts the unsigned short integer hostshort
		 from host byte order to network byte order. */
	else if (strcmp(ethtype,"ipv4") == 0)
		/* Set ipv4 type */
		newconn->ether_type = htons(ETHERTYPE_IP);	/* 0x0800 */
	else if (strcmp(ethtype,"ipv6") == 0)
		/* Set ipv6 type */
		newconn->ether_type = htons(ETHERTYPE_IPV6);	/* 0x86dd */
	else if (strcmp(ethtype,"rand") == 0)
		/* Generates random number as type */
		newconn->ether_type = htons(0xffff);
	else {
		char *endptr;
		unsigned long type = strtoul(ethtype, &endptr, 0);
		if (ethtype == endptr && strcmp(ethtype, "") != 0) { /* ethtype doesn't contain a number */
			errno = EINVAL;
			goto error;
		}
		if (type == 0)
			newconn->ether_type = htons(AGNO_TYPE);
		else if (type >= 0x600 && type < 0xffff) /* The input tag is valid */
			newconn->ether_type = htons(type);
		else {
			errno = EINVAL;
			goto error;
		}
	}
	/* Set key as encryption and decryption key */
	AES_set_encrypt_key(cryptkey, sizeof(cryptkey) * 8, &newconn->ekey);
	AES_set_decrypt_key(cryptkey, sizeof(cryptkey) * 8, &newconn->dkey);
	return (VDECONN *) newconn;

error:
	vde_close(conn);
	return NULL;
}

static ssize_t vde_agno_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *)conn;
	/*  */
	size_t enclen = len + 30;
	struct ether_header *ehdr=(struct ether_header *) buf;
	/* Array of bytes where receiving and decryption are done */
	unsigned char encbuf[enclen];
	struct agno_hdr ahdr;
	/* Initialization Vector */
	unsigned char iv_dec[AES_BLOCK_SIZE];
	ssize_t retval = vde_recv(vde_conn->conn, encbuf, enclen, flags);
	if (retval < 0)
		return retval;
	if (len < ETH_HEADER_SIZE || retval < ETH_HEADER_SIZE)
		goto error;
	/* The Ethernet header is not encrypted, we can already copy it. */
	memcpy(ehdr, encbuf, sizeof(*ehdr));
	//memcpy(&ahdr, encbuf + sizeof(*ehdr), sizeof(ahdr));
	/* Get decrypted agno header */
	AES_ecb_encrypt(encbuf + sizeof(*ehdr), (unsigned char *)&ahdr, &vde_conn->dkey, AES_DECRYPT);
	/* Tag check */
	if (ahdr.tag != AGNO_TAG)
		goto error;
	if ((time(NULL) - ntohl(ahdr.time) + 1) & ~3) /* avoid record_playback */
		goto error;
	memcpy(iv_dec, &ahdr, sizeof(iv_dec));
	ehdr->ether_type = ahdr.ether_type;
	retval -= ETH_HEADER_SIZE + (ahdr.flags & 0xf);
	//memcpy(((unsigned char *) buf) + ETH_HEADER_SIZE, encbuf + sizeof(*ehdr) + sizeof(ahdr), retval - ETH_HEADER_SIZE); //Decrypt 2
	/* Decrypt payload */
	AES_cbc_encrypt(
			encbuf + sizeof(*ehdr) + sizeof(ahdr),
			((unsigned char *) buf) + ETH_HEADER_SIZE,
			retval - ETH_HEADER_SIZE, &vde_conn->dkey, iv_dec, AES_DECRYPT);
	return retval;
error:
	errno = EAGAIN;
	return 1;
}

static ssize_t vde_agno_send(VDECONN *conn,const void *buf, size_t len,int flags) {
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *)conn;
	struct ether_header *ehdr=(struct ether_header *) buf;
	/* AES works with 16 byte blocks; 16 == header + padding */
	size_t newlen = len + 16;
	/*  */
	size_t enclen = (((newlen - ETH_HEADER_SIZE) + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1)) + ETH_HEADER_SIZE;
	/* This will contain the encrypted packet */
	unsigned char encbuf[enclen];
	struct ether_header *newehdr=(struct ether_header *) encbuf;
	/* Init of agno header, except for .rand */
	struct agno_hdr ahdr = {
		.ether_type = ehdr->ether_type,
		.flags = enclen - newlen,
		.unused = 0,
		.time = htonl(time(NULL)),
		.tag = AGNO_TAG
	};
	/* Initialization Vector */
	unsigned char iv_enc[AES_BLOCK_SIZE];
	ssize_t retval;
	if (len < ETH_HEADER_SIZE)
		return len;
	memcpy(encbuf, ehdr, sizeof(*ehdr));
	*newehdr = *ehdr;
	switch (vde_conn->ether_type) {
		case 0:
			newehdr->ether_type = ehdr->ether_type; break;
		case 0xffff:
			/* 0x600 <= random number < 0xffff */
			/* if type <= 0x600 many systems think it is the lenght */
			newehdr->ether_type = ntohs(0x600 + (rand() % 0xf9ff)); break;
		default:
			newehdr->ether_type = vde_conn->ether_type;
	}
	/* Complete initialization of agno header */
	RAND_bytes(ahdr.rand, 4);
	//memcpy(encbuf + sizeof(*ehdr), &ahdr, sizeof(ahdr));
	/* Encrypt agno header */
	AES_ecb_encrypt((unsigned char *)&ahdr, encbuf + sizeof(*ehdr), &vde_conn->ekey, AES_ENCRYPT);
	memcpy(iv_enc, &ahdr, sizeof(iv_enc));
	//memcpy(encbuf + sizeof(*ehdr) + sizeof(ahdr), ((const unsigned char *) buf) + ETH_HEADER_SIZE, len - ETH_HEADER_SIZE);
	/* Encrypt payload */
	AES_cbc_encrypt(
			((const unsigned char *) buf) + ETH_HEADER_SIZE,
			encbuf + sizeof(*ehdr) + sizeof(ahdr),
			len - ETH_HEADER_SIZE, &vde_conn->ekey, iv_enc, AES_ENCRYPT);
	retval = vde_send(vde_conn->conn, encbuf, enclen, flags);
	if (retval == enclen)
		return len;
	else
		return retval;
}

static int vde_agno_datafd(VDECONN *conn) {
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *)conn;
	return vde_datafd(vde_conn->conn);
}

static int vde_agno_ctlfd(VDECONN *conn) {
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *)conn;
	return vde_ctlfd(vde_conn->conn);
}

static int vde_agno_close(VDECONN *conn) {
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *)conn;
	return vde_close(vde_conn->conn);
}
