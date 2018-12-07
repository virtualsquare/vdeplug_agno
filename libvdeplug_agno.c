/*
 * VDE - libvdeplug_agno encrypted vde net (XChaCha20-Poly1305)
 * Copyright (C) 2018 Michele Nalli VirtualSquare
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <net/if.h>
#include <pwd.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

/* libvdeplug */
#include <libvdeplug.h>
#include <libvdeplug_mod.h>

#include <assert.h>

#include <sodium.h>

/* Uncomment to disable DEBUG_PRINT() and assert() */
#define NDEBUG

#ifndef NDEBUG
	#define DEBUG_PRINT(format, args...) \
		fprintf(stderr, "DEBUG: %d:%s(): " format, __LINE__, __func__, ##args)
#else
	/* Don't do anything in release builds */
	#define DEBUG_PRINT(format, args...) do {} while(0)
#endif

// #if __BYTE_ORDER == __BIG_ENDIAN
// uint64_t htonll(uint64_t hostlonglong) {
// 	return hostlonglong
// }
//
// uint64_t ntohll(uint64_t netlonglong) {
// 	return netlonglong
// }
// #else
//
// # if __BYTE_ORDER == __LITTLE_ENDIAN
// uint64_t htonll(uint64_t hostlonglong) {
// 	return (((uint64_t) htonl((uint32_t) hostlonglong)) << 32 | htonl((uint32_t) (hostlonglong >> 32)));
// }
//
// uint64_t ntohll(uint64_t netlonglong) {
// 	return (((uint64_t) ntohl((uint32_t) netlonglong)) << 32 | ntohl((uint32_t) (netlonglong >> 32)));
// }
// # endif
// #endif

static VDECONN *vde_agno_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_agno_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_agno_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_agno_datafd(VDECONN *conn);
static int vde_agno_ctlfd(VDECONN *conn);
static int vde_agno_close(VDECONN *conn);

#define ETH_HEADER_SIZE sizeof(struct ether_header)

#define JUMBO_FRAME_MAX_LENGHT ETH_HEADER_SIZE + 9000 /* payload */

#define AGNO_TYPE 0xa6de

/* Nonce = | 4-byte fixed field | 8-byte invocation field | */
#define FIXED_FIELD_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES - 8
#define INVOCATION_FIELD_SIZE 8

#define AGNO_HEADER_SIZE sizeof(struct agno_header)

/* Header added to packets; is is used as nonce (IV) */
struct agno_header {
	uint32_t time;
	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
};

/* Declaration of the connection sructure of the module */
struct vde_agno_conn {
	void *handle;
	struct vdeplug_module *module;
	VDECONN *conn;
	/* Plug-in data */
	uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	/* Nonce information */
	uint8_t rand_id[FIXED_FIELD_SIZE];
	uint64_t counter;
};

/* Declaration of the module structure */
struct vdeplug_module vdeplug_ops = {
	/* .flags is not initialized */
	.vde_open_real = vde_agno_open,
	.vde_recv = vde_agno_recv,
	.vde_send = vde_agno_send,
	.vde_datafd = vde_agno_datafd,
	.vde_ctlfd = vde_agno_ctlfd,
	.vde_close = vde_agno_close
};

/* Precondition: c is an hexadecimal char */
static inline uint8_t hexchar_to_uint(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
	else if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	else /* if (c >= 'a' && c <= 'f') */
		return 10 + c - 'a';
}

/* Precondition: msig and lsig is an hexadecimal char.
 	msig is the most significant one.
	lsig is the least significant one. */
static inline uint8_t hexchars_to_byte(char msig, char lsig) {
	return (hexchar_to_uint(msig) << 4) + hexchar_to_uint(lsig);
}

/* keyfile  - absolute path of the keyfile.
 *	cryptkey - buffer where the key will be placed;
   		its lenght must be AES128_KEY_SIZE.
 *	On success returns 0 and cryptkey is set to the key.
 *	On failure returns -1 and cryptkey is set to 0.
 */
static int get_cryptkey(const char *keyfile, uint8_t *cryptkey) {
	DEBUG_PRINT("start\n");
	/* File pointer for reading from keyfile */
	FILE *fp;

	/* Reset cryptkey */
	memset(cryptkey, 0, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

	/* Open the keyfile */
	if ((fp = fopen(keyfile, "r")) == NULL)
		return -1;

	/* 32 character + optional '\n' + '\0' */
	const size_t bufsize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2 + 2;
	char buf[bufsize];

	if (fgets(buf, bufsize, fp) == NULL)
		return -1;

	/* Next character must be EOF */
	if (fgetc(fp) != EOF) {
		errno = EKEYREJECTED;
		return -1;
	}

	fclose(fp);

	size_t actual_len = strlen(buf);

	/* Remove '\n' character if any */
	if (buf[actual_len - 1] == '\n') {
		buf[actual_len - 1] = '\0';
		actual_len--;
	}

	if (actual_len != crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2) {
		errno = EKEYREJECTED;
		return -1;
	}

	for (size_t i = 0; i < actual_len; i++) {
		if (!isxdigit(buf[i])) {
			errno = EKEYREJECTED;
			return -1;
		}
	}

	/* Convert the string from hexadecimal to bytes */
	for (size_t i = 0; i < crypto_aead_xchacha20poly1305_ietf_KEYBYTES; i++)
		cryptkey[i] = hexchars_to_byte(buf[i*2], buf[i*2+1]);

	DEBUG_PRINT("end\n");
	return 0;
}

#define DEFAULT_KEYDIRECTORY ".vde_agno"
#define DEFAULT_KEYFILE	DEFAULT_KEYDIRECTORY "/default_key"

/* Given the argument this function returns the absolute path to the keyfile,
	NULL on error.
	NOTE: it's not guaranteed that the keyfile actually exists. */
static char *get_cryptkey_file(const char *arg) {
	/* passwd file entry */
	struct passwd pwd;
	/* passwd file entry pointer */
	struct passwd *result;
	/* The maximum size needed for the user information
	   buffer to be filled in by getpwuid_r(). */
	/* returns either -1, without changing errno, or an initial suggested size for buf. */
	size_t sc_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	size_t bufsize = sc_bufsize < 0 ? 16384 : sc_bufsize;
	/* buffer used in getpwuid_r */
	char buf[bufsize];

	/* Get password file from uid */
	/* result is initialized by getpwuid_r */
	if (getpwuid_r(geteuid(), &pwd, buf, bufsize, &result) != 0 || result == NULL)
		/* errno is already set */
		return NULL;

	/* buffer for absolute path of the keyfile */
	char *path = malloc(PATH_MAX + 1);
	if (path == NULL)
		/* errno is already set */
		return NULL;

	/* Get absolute path of keyfile */
	if (arg == NULL || *arg == 0)
		/* keyfile not specified: look for it at the default location in the home */
		snprintf(path, PATH_MAX, "%s/" DEFAULT_KEYFILE, result->pw_dir);
	else if (*arg == '~')
		/* keyfile based on home directory */
		snprintf(path, PATH_MAX, "%s%s", result->pw_dir, arg + 1);
	else if (*arg == '/')
		/* keyfile is an absolute path */
		snprintf(path, PATH_MAX, "%s", arg);
	else
		/* Look for the argument in the default directory */
		snprintf(path, PATH_MAX, "%s/" DEFAULT_KEYDIRECTORY "/%s", result->pw_dir, arg);

	path[PATH_MAX] = 0;
	return path;
}

static VDECONN *vde_agno_open(char *vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args)
{
	DEBUG_PRINT("start\n");

	struct vde_agno_conn *agno_conn = NULL;
	char *nested_url;

	VDECONN *conn;

	nested_url = vde_parsenestparms(vde_url);

	if (vde_parsepathparms(vde_url, NULL) != 0)
		return NULL;

	/* Open connection with nested url */
	conn = vde_open(nested_url, descr, open_args);
	if (conn == NULL)
		return  NULL;
	if ((agno_conn = calloc(1, sizeof(struct vde_agno_conn))) == NULL)
		goto error;

	agno_conn->conn = conn;

	char *keyfile = get_cryptkey_file(vde_url);
	if (keyfile == NULL)
		goto error;
	if (get_cryptkey(keyfile, agno_conn->key) == -1) {
		free(keyfile);
		goto error;
	}
	free(keyfile);

	/* Init libsodium */
	if (sodium_init() < 0)
        goto error;

	/* Init counter */
	agno_conn->counter = 0;

	/* Init random ID */
	randombytes_buf(agno_conn->rand_id, FIXED_FIELD_SIZE);

	printf("agno id: [");
	for (size_t i = 0; i < FIXED_FIELD_SIZE; i++) {
		printf("%x", agno_conn->rand_id[i]);
	}
	printf("]\n");

	DEBUG_PRINT("Initialization completed\n");

	return (VDECONN *) agno_conn;

error:
	vde_close(conn);
	return NULL;
}

void print_enc_packet(const uint8_t *enc_packet, const size_t enc_packet_size) {
	struct ether_header *enc_ehdr = (struct ether_header *) enc_packet;
	struct agno_header *enc_ahdr = (struct agno_header *) (enc_ehdr + 1);
	/* Secure data (EtherType and payload) + ICV */
	uint8_t *secure_data_icv = (uint8_t *) (enc_ahdr + 1);
	const size_t secure_data_icv_size = enc_packet_size - (ETH_HEADER_SIZE + AGNO_HEADER_SIZE);

	fprintf(stderr, "| ");

	for (size_t i = 0; i < ETH_HEADER_SIZE; i++)
		fprintf(stderr, "%x ", ((uint8_t *) enc_ehdr)[i]);

	fprintf(stderr, "| ");

	for (size_t i = 0; i < AGNO_HEADER_SIZE; i++)
		fprintf(stderr, "%x ", ((uint8_t *) enc_ahdr)[i]);

	fprintf(stderr, "| ");

	for (size_t i = 0; i < secure_data_icv_size - crypto_aead_xchacha20poly1305_ietf_ABYTES; i++)
		fprintf(stderr, "%x ", secure_data_icv[i]);

	fprintf(stderr, "| ");

	for (size_t i = secure_data_icv_size - crypto_aead_xchacha20poly1305_ietf_ABYTES; i < secure_data_icv_size; i++)
		fprintf(stderr, "%x ", secure_data_icv[i]);

	fprintf(stderr, "\n");
}

static ssize_t vde_agno_recv(VDECONN *conn, void *buf, size_t len, int flags) {
	struct vde_agno_conn *agno_conn = (struct vde_agno_conn *) conn;
	/* Array of bytes where receiving and decryption are done */

	/* TODO: jumbo frames and baby giant? */
	uint8_t recvbuf[JUMBO_FRAME_MAX_LENGHT];

	if (len < ETH_HEADER_SIZE)
		return 1;

	ssize_t retval = vde_recv(agno_conn->conn, recvbuf, JUMBO_FRAME_MAX_LENGHT, flags);

	if (retval < 0) {
		errno = EAGAIN;
		return -1;
	}

	if (retval < ETH_HEADER_SIZE)
		return 1;

	// DEBUG_PRINT("Received lenght -> %d\n", (int) retval);

	/** Mapping of the plain packet **/
	struct ether_header *ehdr = (struct ether_header *) buf;
	uint8_t *payload = (uint8_t *) (ehdr + 1);

	/** Mapping of the encrypted packet **/
	/* NOTE: we are not sure if the recvbuf contains a valid encrypted packet */
	struct ether_header *auth_ehdr = (struct ether_header *) recvbuf;
	struct agno_header *auth_ahdr = (struct agno_header *) (auth_ehdr + 1);
	/* Secure data (without ICV) */
	uint8_t *secure_data = (uint8_t *) (auth_ahdr + 1);
																					/* Tag lenght */
	const size_t secure_data_size = retval - (ETH_HEADER_SIZE + AGNO_HEADER_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES);
	/* NOTE: ICV is found after secure_data */

	// fprintf(stderr, "PACCHETTO IN ENTRATA\n");
	// print_enc_packet(recvbuf, retval);

	/* Now - timestamp >= -1 && Now - timestamp <= 2 */
	if ((time(NULL) - ntohl(auth_ahdr->time) + 1) & ~3) {
		DEBUG_PRINT("Packet expired\n");
		return 1;
	}

	/* Copy plain Ethernet header */
	memcpy(ehdr, auth_ehdr, ETH_HEADER_SIZE);

	/* Get host order nonce */
	// uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
	// uint8_t *fixed_field = (uint8_t *) nonce;
	// uint64_t *invocation_field = (uint64_t *) (fixed_field + FIXED_FIELD_SIZE);

	/* Buffer for secure data decryption */
	uint8_t plain_secure_data[secure_data_size];
	uint16_t *plain_ether_type = (uint16_t *) plain_secure_data;
	uint8_t *plain_payload = (uint8_t *) (plain_ether_type + 1);

	size_t plain_secure_data_size = secure_data_size;

	if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain_secure_data, (unsigned long long *) &plain_secure_data_size, NULL,
                                               secure_data, secure_data_size + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                                               recvbuf, ETH_HEADER_SIZE + AGNO_HEADER_SIZE,
                                               auth_ahdr->nonce, agno_conn->key) < 0) {
		DEBUG_PRINT("Decryption failed\n");
		return 1;
	}

	assert(plain_secure_data_size == secure_data_size);

	ehdr->ether_type = *plain_ether_type;

	size_t pkt_lenght = ETH_HEADER_SIZE + (secure_data_size - sizeof(uint16_t /* EtherType */));
	pkt_lenght = pkt_lenght < len ? pkt_lenght : len;

	memcpy(payload, plain_payload, pkt_lenght - ETH_HEADER_SIZE);

	return pkt_lenght;
}

static ssize_t vde_agno_send(VDECONN *conn, const void *buf, size_t len, int flags) {
	struct vde_agno_conn *agno_conn = (struct vde_agno_conn *) conn;

	if (len < ETH_HEADER_SIZE)
		/* Fake send (successful send of an invalid packet) */
		return len;

	/** Mapping of the plain packet **/
	struct ether_header *ehdr = (struct ether_header *) buf;
	uint8_t *payload = (uint8_t *) (ehdr + 1);
	const size_t payload_size = len - ETH_HEADER_SIZE;

	/* NOTE: AES-GCM is a stream cipher (no padding) */
	const size_t secure_data_size = payload_size + sizeof(uint16_t /* old EtherType */);
	/* Lenght of the entire encrypted packet */
	const size_t enclen = ETH_HEADER_SIZE + AGNO_HEADER_SIZE + secure_data_size + crypto_aead_xchacha20poly1305_ietf_ABYTES;

	/* buffer for the encrypted packet */
	uint8_t encbuf[enclen];
	/** Mapping of the encrypted packet **/
	struct ether_header *auth_ehdr = (struct ether_header *) encbuf;
	struct agno_header *auth_ahdr = (struct agno_header *) (auth_ehdr + 1);
	/* Secure data (EtherType of the plain packet and payload) */
	uint8_t *secure_data = (uint8_t *) (auth_ahdr + 1);
	/* NOTE: ICV is found after secure_data */

	/* Copy the plain ethernet header */
	*auth_ehdr = *ehdr;
	auth_ehdr->ether_type = htons(AGNO_TYPE);

	/* Set network order time */
	auth_ahdr->time = htonl(time(NULL));

	/* TODO: network order nonce */
	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
	uint8_t *fixed_field = nonce;
	uint64_t *invocation_field = (uint64_t *) (fixed_field + FIXED_FIELD_SIZE);
	memcpy(fixed_field, agno_conn->rand_id, FIXED_FIELD_SIZE);
	*invocation_field = agno_conn->counter;
	agno_conn->counter++;

	memcpy(auth_ahdr->nonce, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

	uint8_t plain_secure_data[secure_data_size];
	uint16_t *plain_ether_type = (uint16_t *) plain_secure_data;
	uint8_t *plain_payload = (uint8_t *) (plain_ether_type + 1);

	*plain_ether_type = ehdr->ether_type;
	memcpy(plain_payload, payload, payload_size);

	size_t secure_data_icv_len = secure_data_size + crypto_aead_xchacha20poly1305_ietf_ABYTES;

	if (crypto_aead_xchacha20poly1305_ietf_encrypt(secure_data, (unsigned long long *) &secure_data_icv_len,
                                           plain_secure_data, secure_data_size,
                                           encbuf, ETH_HEADER_SIZE + AGNO_HEADER_SIZE, /* Authenticate headers */
                                           NULL, nonce, agno_conn->key) < 0) {
		DEBUG_PRINT("Encryption failed.\n");
		errno = EAGAIN;
		return -1;
	}

	assert(secure_data_icv_len == secure_data_size + crypto_aead_xchacha20poly1305_ietf_ABYTES);

	// fprintf(stderr, "PACCHETTO IN USCITA\n");
	// print_enc_packet(encbuf, enclen);

	ssize_t retval = vde_send(agno_conn->conn, encbuf, enclen, flags);

	// DEBUG_PRINT("enclen -> %d, retval -> %d\n", (int) enclen, (int) retval);

	if (retval == enclen)
		return len;
	else
		/* error */
		return retval;
}

static int vde_agno_datafd(VDECONN *conn) {
	struct vde_agno_conn *agno_conn = (struct vde_agno_conn *)conn;
	return vde_datafd(agno_conn->conn);
}

static int vde_agno_ctlfd(VDECONN *conn) {
	struct vde_agno_conn *agno_conn = (struct vde_agno_conn *)conn;
	return vde_ctlfd(agno_conn->conn);
}

static int vde_agno_close(VDECONN *conn) {
	struct vde_agno_conn *agno_conn = (struct vde_agno_conn *) conn;
	return vde_close(agno_conn->conn);
}
