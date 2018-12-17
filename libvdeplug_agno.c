/*
 * VDE - libvdeplug_agno encrypted vde net (GCM-AES-128)
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pwd.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

/* libvdeplug */
#include <libvdeplug.h>
#include <libvdeplug_mod.h>

#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

#include <assert.h>
/* Scan directory during certificate handling */
#include <dirent.h>

/* gnutls data types - include before crypto */
#include <gnutls/abstract.h>
/* gnutls crypto functions */
#include <gnutls/crypto.h>

/* Get size of x.509 certificates */
#include <sys/stat.h>

/* Configuration files handling */
#include <libconfig.h>

#include <libgen.h>

/* Uncomment to disable DEBUG_PRINT() and assert() */
// #define NDEBUG

#ifndef NDEBUG
	#define DEBUG_PRINT(format, args...) \
		fprintf(stderr, "DEBUG: %d:%s(): " format, __LINE__, __func__, ##args)
#else
	/* Don't do anything in release builds */
	#define DEBUG_PRINT(format, args...) do {} while(0)
#endif

static VDECONN *vde_agno_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_agno_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_agno_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_agno_datafd(VDECONN *conn);
static int vde_agno_ctlfd(VDECONN *conn);
static int vde_agno_close(VDECONN *conn);

#define _AGNO_TAG 0x61676e6f /* agno in hex code */
#define AGNO_TYPE 0xa6de
// #define MACsec_TYPE 0x88e5

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define AGNO_TAG __bswap_constant_32(_AGNO_TAG)
#else
#define AGNO_TAG _AGNO_TAG
#endif

#define DEFAULT_CONFIGFILE ".agno_config"

#define  ETH_HEADER_SIZE sizeof(struct ether_header)

#define AES_BLOCK_SIZE	16
#define AES_KEY_SIZE	16

/* 12 bytes (96-bits) is the most efficient IV for GCM mode */
#define NONCE_SIZE 12
/* 16 bytes is the most secure authentication */
#define ICV_SIZE 16

#define AGNO_HEADER_SIZE sizeof(struct agno_hdr)

/* Structure of the header added by the module */
struct agno_hdr {
	uint32_t time;
	uint8_t flags;
	uint8_t short_lenght;
	uint16_t ether_type;
};

/* RSA 2048 bit (256 byte) */
#define RSA_BLOCK_SIZE 256
#define RSA_SIGN_SIZE RSA_BLOCK_SIZE

#define PROTOCOL_TYPE_NULL		0
#define PROTOCOL_TYPE_REQUEST	1
#define PROTOCOL_TYPE_REPLY		2

#define PROTOCOL_HEADER_SIZE sizeof(struct agno_protocol_hdr)

struct agno_protocol_hdr {
	uint32_t tag;
	uint32_t time;
	uint8_t type;
};

/* Declaration of the connection sructure of the module */
struct vde_agno_conn {
	void *handle;
	struct vdeplug_module *module;
	VDECONN *conn;
	uint16_t ether_type;
	unsigned char auth_only;
	uint8_t session_key[AES_KEY_SIZE];
	gnutls_aead_cipher_hd_t aes_gcm_ctx; /* Context of the AES CBC algorithm */
	char *id;
	gnutls_pubkey_t pubkey;
	gnutls_privkey_t privkey;
	char *certificate_folder;
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

/* Verify the given certificate against root CA's certificate found at root_path path.
 	returns 0 if valid, a number > 0 if invalid, -1 on error. */
int x509_verify_crt(const gnutls_x509_crt_t cert, const char *root_path) {
	/* root CA's certificate */
	gnutls_datum_t		root;
	gnutls_x509_crt_t	root_crt;
	/* Return value for GnuTLS functions */
	int ret;
	/* File pointer for reading from certificate files */
	FILE *fp;
	/* stat structure for getting the lenght of the CA's certificate file */
	struct stat statbuf;

	if ((fp = fopen(root_path, "r")) == NULL)
		return -1;

	lstat(root_path, &statbuf);

	root.size = statbuf.st_size;
	if ((root.data = malloc(root.size * sizeof(unsigned char))) == NULL)
		return -1;

	fread(root.data, root.size, 1, fp);

	fclose(fp); /* Close root certificate file */

	/* Initialize certificate chain */
	if ((ret = gnutls_x509_crt_init(&root_crt)) < 0) {
		fprintf(stderr, "gnutls_x509_crt_init - %s\n",
				gnutls_strerror(ret));
		/* Clean memory up */
		free(root.data);
		return -1;
	}

	if ((ret = gnutls_x509_crt_import(root_crt, &root, GNUTLS_X509_FMT_PEM)) < 0) {
		DEBUG_PRINT("gnutls_x509_crt_import: %s\n", gnutls_strerror(ret));
		/* Clean memory up */
		free(root.data);
		gnutls_x509_crt_deinit(root_crt);
		return -1;
	}

	free(root.data); /* Clean up root datum */

	unsigned int result;
	if ((ret = gnutls_x509_crt_verify(cert, &root_crt, 1, 0, &result)) < 0) {
		fprintf(stderr, "gnutls_x509_crt_verify - %s\n",
				gnutls_strerror(ret));
		/* Clean memory up */
		gnutls_x509_crt_deinit(root_crt);
		return -1;
	}

	/* deinit just root CA's certificate */
	gnutls_x509_crt_deinit(root_crt);

	return result;
}

/* Get public key from x509 certificate.
	The key is imported only if the certificate is valid.
 	pubkey - buffer where the public key will be stored. it must be initialized
		with gnutls_pubkey_init
	certfile - absolute path of the certificate
	return value - 0 success, -1 failure */
int get_public_key_x509(gnutls_pubkey_t *pubkey, const char *certfile) {
	/* Return value for GnuTLS functions */
	int ret;
	/* File pointer for reading from certfile */
	FILE *fp;
	/* certificate in memory + size */
	gnutls_datum_t cert_data;
	gnutls_x509_crt_t cert;
	/* stat structure for getting the lenght of the certificate */
	struct stat certfile_stat;

	if ((fp = fopen(certfile, "r")) == NULL) {
		fprintf(stderr, "get_public_key_x509: fopen\n");
		return -1;
	}

	lstat(certfile, &certfile_stat);

	cert_data.size = certfile_stat.st_size;
	if ((cert_data.data = malloc(cert_data.size * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "get_public_key_x509: malloc\n");
		return -1;
	}

	/* Put file in memory */
	fread(cert_data.data, cert_data.size, 1, fp);
	fclose(fp); /* Close certfile */

	if ((ret = gnutls_x509_crt_init(&cert)) < 0) {
		fprintf(stderr, "get_public_key_x509: gnutls_x509_crt_init - %s\n",
				gnutls_strerror(ret));
		free(cert_data.data);
		return -1;
	}

	if ((ret = gnutls_x509_crt_import(cert, &cert_data, GNUTLS_X509_FMT_PEM)) < 0) {
		fprintf(stderr, "get_public_key_x509: gnutls_x509_crt_import - %s\n",
				gnutls_strerror(ret));
		free(cert_data.data);
		gnutls_x509_crt_deinit(cert);
		return -1;
	}
	/* Clean up cert datum */
	free(cert_data.data);

	/* Verify the validity of the certificate */
	if ((ret = x509_verify_crt(cert, "/home/michele/Desktop/sistemi_virtuali/Tirocinio/CA_cert.pem")) != 0) {
		if (ret != -1)
			fprintf(stderr, "The certificate is invalid\n");
		gnutls_x509_crt_deinit(cert);
		return -1;
	}

	if ((ret = gnutls_pubkey_import_x509(*pubkey, cert, 0)) < 0) {
		fprintf(stderr, "get_public_key_x509: gnutls_pubkey_import_x509 - %s\n",
				gnutls_strerror(ret));
		gnutls_x509_crt_deinit(cert);
		return -1;
	}

	gnutls_x509_crt_deinit(cert);

	return 0;
}

/* Get private key from keyfile
 	privkey - buffer where the private key will be stored
	keyfile - absolute path of the keyfile
	return value - 0 success, 1 failure */
int get_private_key(gnutls_privkey_t *privkey, const char *keyfile) {
	/* Return value for GnuTLS functions */
	int ret;
	/* File pointer for reading from certfile */
	FILE *fp;
	gnutls_datum_t key_data;
	/* stat structure for getting the lenght of the certificate */
	struct stat keyfile_stat;

	if ((fp = fopen(keyfile, "r")) == NULL)
		return -1;

	lstat(keyfile, &keyfile_stat);

	key_data.size = keyfile_stat.st_size;
	if ((key_data.data = malloc(key_data.size * sizeof(unsigned char))) == NULL) {
		return -1;
	}

	fread(key_data.data, key_data.size, 1, fp);
	fclose(fp);

	/* Password NULL */
	if ((ret = gnutls_privkey_import_x509_raw(*privkey, &key_data, GNUTLS_X509_FMT_PEM, NULL, 0)) < 0) {
		fprintf(stderr, "gnutls_privkey_import_x509_raw - %s\n",
				gnutls_strerror(ret));
		return -1;
	}

	free(key_data.data);

	return 0;
}

char *get_certfile_from_id(const char *certificate_folder, const char *id) {
	const size_t cert_path_len = strlen(certificate_folder) + strlen(id) + 10 + 1;
	char *cert_path = malloc(cert_path_len);

	snprintf(cert_path, cert_path_len, "%s/%s_cert.pem", certificate_folder, id);
	return cert_path;
}

// int x509_directory_verify_crt(const char *cert_dir) {
// 	/* Datum for certificate to verify */
// 	gnutls_datum_t cert;
// 	/* Root CA datum */
// 	gnutls_datum_t root;
// 	/* certificate chain to verify */
// 	gnutls_x509_crt_t cert_x509[2];
// 	/* Root CA certificate */
// 	gnutls_x509_crt_t root_x509;
// 	// FIXME: join cert_x509[1] and root_x509;
//
// 	/* Trust list; it will contain our CA only */
// 	gnutls_x509_trust_list_t tlist;
//
// 	/* Return value for GnuTLS functions */
// 	int ret;
// 	/* File pointer for reading from certfile */
// 	FILE *fp;
// 	/* stat structure for getting the lenght of the certificate */
// 	struct stat root_stat;
//
// 	/* FIXME: hardcoded */
// 	const char *CA_cert = "/home/michele/Desktop/sistemi_virtuali/Tirocinio/CA_cert.pem";
// 	if ((fp = fopen(CA_cert, "r")) == NULL)
// 		return -1;
//
// 	lstat(CA_cert, &root_stat);
//
// 	root.size = root_stat.st_size;
// 	if ((root.data = malloc(root.size * sizeof(unsigned char))) == NULL) {
// 		return -1;
// 	}
//
// 	fread(root.data, root.size, 1, fp);
//
// 	fclose(fp);
//
// 	if ((ret = gnutls_x509_crt_init(&root_x509)) < 0) {
// 		fprintf(stderr, "gnutls_x509_crt_init - %s\n",
// 				gnutls_strerror(ret));
// 		return -1;
// 	}
//
// 	if ((ret = gnutls_x509_crt_import(root_x509, &root, GNUTLS_X509_FMT_PEM)) < 0) {
// 		fprintf(stderr, "gnutls_x509_crt_import - %s\n",
// 				gnutls_strerror(ret));
// 		return -1;
// 	}
//
// 	if ((ret = gnutls_x509_trust_list_init(&tlist, 0)) < 0) {
// 		fprintf(stderr, "gnutls_x509_trust_list_init - %s\n",
// 				gnutls_strerror(ret));
// 		return -1;
// 	}
//
// 	/* Add root CA's certificate to the trusted list.
// 		The list of CAs must not be deinitialized during this structure's lifetime. */
// 	if (gnutls_x509_trust_list_add_cas(tlist, &root_x509, 1, 0) != 1) {
// 		/* wrong number of certificate added; should be 1 */
// 		DEBUG_PRINT("Wrong number of certificate added; should be 1.");
// 		return -1;
// 	}
//
// 	/* Set root CA as last ring of the chain */
// 	if ((ret = gnutls_x509_crt_init(&cert_x509[1])) < 0) {
// 		fprintf(stderr, "gnutls_x509_crt_init - %s\n",
// 				gnutls_strerror(ret));
// 		return -1;
// 	}
//
// 	if ((ret = gnutls_x509_crt_import(cert_x509[1], &root, GNUTLS_X509_FMT_PEM)) < 0) {
// 		fprintf(stderr, "gnutls_x509_crt_import - %s\n",
// 				gnutls_strerror(ret));
// 		return -1;
// 	}
//
// 	DIR *dp;
//     struct dirent *entry;
//     struct stat statbuf;
// 	int validated_certificates = 0;
//
//     if((dp = opendir(cert_dir)) == NULL) {
//         fprintf(stderr,"cannot open directory\n");
//         return -1;
//     }
//
// 	char cwd[PATH_MAX];
// 	getcwd(cwd, PATH_MAX);
//
//     chdir(cert_dir);
//     while((entry = readdir(dp)) != NULL) {
//
// 		if ((fp = fopen(entry->d_name, "r")) == NULL)
// 			return -1;
//
// 		lstat(entry->d_name, &statbuf);
//
// 		if(S_ISDIR(statbuf.st_mode))
// 		 /* Skip . and .. */
// 			continue;
//
// 		cert.size = statbuf.st_size;
//
// 		if ((cert.data = malloc(cert.size * sizeof(unsigned char))) == NULL) {
// 			return -1;
// 		}
//
// 		fread(cert.data, cert.size, 1, fp);
//
// 		fclose(fp);
//
// 		if ((ret = gnutls_x509_crt_init(&cert_x509[0])) < 0) {
// 			fprintf(stderr, "gnutls_x509_crt_init - %s\n",
// 					gnutls_strerror(ret));
// 			return -1;
// 		}
//
// 		/* If the file is not a certificate importation should fail */
// 		if ((ret = gnutls_x509_crt_import(cert_x509[0], &cert, GNUTLS_X509_FMT_PEM)) < 0) {
// 			DEBUG_PRINT("gnutls_x509_crt_import: %s - %s\n", entry->d_name, gnutls_strerror(ret));
// 			continue;
// 		}
//
// 		gnutls_free(cert.data);
//
// 		unsigned int result;
// 		if ((ret = gnutls_x509_trust_list_verify_crt(tlist, cert_x509, 2, 0, &result, NULL)) < 0) {
// 			fprintf(stderr, "gnutls_x509_trust_list_verify_crt - %s\n",
// 					gnutls_strerror(ret));
// 			return -1;
// 		}
//
// 		if (result == 0) {
// 			/* result: 0 if validated */
// 			DEBUG_PRINT("Certificate %s is valid\n", entry->d_name);
// 			validated_certificates++;
// 		} else {
// 			DEBUG_PRINT("Certificate %s is invalid\n", entry->d_name);
// 		}
//
// 		gnutls_x509_crt_deinit(cert_x509[0]);
//     }
//
//     closedir(dp);
// 	chdir(cwd);
//
// 	/* Clean root CA's certificate */
// 	gnutls_x509_crt_deinit(cert_x509[1]);
// 	gnutls_x509_crt_deinit(root_x509);
// 	/* Clean up root datum */
// 	gnutls_free(root.data);
//
// 	return validated_certificates;
// }

static inline void protocol_msg_init(struct ether_header *ehdr, struct vde_agno_conn *conn) {
	/* Broadcast MAC address --> FF:FF:FF:FF:FF:FF */
	/* Fill the 6 (ETH_ALEN) bytes of the destination MAC address */
	memset(ehdr->ether_dhost, 0xFF, ETH_ALEN);
	/* NOTE: We don't have a way to know the MAC address of the sender */
	memset(ehdr->ether_shost, 0x00, ETH_ALEN);

	switch (conn->ether_type) {
		case 0xffff:
			/* 0x600 <= random number < 0xffff */
			/* if type <= 0x600 many systems think it is the lenght */
			ehdr->ether_type = ntohs(0x600 + (rand() % 0xf9ff));
			break;
		case 0:
			/* NOTE: ether_type should have the same type of the non agno packet.
			 	In this case this doesn't make sense because we're dealing with
				a protocol message; let's give it an AGNO_TYPE */
			ehdr->ether_type = htons(AGNO_TYPE);
			break;
		default:
			ehdr->ether_type = conn->ether_type;
	}
}

static inline int is_protocol_msg(uint8_t *msg) {
	struct ether_header *ehdr = (struct ether_header *) msg;
	/* A protocol message has 00:00:00:00:00:00 as MAC sender */
	for (size_t i = 0; i < ETH_ALEN; i++)
		if (ehdr->ether_shost[i] != 0x00)
			return 0;
	return 1;
}

/* TODO: change */
/* Used to avoid buffer overflow vulnerabilities on id string */
static inline int check_enc_protocol_msg(uint8_t *msg, size_t msg_len) {
	struct ether_header *ehdr = (struct ether_header *) msg;
	uint8_t *enc_ahdr_key = (uint8_t *) (ehdr + 1);
	char *id = (char *) (enc_ahdr_key + 256);

	const size_t id_len = msg_len - ETH_HEADER_SIZE - 256;
	return id[id_len - 1] == '\0';
}

/* Preconditions:
 	conn->id is a well-formed string */
int negotiate_session_key_client(struct vde_agno_conn *conn) {
	/** Data used to listen for incoming messages */
	fd_set input_set;
	/* Setting up a timeout for a valid answer */
    struct timeval timeout = {
		.tv_sec  = 1,	// 1 second
		.tv_usec = 0
	};
	/* fd used to check if there are incoming packets */
	int listen_fd;
	/* Flag that says if we are ready to call a non blocking vde_recv */
    int ready4recv;
	/* Return value for gnutls functions */
	int ret;

	/* Lenght of the request packet */
	const size_t req_len = ETH_HEADER_SIZE + RSA_SIGN_SIZE + PROTOCOL_HEADER_SIZE + (strlen(conn->id) + 1);
	/* Buffer for the request packet */
	uint8_t req_buf[req_len];
	/* Mapping of the request packet */
	struct ether_header *req_ehdr = (struct ether_header *) req_buf;
	/* Protocol header signed with RSA */
	uint8_t *req_signed_hdr = (uint8_t *) (req_ehdr + 1);
	/* Clear protocol header */
	struct agno_protocol_hdr *req_hdr = (struct agno_protocol_hdr *) (req_signed_hdr + RSA_SIGN_SIZE);
	char *client_id = (char *) (req_hdr + 1);

	/* Copy client id into packet */
	strcpy(client_id, conn->id);

	/* Request packet initialization */
	protocol_msg_init(req_ehdr, conn);

	/* Initialize plain request header */
	req_hdr->tag = AGNO_TAG;
	req_hdr->time = htonl(time(NULL));
	req_hdr->type = PROTOCOL_TYPE_REQUEST;

	const gnutls_datum_t request_hdr = {(void *) req_hdr, PROTOCOL_HEADER_SIZE};
	gnutls_datum_t signed_request_hdr;

	if ((ret = gnutls_privkey_sign_data(conn->privkey, GNUTLS_DIG_SHA256, 0, &request_hdr, &signed_request_hdr)) < 0) {
		DEBUG_PRINT("gnutls_privkey_sign_data - %s\n", gnutls_strerror(ret));
		return -1;
	}

	assert(signed_request_hdr.size == RSA_SIGN_SIZE);
	/* Copy signed request header in send buffer */
	memcpy(req_signed_hdr, signed_request_hdr.data, RSA_SIGN_SIZE);
	/* Free allocated memory */
	gnutls_free(signed_request_hdr.data);

	/* Get fd for event handling (wait for network packets) */
	listen_fd = vde_datafd(conn->conn);
	if (listen_fd < 0)
		return -1;

	/********** Starting negotiation **********/
	/* Send request */
	if (vde_send(conn->conn, req_buf, req_len, 0) < 0)
		/* Send error */
		return -1;

	/* Empty the FD Set */
	FD_ZERO(&input_set);
	/* Listen to the input descriptor */
	FD_SET(listen_fd, &input_set);

	/* Wait for the reply */
	while (1) {
		/* Listening for incoming messages */
	    ready4recv = select(listen_fd + 1, &input_set, NULL, NULL, &timeout);

		switch (ready4recv) {
			case -1:
				/* Some error has occured */
	        	return -1;
			case  0:
				/* Timeout expired */
				DEBUG_PRINT("Timeout expired - no data input \n");
				/* Generate session key */
				if (gnutls_rnd(GNUTLS_RND_KEY, conn->session_key, AES_KEY_SIZE) < 0)
					return -1;
				else
					return 0;
			default:
				DEBUG_PRINT("Message received\n");

				/* NOTE: As a message arrived on the listen_fd
					FD_ISSET(listen_fd, &input_set) will be true.
					If we executo continue command we don't need to reset
					the input_set. */

				/* Buffer for the reply packet */
				uint8_t recv_buf[ETHER_MAX_LEN];

				size_t msg_len;
				if ((msg_len = vde_recv(conn->conn, recv_buf, ETHER_MAX_LEN, 0)) < ETH_HEADER_SIZE)
					/* Receive another packet. NOTE: when we do continue we
						don't reset the timeout struct */
					continue;

				if (!is_protocol_msg(recv_buf) || !check_enc_protocol_msg(recv_buf, msg_len))
					continue;

				/* Ethernet header of the received packet;
					 NOTE: we don't know if the packet is a well-formed agno reply */
				struct ether_header *reply_ehdr = (struct ether_header *) recv_buf;
				uint8_t *signed_hdr_key = (uint8_t *) (reply_ehdr + 1);
				uint8_t *enc_hdr_key = signed_hdr_key + RSA_BLOCK_SIZE;
				char *server_id = (char *) (enc_hdr_key + RSA_BLOCK_SIZE);

				gnutls_pubkey_t server_pubkey;

				if ((ret = gnutls_pubkey_init(&server_pubkey)) < 0) {
					DEBUG_PRINT("gnutls_pubkey_init - %s\n", gnutls_strerror(ret));
					return -1;
				}

				char *certfile_path = get_certfile_from_id(conn->certificate_folder, server_id);
				if (get_public_key_x509(&server_pubkey, certfile_path) < 0) {
					DEBUG_PRINT("get_certfile_from_id\n");
					free(certfile_path);
					continue;
				}
				free(certfile_path);

				const gnutls_datum_t enc_hdr_key_dat = {enc_hdr_key, RSA_BLOCK_SIZE};
				const gnutls_datum_t signed_hdr_key_dat = {signed_hdr_key, RSA_BLOCK_SIZE};
				gnutls_datum_t plain_hdr_key_dat;

				if ((ret = gnutls_privkey_decrypt_data(conn->privkey, 0, &enc_hdr_key_dat, &plain_hdr_key_dat)) < 0) {
					DEBUG_PRINT("gnutls_privkey_decrypt_data - %s\n", gnutls_strerror(ret));
					continue;
				}

				if (plain_hdr_key_dat.size != PROTOCOL_HEADER_SIZE + AES_KEY_SIZE) {
					gnutls_free(plain_hdr_key_dat.data);
					/* Receive another packet */
					continue;
				}

				struct agno_protocol_hdr *plain_hdr = (struct agno_protocol_hdr *) plain_hdr_key_dat.data;

				if (plain_hdr->tag != AGNO_TAG ||
						plain_hdr->type != PROTOCOL_TYPE_REPLY ||
						(time(NULL) - ntohl(plain_hdr->time) + 1) & ~3) {
					gnutls_free(plain_hdr_key_dat.data);
					continue;
				}

				if (gnutls_pubkey_verify_data2(server_pubkey, GNUTLS_SIGN_RSA_SHA256, 0, &plain_hdr_key_dat, &signed_hdr_key_dat) < 0) {
					gnutls_free(plain_hdr_key_dat.data);
					continue;
				}

				DEBUG_PRINT("Valid answer got\n");

				/* Save session key (found after agno header) */
				memcpy(conn->session_key, (uint8_t *) (plain_hdr + 1), AES_KEY_SIZE);

				gnutls_free(plain_hdr_key_dat.data);

				return 0;
		}
	}
}

/* Preconditions: request is buffer overflow safe (use check_enc_protocol_msg) */
int negotiate_session_key_server(struct vde_agno_conn *conn, uint8_t *request) {
	/* Return value for gnutls functions */
	int ret;

	struct ether_header *ehdr = (struct ether_header *) request;
	uint8_t *signed_hdr = (uint8_t *) (ehdr + 1);
	struct agno_protocol_hdr *plain_hdr = (struct agno_protocol_hdr *) (signed_hdr + RSA_SIGN_SIZE);
	char *client_id = (char *) (plain_hdr + 1);

	if (plain_hdr->tag != AGNO_TAG ||
			plain_hdr->type != PROTOCOL_TYPE_REQUEST ||
			(time(NULL) - ntohl(plain_hdr->time) + 1) & ~3) {
		return -1;
	}

	gnutls_pubkey_t client_pubkey;

	if ((ret = gnutls_pubkey_init(&client_pubkey)) < 0) {
		DEBUG_PRINT("gnutls_pubkey_init - %s\n", gnutls_strerror(ret));
		return -1;
	}

	char *certfile_path = get_certfile_from_id(conn->certificate_folder, client_id);
	if (get_public_key_x509(&client_pubkey, certfile_path) < 0) {
		DEBUG_PRINT("get_certfile_from_id\n");
		free(certfile_path);
		return -1;
	}
	free(certfile_path);

	const gnutls_datum_t signed_hdr_dat = {signed_hdr, RSA_SIGN_SIZE};
	const gnutls_datum_t plain_hdr_dat = {(void *) plain_hdr, PROTOCOL_HEADER_SIZE};

	if ((ret = gnutls_pubkey_verify_data2(client_pubkey, GNUTLS_SIGN_RSA_SHA256, 0, &plain_hdr_dat, &signed_hdr_dat)) < 0) {
		DEBUG_PRINT("gnutls_pubkey_verify_data2 - %s\n", gnutls_strerror(ret));
		return -1;
	}

	const size_t reply_len = ETH_HEADER_SIZE + RSA_BLOCK_SIZE * 2 + (strlen(conn->id) + 1);
	uint8_t reply_buf[reply_len];
	/* Mapping of reply packet */
	struct ether_header *reply_ehdr = (struct ether_header *) reply_buf;
	uint8_t *reply_signed_hdr_key = (uint8_t *) (reply_ehdr + 1);
	uint8_t *reply_enc_hdr_key = reply_signed_hdr_key + RSA_SIGN_SIZE;
	char *server_id = (char *) (reply_enc_hdr_key + RSA_BLOCK_SIZE);

	strcpy(server_id, conn->id);

	/* Init answer packet */
	protocol_msg_init(reply_ehdr, conn);

	uint8_t plain_hdr_key[PROTOCOL_HEADER_SIZE + AES_KEY_SIZE];
	struct agno_protocol_hdr *plain_reply_hdr = (struct agno_protocol_hdr *) plain_hdr_key;
	uint8_t *plain_session_key = (uint8_t *) (plain_reply_hdr + 1);

	plain_reply_hdr->tag = AGNO_TAG;
	plain_reply_hdr->time = htonl(time(NULL));
	plain_reply_hdr->type = PROTOCOL_TYPE_REPLY;

	memcpy(plain_session_key, conn->session_key, AES_KEY_SIZE);

	const gnutls_datum_t plain_hdr_key_dat = {plain_hdr_key, PROTOCOL_HEADER_SIZE + AES_KEY_SIZE};
	gnutls_datum_t signed_hdr_key_dat, enc_hdr_key_dat;

	if ((ret = gnutls_privkey_sign_data(conn->privkey, GNUTLS_DIG_SHA256, 0, &plain_hdr_key_dat, &signed_hdr_key_dat)) < 0) {
		DEBUG_PRINT("gnutls_privkey_sign_data - %s\n", gnutls_strerror(ret));
		return -1;
	}

	assert(signed_hdr_key_dat.size == RSA_SIGN_SIZE);

	memcpy(reply_signed_hdr_key, signed_hdr_key_dat.data, RSA_SIGN_SIZE);

	gnutls_free(signed_hdr_key_dat.data);

	if ((ret = gnutls_pubkey_encrypt_data(client_pubkey, 0, &plain_hdr_key_dat, &enc_hdr_key_dat)) < 0) {
		DEBUG_PRINT("gnutls_pubkey_encrypt_data - %s\n", gnutls_strerror(ret));
		return -1;
	}

	assert(enc_hdr_key_dat.size == RSA_BLOCK_SIZE);

	memcpy(reply_enc_hdr_key, enc_hdr_key_dat.data, RSA_BLOCK_SIZE);

	gnutls_free(enc_hdr_key_dat.data);

	/* Send back answer */
	if (vde_send(conn->conn, reply_buf, reply_len, 0) < 0) {
		fprintf(stderr, "Answer not sent\n");
		return -1;
	}

	DEBUG_PRINT("Reply sent\n");
	return 0;
}

/* Parses the configuration file and stores the info in a vde_agno_conn struct.
	conn - struct vde_agno_conn where the information of the configuration file
		will be stored.
	config - path of the configuration file. */
int get_config_info(struct vde_agno_conn *conn, const char *config) {
	/* Configuration structure */
	config_t cfg;
	/* Return value for lookup over configuration file */
	const char *value;
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
	char pwdbuf[bufsize];
	/* buffer for absolute path of the keyfile */
	char path[PATH_MAX + 1];
	/* Get password file from uid */
	/* result is initialized by getpwuid_r */
	if (getpwuid_r(geteuid(), &pwd, pwdbuf, bufsize, &result) != 0 || result == NULL) {
		return -1;
	}
	/* Get absolute path of keyfile */
	if (config == NULL || *config == 0)
	/* keyfile not specified */
		snprintf(path, PATH_MAX, "%s/" DEFAULT_CONFIGFILE, result->pw_dir);
	else if (*config == '~')
	/* keyfile based on home directory */
		snprintf(path, PATH_MAX, "%s/%s", result->pw_dir, config + 1);
	else if (*config == '/')
	/* keyfile is an absolute path */
		snprintf(path, PATH_MAX, "%s", config);
	else {
	/* No other formats available */
		errno = EINVAL;
		return -1;
	}
	path[PATH_MAX] = '\0';

	config_init(&cfg);

	/* Get configuration */
	if (!config_read_file(&cfg, path)) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	/* Get name of file */
	char *id = basename(path);

	/* Remove extension */
	if (strtok(id, ".") == NULL)
		return -1;

	conn->id = strdup(id);
	DEBUG_PRINT("id == \"%s\"\n", conn->id);

	if (!config_lookup_string(&cfg, "certificate_folder", &value)) {
		fprintf(stderr, "%s\n", config_error_text(&cfg));
		free(conn->id);
		config_destroy(&cfg);
		return -1;
	}

	DEBUG_PRINT("Certificate folder --> \"%s\"\n", value);

	/* Check if the directory exists */
	DIR* dir = opendir(value);
	if (!dir) {
		config_destroy(&cfg);
		return -1;
	}
	closedir(dir);

	conn->certificate_folder = strdup(value);

	// if (!config_lookup_string(&cfg, "pubkey_certificate", &value)) {
	// 	fprintf(stderr, "%s\n", config_error_text(&cfg));
	// 	free(conn->id);
	// 	config_destroy(&cfg);
	// 	return -1;
	// }
	//
	// DEBUG_PRINT("public key certificate path --> \"%s\"\n", value);

	if (gnutls_pubkey_init(&conn->pubkey) < 0) {
		fprintf(stderr, "gnutls_pubkey_init\n");
		config_destroy(&cfg);
		return -1;
	}

	char *certfile_path = get_certfile_from_id(conn->certificate_folder, conn->id);
	if (get_public_key_x509(&conn->pubkey, certfile_path) < 0) {
		DEBUG_PRINT("get_certfile_from_id\n");
		free(certfile_path);
		config_destroy(&cfg);
		return -1;
	}
	free(certfile_path);

	if (!config_lookup_string(&cfg, "privkey_file", &value)) {
		fprintf(stderr, "%s\n", config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	DEBUG_PRINT("private key file path --> \"%s\"\n", value);

	if (gnutls_privkey_init(&conn->privkey) < 0) {
		fprintf(stderr, "gnutls_privkey_init\n");
		free(conn->id);
		config_destroy(&cfg);
		return -1;
	}

	if (get_private_key(&conn->privkey, value) < 0) {
		fprintf(stderr, "get_private_key\n");
		free(conn->id);
		config_destroy(&cfg);
		return -1;
	}

	config_destroy(&cfg);
	return 0;
}

static VDECONN *vde_agno_open(char *vde_url, char *descr, int interface_version,
		struct vde_open_args *open_args)
{
	DEBUG_PRINT("vde_agno_open\n");

	/* Return value on success; dynamically allocated */
	struct vde_agno_conn *newconn = NULL;
	char *nested_url;
	char *ethtype = "";
	char *auth_only = NULL;

	/* NULL-terminating array of struct vdeparms */
	struct vdeparms parms[] = {
		{"ethtype", &ethtype},
		{"auth_only", &auth_only},
		{NULL, NULL}
	};

	VDECONN *conn;

	nested_url = vde_parsenestparms(vde_url);
	if (vde_parsepathparms(vde_url, parms) != 0)
		return NULL;

	/* Open connection with nested url */
	conn = vde_open(nested_url, descr, open_args);
	if (conn == NULL)
		return  NULL;
	if ((newconn = calloc(1, sizeof(struct vde_agno_conn))) == NULL) {
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

	newconn->auth_only = auth_only != NULL;

	if (get_config_info(newconn, vde_url) == -1)
		goto error;

	if (negotiate_session_key_client(newconn) == -1)
		goto error;

	const gnutls_datum_t session_key = {newconn->session_key, 16};

	/* Initialize authenticated symmetric encryption context */
	if (gnutls_aead_cipher_init(&newconn->aes_gcm_ctx, GNUTLS_CIPHER_AES_128_GCM, &session_key) < 0) {
		fprintf(stderr, "gnutls_aead_cipher_init\n");
		/* TODO: goto "vdeplug: success" */
		goto error;
	}

	DEBUG_PRINT("Initialization completed\n");

	return (VDECONN *) newconn;

error:
	vde_close(conn);
	return NULL;
}

void print_enc_packet(const uint8_t *enc_packet, const size_t enc_packet_size) {
	struct ether_header *enc_ehdr = (struct ether_header *) enc_packet_size;
	uint8_t *nonce = (uint8_t *) (enc_ehdr + 1);
	/* Secure data (encrypted agno header and payload) + ICV */
	uint8_t *secure_data_icv = nonce + NONCE_SIZE;
	const size_t secure_data_icv_size = enc_packet_size - (ETH_HEADER_SIZE + NONCE_SIZE);

	for (size_t i = 0; i < ETH_HEADER_SIZE; i++)
		fprintf(stderr, "%x ", ((uint8_t *) enc_ehdr)[i]);

	fprintf(stderr, "| ");

	for (size_t i = 0; i < NONCE_SIZE; i++)
		fprintf(stderr, "%x ", nonce[i]);

	fprintf(stderr, "| ");

	for (size_t i = 0; i < secure_data_icv_size - ICV_SIZE; i++)
		fprintf(stderr, "%x ", secure_data_icv[i]);

	fprintf(stderr, "| ");

	for (size_t i = secure_data_icv_size - ICV_SIZE; i < secure_data_icv_size; i++)
		fprintf(stderr, "%x ", secure_data_icv[i]);

	fprintf(stderr, "\n");
}

static ssize_t vde_agno_recv(VDECONN *conn, void *buf, size_t len, int flags) {
	/* agno connection */
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *) conn;
	/* Array of bytes where receiving and decryption are done */
	uint8_t recvbuf[ETHER_MAX_LEN];

	if (len < ETH_HEADER_SIZE)
		goto error;

	ssize_t retval = vde_recv(vde_conn->conn, recvbuf, ETHER_MAX_LEN, flags);

	if (retval < 0)
		return retval;
	if (retval < ETH_HEADER_SIZE)
		goto error;

	if (is_protocol_msg(recvbuf)) {
		if (!check_enc_protocol_msg(recvbuf, retval))
			return -1;
		if (negotiate_session_key_server(vde_conn, recvbuf) == -1)
			goto error;
		return -1;	/* TODO: decide success return value */
		/* WARNING: return value 0 causes a bug in the vdens.
		 	The vdens exits without command. */
	} else {
															/* At least 1 octet of payload */
		if (retval < ETH_HEADER_SIZE + NONCE_SIZE + AGNO_HEADER_SIZE + 1 + ICV_SIZE)
			/* TODO: decide return value policies */
			return 1;

		/** Mapping of the plain packet **/
		struct ether_header *ehdr = (struct ether_header *) buf;
		uint8_t *payload = (uint8_t *) (ehdr + 1);

		/** Mapping of the encrypted packet **/
		/* NOTE: we are not sure if the recvbuf contains a valid encrypted packet */
		struct ether_header *enc_ehdr = (struct ether_header *) recvbuf;
		uint8_t *nonce = (uint8_t *) (enc_ehdr + 1);
		/* Secure data (encrypted agno header and payload) + ICV */
		// uint8_t *secure_data_icv = nonce + NONCE_SIZE;
		// const size_t secure_data_icv_size = retval - (ETH_HEADER_SIZE + NONCE_SIZE);
		uint8_t *secure_data = nonce + NONCE_SIZE;
		const size_t secure_data_size = retval - (ETH_HEADER_SIZE + NONCE_SIZE + ICV_SIZE);
		uint8_t *icv = secure_data + secure_data_size;

		// fprintf(stderr, "PACCHETTO CHE IN ENTRATA\n");
		// print_enc_packet(recvbuf, retval);

		/* The Ethernet header is not encrypted, we can already copy it. */
		memcpy(ehdr, enc_ehdr, ETH_HEADER_SIZE);

		// const size_t secure_data_size = secure_data_icv_size - ICV_SIZE;

		/* Return value for gnutls_aead_cipher_decrypt() */
		int ret;

		if (vde_conn->auth_only) {
			struct agno_hdr *ahdr = (struct agno_hdr *) secure_data;
			uint8_t *_payload = (uint8_t *) (ahdr + 1);

			/* NOTE: if the header is in plaintext we could check time before decryption */

			size_t ptext_len = 0;

			if ((ret = gnutls_aead_cipher_decrypt(vde_conn->aes_gcm_ctx,
									nonce, NONCE_SIZE,
									recvbuf, retval - ICV_SIZE, /* The whole packet is AD */
									ICV_SIZE,
									icv, ICV_SIZE, /* ICV only */
									NULL, &ptext_len)) < 0) {
				DEBUG_PRINT("%s\n", gnutls_strerror(ret));
				return 1;
			}

			assert(ptext_len == 0);

			if ((time(NULL) - ntohl(ahdr->time) + 1) & ~3) /* avoid record_playback */
				goto error;

			ehdr->ether_type = ahdr->ether_type;

			size_t pkt_lenght = ETH_HEADER_SIZE + secure_data_size - AGNO_HEADER_SIZE;
			pkt_lenght = pkt_lenght < len ? pkt_lenght : len;

			memcpy(payload, _payload, pkt_lenght - ETH_HEADER_SIZE);

			return pkt_lenght;

		} else {
			uint8_t ptext[secure_data_size];
			struct agno_hdr *ahdr = (struct agno_hdr *) ptext;
			uint8_t *_payload = (uint8_t *) (ahdr + 1);

			size_t ptext_len = secure_data_size;

			if ((ret = gnutls_aead_cipher_decrypt(vde_conn->aes_gcm_ctx,
									nonce, NONCE_SIZE,
									enc_ehdr, ETH_HEADER_SIZE, /* Only the header is authenticated */
									ICV_SIZE,
									secure_data, secure_data_size + ICV_SIZE, /* Secure data + ICV */
									ptext, &ptext_len)) < 0) {
				DEBUG_PRINT("%s\n", gnutls_strerror(ret));
				return 1;
			}

			assert(ptext_len == secure_data_size);

			if ((time(NULL) - ntohl(ahdr->time) + 1) & ~3) /* avoid record_playback */
				goto error;

			ehdr->ether_type = ahdr->ether_type;

			size_t pkt_lenght = ETH_HEADER_SIZE + secure_data_size - AGNO_HEADER_SIZE;
			pkt_lenght = pkt_lenght < len ? pkt_lenght : len;

			memcpy(payload, _payload, pkt_lenght - ETH_HEADER_SIZE);

			return pkt_lenght;
		}
	}

error:
	errno = EAGAIN;
	return 1;
}

static ssize_t vde_agno_send(VDECONN *conn, const void *buf, size_t len, int flags) {
	/* agno connection */
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *) conn;

	if (len < ETH_HEADER_SIZE)
		return len;

	/** Mapping of the plain packet **/
	struct ether_header *ehdr = (struct ether_header *) buf;
	uint8_t *payload = (uint8_t *) (ehdr + 1);
	const size_t payload_size = len - ETH_HEADER_SIZE;

	/* payload is not padded */
	const size_t secure_data_size = AGNO_HEADER_SIZE + payload_size;
	/* Lenght of the entire encrypted packet */
	const size_t enclen = ETH_HEADER_SIZE + NONCE_SIZE + secure_data_size + ICV_SIZE;
	/* buffer for the encrypted packet */
	uint8_t encbuf[enclen];
	/* ethernet header of the encrypted packet (copy of the plain packet's header) */
	struct ether_header *enc_ehdr = (struct ether_header *) encbuf;
	uint8_t *nonce = (uint8_t *) (enc_ehdr + 1);
	/* Secure data (encrypted agno header and payload) */
	uint8_t *secure_data = nonce + NONCE_SIZE;
	uint8_t *icv = secure_data + secure_data_size;

	/* Copy the clear ethernet header */
	*enc_ehdr = *ehdr;

	switch (vde_conn->ether_type) {
		case 0:
			// enc_ehdr->ether_type = ehdr->ether_type;
			break;
		case 0xffff:
			/* 0x600 <= random number < 0xffff */
			/* if type <= 0x600 many systems think it is the lenght */
			enc_ehdr->ether_type = ntohs(0x600 + (rand() % 0xf9ff));
			break;
		default:
			enc_ehdr->ether_type = vde_conn->ether_type;
	}

	/* Init rand bytes of the nonce */
	if (gnutls_rnd(GNUTLS_RND_NONCE, nonce, NONCE_SIZE) < 0)
		return -1;

	/* Return value for gnutls_aead_cipher_encrypt() */
	int ret;

	if (vde_conn->auth_only) {

		size_t icv_size = ICV_SIZE;

		struct agno_hdr *ahdr = (struct agno_hdr *) secure_data;
		uint8_t *_payload = (uint8_t *) (ahdr + 1);

		ahdr->ether_type = ehdr->ether_type;
		ahdr->flags = 0;
		ahdr->time = htonl(time(NULL));

		memcpy(_payload, payload, payload_size);

		if ((ret = gnutls_aead_cipher_encrypt(vde_conn->aes_gcm_ctx,
									nonce, NONCE_SIZE,
									encbuf, enclen - ICV_SIZE,
									ICV_SIZE,
									NULL, 0,
									icv, &icv_size)) < 0) {
			DEBUG_PRINT("%s\n", gnutls_strerror(ret));
			return -1;
		}

		assert(icv_size == ICV_SIZE);
	} else {
		uint8_t ptext[AGNO_HEADER_SIZE + payload_size];
		struct agno_hdr *ahdr = (struct agno_hdr *) ptext;
		uint8_t *_payload = (uint8_t *) (ahdr + 1);

		ahdr->ether_type = ehdr->ether_type;
		ahdr->flags = 0;
		ahdr->time = htonl(time(NULL));

		memcpy(_payload, payload, payload_size);

		size_t secure_data_icv_len = secure_data_size + ICV_SIZE;

		if ((ret = gnutls_aead_cipher_encrypt(vde_conn->aes_gcm_ctx,
									nonce, NONCE_SIZE,
									enc_ehdr, ETH_HEADER_SIZE,
									ICV_SIZE,
									ptext, AGNO_HEADER_SIZE + payload_size,
									secure_data, &secure_data_icv_len)) < 0) {
			DEBUG_PRINT("%s\n", gnutls_strerror(ret));
			return -1;
		}

		assert(secure_data_icv_len == secure_data_size + ICV_SIZE);
	}

	ssize_t retval = vde_send(vde_conn->conn, encbuf, enclen, flags);
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
	struct vde_agno_conn *vde_conn = (struct vde_agno_conn *) conn;

	free(vde_conn->id);
	free(vde_conn->certificate_folder);

	/* Pubkey can be deinitialized after initialization */
	gnutls_pubkey_deinit(vde_conn->pubkey);
	gnutls_privkey_deinit(vde_conn->privkey);

	/* Clean context */
	gnutls_aead_cipher_deinit (vde_conn->aes_gcm_ctx);

	return vde_close(vde_conn->conn);
}
