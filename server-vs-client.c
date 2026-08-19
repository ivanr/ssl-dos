/*
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 * Copyright (c) 2014 Ivan Ristic <ivanr@webkreator.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Tools to assess the difference of computational power between a SSL
   client and a SSL server to establish a SSL connection. Test with
   various ciphers and various certificates.

   This program will just fork a second copy to act as a client and
   exchange several SSL handshakes during a short period of time and
   measure CPU time of both client and server.
*/

#include "common.h"

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int handshake_count = 1000;

int data_writes = 0;

int data_write_len = 1;

struct result {
  int handshakes;		/* Number of handshakes done. */
  struct timespec cpu_handshake;
  struct timespec cpu;		/* CPU time */
  unsigned int handshake_read;
  unsigned int handshake_write;
  unsigned int data_writes;
  unsigned int data_len;
  unsigned int enc_data_len;
};
int       clientserver[2];

/* Dunno why I should declare it */
extern int pthread_getcpuclockid (pthread_t,
                                  clockid_t *);

/* Record handshake bytes read and written, then determine TLS
 * record overhead by sending a single byte on the connection. */
static int determine_overhead(SSL *ssl, struct result *result) {
  char *buf[data_write_len];
  int i;

  BIO *bio = SSL_get_rbio(ssl);	
  result->handshake_read = BIO_number_read(bio);
  result->handshake_write = BIO_number_written(bio);	
					
  for (i = 0; i < (data_writes == 0 ? 1 : data_writes); i++) {			
    size_t bio_write_before = BIO_number_written(bio);
			
    int r = SSL_write(ssl, buf, data_write_len);
    switch(SSL_get_error(ssl, r)) {
      case SSL_ERROR_NONE :
        result->data_writes++;
        result->data_len += data_write_len;
        if (r != data_write_len) {
          fprintf(stderr, "Client incomplete write: %d\n", r);
          return -1;
        }					
        break;
      default:
        fprintf(stderr, "Client write error.\n");
        return -1;				
    }	
		
    result->enc_data_len += BIO_number_written(bio) - bio_write_before;
    
    r = SSL_read(ssl, buf, data_write_len);	
		switch(SSL_get_error(ssl, r)) {
      case SSL_ERROR_NONE:
        break;
			case SSL_ERROR_ZERO_RETURN:
				fprintf(stderr, "Server disconnected?\n");
				break;
			default:
        fprintf(stderr, "Server read error.\n");
				return -1;
		}
  }

  return 1;
}

/* Client part */
static void* client_thread(void *arg) {
  SSL_CTX       *ctx = arg;
  int           left = handshake_count;	/* Number of handshakes left */
  static struct result result;
  result.handshakes = 0;
  result.handshake_read = 0;
  result.handshake_write = 0;
  result.data_writes = 0;
  result.data_len = 0;
  result.enc_data_len = 0;
  
  clockid_t cid;
  pthread_getcpuclockid(pthread_self(), &cid);

  while (left) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientserver[0]);		
	
    if (SSL_connect(ssl) != 1) {
      fprintf(stderr, "Client failed to connect\n");
      goto client_error;
    }
	
    result.handshakes++;
    left--;
    
    clock_gettime(cid, &result.cpu_handshake);
	
    if (result.handshake_read == 0) {
      if (determine_overhead(ssl, &result) < 0) {
        goto client_error;
      }
    }
		
    SSL_shutdown(ssl);
    SSL_shutdown(ssl);	   
    SSL_free(ssl);
	  continue;
	
client_error:
    SSL_free(ssl);
    break;
  }
     
  clock_gettime(cid, &result.cpu);
  close(clientserver[0]);
  
  return &result;
}

/* Configure key exchange for one side of the connection.

   `params` is either the name of a file or a group list. A file may hold
   DH parameters or EC parameters, and a single read tells us which; the
   decoder skips over any key and certificate the file also contains. A
   group list is anything OpenSSL accepts in the supported_groups
   extension, which is the only way to name groups that have no parameter
   encoding of their own: X25519, MLKEM1024, X25519MLKEM768 and friends.
   `openssl list -tls-groups` prints the ones this build knows.

   Both peers need the same setting. If they disagree the server sends a
   HelloRetryRequest and the client generates a second key share, which
   is a different handshake from the one we mean to measure.

   With no parameters at all, OpenSSL picks a group on its own. */
static void set_params(SSL_CTX *ctx, const char *params, int server) {
  if (!params || !*params)
    return;

  BIO *bio = BIO_new_file(params, "r");
  if (!bio) {
    /* Not a file, so read it as a group list. */
    ERR_clear_error();
    if (SSL_CTX_set1_groups_list(ctx, params) != 1)
      fail("Unable to set group list to %s:\n%s", params,
	   ERR_error_string(ERR_get_error(), NULL));

    /* A TLS 1.2 server picks the DH group itself and will not serve a DHE
       cipher suite without one, so a bare group name would otherwise fail.
       SSL_CTX_set_dh_auto() is no good here: it chooses by key strength and
       ignores supported_groups, so every ffdhe name would land on the same
       group. Build the named group explicitly instead. Names that are not
       finite-field groups simply fail to generate, which is what we want.
       TLS 1.3 ignores this, having no server-chosen parameters at all. */
    if (server) {
      EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
      EVP_PKEY *dh = NULL;
      OSSL_PARAM ps[2] = {
	OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
					 (char *)params, 0),
	OSSL_PARAM_construct_end()
      };

      if (pctx && EVP_PKEY_paramgen_init(pctx) > 0 &&
	  EVP_PKEY_CTX_set_params(pctx, ps) > 0 &&
	  EVP_PKEY_paramgen(pctx, &dh) > 0 &&
	  SSL_CTX_set0_tmp_dh_pkey(ctx, dh) != 1)
	EVP_PKEY_free(dh);

      EVP_PKEY_CTX_free(pctx);
      ERR_clear_error();
    }
    return;
  }

  EVP_PKEY *pkey = PEM_read_bio_Parameters(bio, NULL);
  BIO_free(bio);
  if (!pkey)
    return;

  switch (EVP_PKEY_get_base_id(pkey)) {
  case EVP_PKEY_DH:
  case EVP_PKEY_DHX:
    /* Only the server chooses the DH group, and on success the context
       takes ownership of the key. A bundle carries DH parameters whether
       or not the cipher suite under test wants them, so a refusal here
       (OpenSSL 3.x rejects small groups outright) is not worth dying
       over. */
    if (!server || SSL_CTX_set0_tmp_dh_pkey(ctx, pkey) != 1) {
      if (server)
	warn("Ignoring unusable DH parameters:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));
      EVP_PKEY_free(pkey);
    }
    break;

  case EVP_PKEY_EC: {
    /* Restrict the handshake to the curve named in the file. Unlike the
       old SSL_CTX_set_tmp_ecdh(), this also applies to TLS 1.3. */
    char   group[80];
    size_t group_len = 0;

    if (EVP_PKEY_get_group_name(pkey, group, sizeof(group),
				&group_len) != 1)
      fail("Unable to find specified named curve");
    if (SSL_CTX_set1_groups_list(ctx, group) != 1)
      fail("Unable to set group list to %s:\n%s", group,
	   ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(pkey);
    break;
  }

  default:
    EVP_PKEY_free(pkey);
    break;
  }
}

static pthread_t start_client(const char *ciphersuite, const char *params) {
  SSL_CTX *ctx;

  start("Initializing client");
  if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
    fail("Unable to initialize SSL context:\n%s",
         ERR_error_string(ERR_get_error(), NULL));

  /* We deliberately benchmark small keys and weak cipher suites, so lift
     the default security level out of the way. */
  SSL_CTX_set_security_level(ctx, 0);

  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	
  #ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  #endif
  
  if (SSL_CTX_set_ciphersuites(ctx, ciphersuite) != 1) {
    // Setting a TLS 1.3 suite failed, so let's assume it's TLS 1.2
    // or below. Also, disable TLS 1.3 just in case.
    
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    
    if (SSL_CTX_set_cipher_list(ctx, ciphersuite) != 1)
      fail("Unable to set cipher list to %s:\n%s",
           ciphersuite,
           ERR_error_string(ERR_get_error(), NULL));
  } else {
    // Setting a TLS 1.3 worked, so we want to enable only TLS 1.3.
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  }

  set_params(ctx, params, 0);

  pthread_t threadid;
  if (pthread_create(&threadid, NULL, &client_thread, ctx))
    fail("Unable to create server thread");
  
  return threadid;
}

/* Server part */
static void* server_thread(void *arg) {
  SSL_CTX *ctx = arg;
  char buf[data_write_len];
  static struct result result;
  result.handshakes = 0;
  
  clockid_t cid;
  pthread_getcpuclockid(pthread_self(), &cid);

  while (1) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientserver[1]);
    if (SSL_accept(ssl) != 1)
      break;
    result.handshakes++;
    
    clock_gettime(cid, &result.cpu_handshake);
			
    int receiving = 1;
    while(receiving) {
      int write_back = 0;
      int r = SSL_read(ssl, buf, data_write_len);	
      switch(SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
          write_back = 1;
          break;
        case SSL_ERROR_ZERO_RETURN:
          receiving = 0;
          break;
        default:
          fprintf(stderr, "Server read error.");
          goto server_error;					
      }

      if (write_back) {
        r = SSL_write(ssl, buf, data_write_len);
        switch(SSL_get_error(ssl, r)) {
          case SSL_ERROR_NONE :          
            if (r != data_write_len) {
              fprintf(stderr, "Server incomplete write: %d\n", r);
              goto server_error;
            }					
            break;
          default:
            fprintf(stderr, "Server write error.\n");
            goto server_error;
        }	
      }
    }	
	
    SSL_shutdown(ssl);
    SSL_shutdown(ssl);    
    SSL_free(ssl);
    continue;
    
server_error:
    SSL_free(ssl);
    break;
  }
  
  clock_gettime(cid, &result.cpu);
  close(clientserver[1]);
  return &result;
}

static pthread_t start_server(const char *ciphersuite,
			      const char *certificate, const char *params) {
  SSL_CTX *ctx;

  start("Initializing server");
  if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL)
    fail("Unable to initialize SSL context:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));

  /* See start_client(). */
  SSL_CTX_set_security_level(ctx, 0);

  #ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  #endif

  /* Cipher suite */
  if (SSL_CTX_set_ciphersuites(ctx, ciphersuite) != 1) {
    // Setting a TLS 1.3 suite failed, so let's assume it's TLS 1.2
    // or below. Also, disable TLS 1.3 just in case.
    
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    
    if (SSL_CTX_set_cipher_list(ctx, ciphersuite) != 1)
      fail("Unable to set cipher list to %s:\n%s",
	   ciphersuite,
	   ERR_error_string(ERR_get_error(), NULL));
  } else {
    // Setting a TLS 1.3 worked, so we want to enable only TLS 1.3.
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  }

  /* Disable session caching */	 
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

  /* Certificate */
  if (SSL_CTX_use_certificate_chain_file(ctx, certificate) <= 0)
    fail("Unable to use given certificate:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));
  if (SSL_CTX_use_PrivateKey_file(ctx, certificate, SSL_FILETYPE_PEM) <= 0)
    fail("Unable to use given key file:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));

  set_params(ctx, params, 1);

  pthread_t threadid;
  if (pthread_create(&threadid, NULL, &server_thread, ctx))
    fail("Unable to create server thread");
  
  return threadid;
}

int
main(int argc, char * const argv[]) {
  if ((argc != 3)&&(argc != 4)&&(argc != 5)&&(argc != 6)) {
    fprintf(stderr, "Usage: \n");
    fprintf(stderr, "  %s ciphersuite certificate [params [handshakes [writes]]]\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, " - `ciphersuite` is the name of cipher suite to use. Use\n");
    fprintf(stderr, "   `openssl ciphers` to choose one.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " - `certificate` is the name of the file containing the key and certificate.\n");    
    fprintf(stderr, "\n");
    fprintf(stderr, " - `params` selects the key exchange. It is either the name of a\n");
    fprintf(stderr, "   file containing DH or ECDH params, or a group list such as\n");
    fprintf(stderr, "   `x25519`, `ffdhe2048` or `X25519MLKEM768`. Run\n");
    fprintf(stderr, "   `openssl list -tls-groups` to see what is supported.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " - `handshakes` is the number of handshakes you wish to\n");
    fprintf(stderr, "   test. Defaults to 1000.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " - `writes` is the number of 16kb writes to test with\n");
    fprintf(stderr, "   test. Defaults to 0, which will use a single 1-byte transfer\n");
    fprintf(stderr, "   to measure record overhead only.\n");
    return 1;
  }

  const char *ciphersuite = argv[1];
  const char *certificate = argv[2];
  const char *params = NULL;
  
  if (argc > 3) {
    params = argv[3];
  }
  
  if (argc > 4) {
    handshake_count = atoi(argv[4]);
  }
  
  if (argc > 5) {
    data_writes = atoi(argv[5]);
    if (data_writes > 0) {
      data_write_len = 16384;
      handshake_count = 1;
    }
  }

  /* OpenSSL 1.1.0 and later initialize themselves on first use and are
     thread-safe without any locking callbacks from the application. */

  /* Whichever of the two threads finishes first closes its end of the
     socket pair, so the other one is bound to write to a closed peer.
     We want the error from write(), not the default SIGPIPE death. */
  signal(SIGPIPE, SIG_IGN);

  pthread_t client, server;
  start("Prepare client and server");
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, clientserver))
    fail("Unable to get a socket pair for client/server communication:\n%m");
  server = start_server(ciphersuite, certificate, params);
  client = start_client(ciphersuite, params);

  struct result *client_result, *server_result;
  start("Waiting for client to finish");
  if (pthread_join(client, (void **)&client_result))
    fail("Unable to join client thread");
  start("Waiting for server to finish");
  if (pthread_join(server, (void **)&server_result))
    fail("Unable to join server thread");

  end("Got the following results:\n"
      "Handshakes from client: %d\n"
      "Total User CPU time in client: %4ld.%03ld\n"	  
      "Transfer User CPU time in client: %4ld.%03ld\n"
      "Handshakes from server: %d\n"
      "Total User CPU time in server: %4ld.%03ld\n"
      "Transfer User CPU time in server: %4ld.%03ld\n"
      "Ratio: %.2f %%\n"
      "\n"
      "Client handshake bytes received: %d\n"
      "Client handshake bytes written: %d\n"      
      "TLS record length: %d (data %d, overhead %d)", 
      client_result->handshakes,
      client_result->cpu.tv_sec, client_result->cpu.tv_nsec / 1000000,	  
      client_result->cpu.tv_sec - client_result->cpu_handshake.tv_sec, (client_result->cpu.tv_nsec - client_result->cpu_handshake.tv_nsec) / 1000000,	  
      server_result->handshakes,
      server_result->cpu.tv_sec, server_result->cpu.tv_nsec / 1000000,
      server_result->cpu.tv_sec - server_result->cpu_handshake.tv_sec, (server_result->cpu.tv_nsec - server_result->cpu_handshake.tv_nsec) / 1000000,
      (server_result->cpu.tv_sec * 1000. + server_result->cpu.tv_nsec / 1000000.) * 100. /
      (client_result->cpu.tv_sec * 1000. + client_result->cpu.tv_nsec / 1000000.),
      client_result->handshake_read,
      client_result->handshake_write,
      data_write_len + ((client_result->enc_data_len - client_result->data_len) / (client_result->data_writes == 0 ? 1 : client_result->data_writes)),
      data_write_len,
      ((client_result->enc_data_len - client_result->data_len) / (client_result->data_writes == 0 ? 1 : client_result->data_writes))
  );
}
