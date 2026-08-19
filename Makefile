CFLAGS=-g -Werror -Wall -std=c99 -D_POSIX_C_SOURCE=200112L
LDFLAGS=
EXEC=server-vs-client.exe brute-shake.exe
# OpenSSL 3.x refuses to generate a DSA key from 768-bit parameters
# (FIPS 186-4 wants L in {1024, 2048, 3072}), so 768-dsa.pem is out.
CERTS = 256-ecc.pem \
        1024-dh.pem 2048-dh.pem \
        768-rsa.pem 1024-rsa.pem 2048-rsa.pem 4096-rsa.pem \
	1024-dsa.pem 2048-dsa.pem # 768-dsa.pem 4096-dsa.pem

all: $(EXEC) certificates

# Tools
server-vs-client.exe: server-vs-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssl -lcrypto -lpthread -lrt
brute-shake.exe: brute-shake.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lcrypto -lpthread

# Certificates
cert_size = $(word 1,$(subst -, ,$@))
cert_type = $(word 2,$(subst -, ,$@))
certificates: $(CERTS)
%.pem: %-key.pem %-cert.pem %-dh.pem
	cat $^ > $@
%-key.pem:
	@case "$(cert_type)" in \
	  ecc) openssl ecparam -name prime256v1 -genkey -noout -out $@ ;; \
	  dsa) openssl dsaparam -out $@.params $(cert_size) && \
	       openssl gendsa -out $@ $@.params && rm -f $@.params ;; \
	  *)   openssl genrsa -out $@ $(cert_size) ;; \
	esac
%-cert.pem: %-key.pem
	openssl req -new -x509 -sha256 -days 700 -config openssl.cnf \
		-key $< -out $@
# Key exchange parameters. There is no 256-bit DH group (and no need for one
# next to an EC key), so the ecc bundle carries EC parameters instead.
%-dh.pem:
	@case "$(cert_type)" in \
	  ecc) openssl ecparam -name prime256v1 -out $@ ;; \
	  *)   openssl dhparam -out $@ $(cert_size) ;; \
	esac

clean:
	rm -f *.pem *.o $(EXEC)

.PHONY: clean certificates all
