#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include "pread.h"

int main(int argc, char **argv) {
    char *result = read_pkcs12_from_file(argv[1], "1234");
    printf(result);
}

// references : https://github.com/php/php-src/blob/master/ext/openssl/openssl.c
//              https://stackoverflow.com/questions/12406459/substring-in-c-using-pointer
char *read_pkcs12_from_file(char *path, char *password) {
    FILE *fp;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
	X509 * cert = NULL;
	STACK_OF(X509) * ca = NULL;
	BIO * bio_in = NULL;
    int i;

    if ((fp = fopen(path, "rb")) == NULL) {
        return "ERROR OPEN FILE";
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    if (p12 == NULL) {
        return "ERROR READ P12";
    }
    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
        return "ERROR PARSE P12";
    }

    BIO *bio_out;

    if(pkey) {
        bio_out = BIO_new(BIO_s_mem());
        if(PEM_write_bio_PrivateKey(bio_out, pkey, NULL, NULL, 0, 0, NULL)) {
            BUF_MEM *bio_buf;
            BIO_get_mem_ptr(bio_out, &bio_buf);
            
            char *data = malloc(bio_buf->length + 1);
            strncpy(data, bio_buf->data, bio_buf->length);
            data[bio_buf->length + 1] = '\0';
            return data;
        } else {
            return "ERROR";
        }
    }
}