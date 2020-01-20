/* mod_authn_fido2
 * Apache module for authentication with FIDO2 (WebAuthn)
 *
 * Roman Hodek <roman@hodek.net>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <openssl/evp.h>

#include "mod_authnz_fido2.h"



static fido2_user_t *getuser_byXXX(request_rec *req, fido2_config_t *conf, const char *xxx, unsigned fno)
{
	FILE *f;
	char line[1024];
	const int NFIELDS = 3;
	fido2_user_t *usr;

	if (!(f = fopen(conf->user_file, "r")))
		return NULL;
	while(fgets(line, sizeof(line), f)) {
		char *v[NFIELDS], *p;
		unsigned i;
		unsigned cntr;

		for(p = line, i = 0; i < NFIELDS; ++i) {
			v[i] = p;
			if (!*(p += strcspn(p, ":")))
				goto next;
			*p++ = '\0';
		}			
		cntr = strtoul(p, NULL, 10);
		
		if (streq(v[fno], xxx)) {
			usr = apr_pcalloc(req->pool, sizeof(*usr));
			usr->name = apr_pstrdup(req->pool, v[0]);
			usr->credid = apr_pstrdup(req->pool, v[1]);
			usr->pubkey = apr_pstrdup(req->pool, v[2]);
			usr->counter = cntr;
			break;
		}
	  next:
		;
	}
	fclose(f);
	if (usr)
		return usr;

	errno = ESRCH;
	return NULL;
}

fido2_user_t *getuser_byname(request_rec *req, fido2_config_t *conf, const char *name)
{
	return getuser_byXXX(req, conf, name, 0);
}
fido2_user_t *getuser_bycredid(request_rec *req, fido2_config_t *conf, const char *credid)
{
	return getuser_byXXX(req, conf, credid, 1);
}

uint8_t *parse_cookieval(const char *_str, unsigned *outlen)
{
	char str[strlen(_str)+1], *save;
	const char *p;
	uint8_t *rv = NULL;
	unsigned len;

	strcpy(str, _str);
	for(p = strtok_r(str, ";", &save); p; p = strtok_r(NULL, ";", &save)) {
		p += strspn(p, " ");
		if ((p = strprefix(p, "fido2session="))) {
			*outlen = apr_base64_decode_len(p);
			rv = malloc(*outlen);
			*outlen = apr_base64_decode(rv, p);
			break;
		}
	}
	return rv;
}

int sha256(const uint8_t *in, size_t inlen, uint8_t *out)
{
	EVP_MD_CTX *ctx;
	int rv = -1;
	unsigned reallen;

	if (!(ctx = EVP_MD_CTX_create()))
		return -1;

	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto out;
	if (!EVP_DigestUpdate(ctx, in, inlen))
		goto out;
	if (!EVP_DigestFinal_ex(ctx, out, &reallen))
		goto out;
	rv = 0;
	
  out:
	EVP_MD_CTX_destroy(ctx);
	return rv;
}

int sha256_str(const char *str, uint8_t *out)
{
	return sha256(str, strlen(str), out);
}

void log_bytearray(request_rec *req, const char *prefix, uint8_t *data, size_t len)
{
	char buf[16*3+1+1], *p;
	unsigned i;

	for(i = 0; i < len; ++i) {
		if ((i % 16) == 0)
			*(p = buf) = '\0';
		p += sprintf(p, "%02x ", data[i]);
		if ((i % 16) == 7)
			strcpy(p++, " ");
		if ((i % 16) == 15)
			debug("%s %04x: %s", prefix, i&~0xf, buf);
						  
	}
	if (len % 16)
		debug("%s: %04x: %s", prefix, i&~0xf, buf);
}

