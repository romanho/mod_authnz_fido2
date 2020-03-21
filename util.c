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
#include <fido.h>
#include <fido/es256.h>
#include <fido/rs256.h>
#include <fido/eddsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include "mod_authnz_fido2.h"



static fido2_user_t *getuser_byXXX(request_rec *req, fido2_config_t *conf,
								   const char *xxx, unsigned fno,
								   int (*callback)(const fido2_user_t *u))
{
	FILE *f;
	char line[1024];
	const int NFIELDS = 4;
	fido2_user_t *usr = NULL;

	if (!(f = fopen(conf->user_file, "r")))
		return NULL;
	while(fgets(line, sizeof(line), f)) {
		char *v[NFIELDS], *p;
		unsigned i;
		unsigned cntr;

		if (line[0] == '\n' || line[0] == '#')
			continue;

		for(p = line, i = 0; i < NFIELDS; ++i) {
			v[i] = p;
			if (!*(p += strcspn(p, ":")))
				goto next;
			*p++ = '\0';
		}			
		cntr = strtoul(p, NULL, 10);
		
		if (xxx && streq(v[fno], xxx)) {
			usr = apr_pcalloc(req->pool, sizeof(*usr));
			usr->name = apr_pstrdup(req->pool, v[0]);
			usr->credid = apr_pstrdup(req->pool, v[1]);
			usr->ktype  = apr_pstrdup(req->pool, v[2]);
			usr->pubkey = apr_pstrdup(req->pool, v[3]);
			usr->counter = cntr;
			break;
		}
		if (callback) {
			fido2_user_t u;
			u.name   = v[0];
			u.credid = v[1];
			u.ktype  = v[2];
			u.pubkey = v[3];
			u.counter = cntr;
			if (callback(&u))
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
	return getuser_byXXX(req, conf, name, 0, NULL);
}
fido2_user_t *getuser_bycredid(request_rec *req, fido2_config_t *conf, const char *credid)
{
	return getuser_byXXX(req, conf, credid, 1, NULL);
}

void for_all_users(request_rec *req, fido2_config_t *conf, int (*callback)(const fido2_user_t *u))
{
	getuser_byXXX(req, conf, NULL, 0, callback);
}

const char *get_rpid(request_rec *req, fido2_config_t *conf)
{
	return conf->rpid_str ?: req->hostname;
}

char *parse_cookie(request_rec *req, const char *cookiename)
{
	const char *cookie = (char*)apr_table_get(req->headers_in, "Cookie");
	char *str, *save, *rv = NULL;
	const char *p;
	
	if (!cookie)
		return NULL;

	/* need a writable copy for strtok() */
	str = alloca(strlen(cookie+1));
	strcpy(str, cookie);

	for(p = strtok_r(str, ";", &save); p; p = strtok_r(NULL, ";", &save)) {
		p += strspn(p, " ");
		if ((p = strprefix(p, cookiename)) && *p == '=') {
			rv = apr_pstrdup(req->pool, p+1);
			break;
		}
	}
	return rv;
}

void base64url2normal(char *str)
{
	char *p;
	for(p = str; *p; ++p)
		switch(*p) {
		  case '-': *p = '+'; break;
		  case '_': *p = '/'; break;
		}
}

void remove_slashes(char *str)
{
	char *p = str+strlen(str)-1;
	while(p > str && *p == '/')
		*p-- = '\0';
}

int get_ktype(const char *str)
{
	if (streq(str, "es256"))
		return COSE_ES256;
	else if (streq(str, "rs256"))
		return COSE_RS256;
	else if (streq(str, "eddsa"))
		return COSE_EDDSA;
	else
		return 0;
}

void *get_pubkey(int ktype, const char *kdata)
{
	void *ret = NULL;
	unsigned pkey_len = apr_base64_decode_len(kdata);
	uint8_t pkey_data[pkey_len];
	const uint8_t *pkey = pkey_data;
	pkey_len = apr_base64_decode(pkey_data, kdata);

	switch(ktype) {
	  case COSE_ES256: {
		EC_KEY *ec = d2i_EC_PUBKEY(NULL, &pkey, pkey_len);
		es256_pk_t *es256_pk;
		if (!ec)
			return NULL;
		if (!(es256_pk = es256_pk_new()) || es256_pk_from_EC_KEY(es256_pk, ec)) {
			EC_KEY_free(ec);
			return NULL;
		}
		ret = es256_pk;
		EC_KEY_free(ec);
		break;
	  }
	  case COSE_RS256: {
		RSA *rk = d2i_RSA_PUBKEY(NULL, &pkey, pkey_len);
		rs256_pk_t *rs256_pk;
		if (!rk)
			return NULL;
		if (!(rs256_pk = rs256_pk_new()) || rs256_pk_from_RSA(rs256_pk, rk)) {
			RSA_free(rk);
			return NULL;
		}
		ret = rs256_pk;
		RSA_free(rk);
	  }
	  case COSE_EDDSA: {
		eddsa_pk_t *eddsa_pk;
		if (!(eddsa_pk = eddsa_pk_new()) ||
			eddsa_pk_from_ptr(eddsa_pk, pkey, pkey_len))
			return NULL;
		ret = eddsa_pk;
	  }
	  default:
		return NULL;
	}
	return ret;
}

void free_pubkey(int ktype, void *pk)
{
	switch(ktype) {
	  case COSE_ES256: {
		es256_pk_t *es256_pk = pk;
		es256_pk_free(&es256_pk);
		break;
	  }
	  case COSE_RS256: {
		rs256_pk_t *rs256_pk = pk;
		rs256_pk_free(&rs256_pk);
		break;
	  }
	  case COSE_EDDSA: {
		eddsa_pk_t *eddsa_pk;
		eddsa_pk_free(&eddsa_pk);
		break;
	  }
	}
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
	if (reallen != SHA256_LEN)
		goto out;
	rv = 0;

  out:
	EVP_MD_CTX_destroy(ctx);
	return rv;
}

int sha256_2buf(const uint8_t *in1, size_t in1len, const uint8_t *in2, size_t in2len, uint8_t *out)
{
	EVP_MD_CTX *ctx;
	int rv = -1;
	unsigned reallen;

	if (!(ctx = EVP_MD_CTX_create()))
		return -1;

	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto out;
	if (!EVP_DigestUpdate(ctx, in1, in1len))
		goto out;
	if (!EVP_DigestUpdate(ctx, in2, in2len))
		goto out;
	if (!EVP_DigestFinal_ex(ctx, out, &reallen))
		goto out;
	if (reallen != SHA256_LEN)
		goto out;
	rv = 0;

  out:
	EVP_MD_CTX_destroy(ctx);
	return rv;
}

int sha256_3buf(const uint8_t *in1, size_t in1len, const uint8_t *in2, size_t in2len, const uint8_t *in3, size_t in3len, uint8_t *out)
{
	EVP_MD_CTX *ctx;
	int rv = -1;
	unsigned reallen;

	if (!(ctx = EVP_MD_CTX_create()))
		return -1;

	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto out;
	if (!EVP_DigestUpdate(ctx, in1, in1len))
		goto out;
	if (!EVP_DigestUpdate(ctx, in2, in2len))
		goto out;
	if (!EVP_DigestUpdate(ctx, in3, in3len))
		goto out;
	if (!EVP_DigestFinal_ex(ctx, out, &reallen))
		goto out;
	if (reallen != SHA256_LEN)
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
	char buf[16*3+1+1], *p = buf;
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
		debug("%s %04x: %s", prefix, i&~0xf, buf);
}
