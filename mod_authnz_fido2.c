/* mod_authn_fido2
 * Apache module for authentication with FIDO2 (WebAuthn)
 *
 * Roman Hodek <roman@hodek.net>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <apr_strings.h>
#define APR_WANT_STRFUNC
#include <apr_want.h>
#include <ap_config.h>
#include <ap_provider.h>
#include <apr_base64.h>
#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <mod_auth.h>
#include <mod_ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <jansson.h>
#include <jwt.h>

#include "mod_authnz_fido2.h"


#define NAME		"mod_authn_fido2"
#define VERSION 	"0.1"

typedef struct {
	char *credid;
	uint8_t *authdata;
	size_t  authdata_len;
	uint8_t *signature;
	size_t  signature_len;
	/* substructure 'clientData' */
	uint8_t *cd_challenge;
	size_t  cd_challenge_len;
	const char *cd_origin;
	const char *cd_type;
} assert_resp_t;

typedef struct {
	uint8_t rp_id_hash[32];
	uint8_t flags;
	uint8_t counter[4];
} raw_authenticator_data_t;

typedef struct {
	uint8_t rp_id_hash[SHA256_LEN];
	unsigned flags;
	unsigned counter;
} authenticator_data_t;

#define JWTKEY_LEN 32
#define CHMACKEY_LEN 16
static uint8_t *jwtkey;
static uint8_t *chmackey;

module AP_MODULE_DECLARE_DATA authnz_fido2_module;

static const char *login_html = "\
<html>\n\
<head>\n\
  <title>mod_authn_fido2 login</title>\n\
</head>\n\
<body>\n\
  <h3>Apache mod_authn_fido2 Login</h3>\n\
  <p>This requires a browser supporting the WebAuthn API</p>\n\
  <p>Trigger your authenticator device now...</p>\n\
  <script>\n\
	function encode(arr) {\n\
		return btoa(String.fromCharCode.apply\n\
					(null, new Uint8Array(arr)));\n\
	}\n\
    navigator.credentials.get(%s)\n\
    .then((asrt) => {\n\
      return fetch('%s', {\n\
        method: 'POST',\n\
        headers: {'Content-Type': 'application/json'},\n\
        body: '{ '+\n\
		  '\"credentialId\":\"'+encode(asrt.rawId)+'\", '+\n\
		  '\"authenticatorData\":\"\'+encode(asrt.response.authenticatorData)+'\", '+\n\
		  '\"clientDataJSON\":\"'+encode(asrt.response.clientDataJSON)+'\", '+\n\
		  '\"signature\":\"'+encode(asrt.response.signature)+'\" }'\n\
      })})\n\
    .then(function(response) {\n\
      var stat = response.ok ? 'successful' : 'unsuccessful';\n\
      alert('Authentication ' + stat + ' More details in server log...');\n\
    }, function(reason) {\n\
console.log('error handler: '+reason);\n\
      alert(reason);\n\
    });\n\
  </script>\n\
</body></html>\n\
";
	

/* ---------------------------------------------------------------------- */


static int send_webauthn_code(request_rec *req, fido2_config_t *conf)
{
	uint8_t challenge[CHALLENGE_LEN+CHMACKEY_LEN];
	uint8_t cookie_bin[CHALLENGE_LEN+SHA256_LEN];
	uint8_t cookie_val[(CHALLENGE_LEN+SHA256_LEN)*2];
	char challenge_str[CHALLENGE_LEN*4+1], *cp, *cookie;
	unsigned i;

	// XXX: use username-less flag for rp_id vs. allowCredentials

	/* a simple HMAC with a short key (128b currently) should be enough to
	 * avoid challenge trickeries */
	RAND_bytes(challenge, CHALLENGE_LEN);
	memcpy(cookie_bin, challenge, CHALLENGE_LEN);
	memcpy(challenge+CHALLENGE_LEN, chmackey, CHMACKEY_LEN);
	sha256(challenge, CHALLENGE_LEN+CHMACKEY_LEN, cookie_bin+CHALLENGE_LEN);
	memset(challenge+CHALLENGE_LEN, 0, CHMACKEY_LEN);

	apr_base64_encode(cookie_val, cookie_bin, CHALLENGE_LEN+SHA256_LEN);
	cookie = apr_psprintf(req->pool, "fido2session=%s;%s"
						  "HttpOnly;SameSite=Strict",
						  cookie_val,
						  streq(req->hostname, "localhost") ? "" : "Secure;");
	apr_table_setn(req->headers_out, "Set-Cookie", cookie);
	
	cp = challenge_str;
	for(i = 0; i < CHALLENGE_LEN; ++i)
		cp += sprintf(cp, "%s%u", i?",":"", challenge[i]);
	memset(challenge, 0, sizeof(challenge));
	memset(cookie_bin, 0, sizeof(cookie_bin));
	memset(cookie_val, 0, sizeof(cookie_val));

	// XXX: if allowCredentials is not present, I always get an
	// InvalidStateError from credentials.get :-(
	char *obj_str = apr_psprintf(
		req->pool,
		"{ \"publicKey\": { "
		"\"rpId\": \"%s\", "
		"\"userVerification\": \"%s\", "
		"\"timeout\": %d, "
		"\"challenge\": new Uint8Array([%s])"
		"%s%s"
		"} }",
		conf->rpid_str ?: "",
		conf->require_UV ? "required" : "discouraged",
		(conf->timeout >= 0 ?: 30) * 1000,
		challenge_str,
		conf->offer_all_users ? ", \"allowCredentials\": [ ]" : "", ""
		);
	
	req->user = "nobody";
	ap_set_content_type(req, "text/html; charset=US-ASCII");
	ap_rprintf(req, login_html, obj_str, req->uri);

	memset(challenge_str, 0, sizeof(challenge_str));
	return DONE;
}

static char *apr_get_postdata(request_rec *req, apr_size_t *len)
{
	char *data = NULL;

	*len = 0;
	ap_setup_client_block(req, REQUEST_CHUNKED_ERROR);
	
	if (ap_should_client_block(req) == 1) {
		apr_off_t n, pos = 0;
		char buf[1024];

		*len = req->remaining;
		data = apr_pcalloc(req->pool, *len);
		while((n = ap_get_client_block(req, buf, sizeof(buf))) > 0) {
			if (pos+n > *len)
				n = *len-pos;
			memcpy(data+pos, buf, n);
			pos += n;				   
		}
	}
	debug("rcv POST data: %s", data);
	return data;
}

static const char *parse_assertation(request_rec *req, uint8_t *buf, size_t len, assert_resp_t *resp)
{
	json_error_t jerr;
	json_t *top = json_loadb(buf, len, 0, &jerr), *jcdata, *node;
	uint8_t *cdata;
	size_t cdata_len;

#define get_str_common(obj,name)							\
		const char *__val;									\
		if (!(node = json_object_get(obj, name)))			\
			return "assertation."name" not found";			\
		if (!json_is_string(node))							\
			return "assertation."name" is not a string";	\
		__val = json_string_value(node);
#define get_dec_base64(val,field)							\
		field##_len = apr_base64_decode_len(val);			\
		if (!(field = apr_pcalloc(req->pool, field##_len)))	\
			return "out of memory";							\
		field##_len = apr_base64_decode(field, val);

#define get_str_attr(obj,name,field)			\
	do {										\
		get_str_common(obj,name);				\
		field = apr_pstrdup(req->pool, __val);	\
	} while(0)
#define get_base64_attr(obj,name,field)			\
	do {										\
		get_str_common(obj,name);				\
		get_dec_base64(__val,field);			\
	} while(0)
#define get_base64url_attr(obj,name,field)		\
	do {										\
		get_str_common(obj,name);				\
		char *__str = alloca(strlen(__val)+1);	\
		strcpy(__str, __val);					\
		base64url2normal(__str);				\
		get_dec_base64(__str,field);			\
	} while(0)

	if (!top || !json_is_object(top))
		return apr_pstrdup(req->pool, jerr.text);
	get_str_attr(top, "credentialId", resp->credid);
	get_base64_attr(top, "authenticatorData", resp->authdata);
	get_base64_attr(top, "signature", resp->signature);

	get_base64_attr(top, "clientDataJSON", cdata);
	jcdata = json_loadb(cdata, cdata_len, JSON_DISABLE_EOF_CHECK, &jerr);
	if (!jcdata || !json_is_object(jcdata))
		return apr_pstrdup(req->pool, jerr.text);

	get_base64url_attr(jcdata, "challenge", resp->cd_challenge);
	get_str_attr(jcdata, "origin", resp->cd_origin);
	get_str_attr(jcdata, "type", resp->cd_type);

	return NULL;
}

static void decode_authenticator_data(authenticator_data_t *out,
									  raw_authenticator_data_t *in)
{
	memcpy(out->rp_id_hash, in->rp_id_hash, sizeof(out->rp_id_hash));
	out->flags = in->flags;
	out->counter = in->counter[3] ||
				   (in->counter[2]<<8) ||
				   (in->counter[1]<<16) ||
				   (in->counter[0]<<24);
}

static int process_webauthn_reply(request_rec *req, fido2_config_t *conf)
{
	const char *ctype = apr_table_get(req->headers_in, "Content-Type");
	const char *p;
	char *postdata;
	apr_off_t postlen;
	assert_resp_t ar;
	const char *errstr;

	uint8_t *sv;
	unsigned svlen;
	uint8_t hmac[CHALLENGE_LEN+CHMACKEY_LEN], hash[SHA256_LEN];
	uint8_t sess_chall[CHALLENGE_LEN];
	
	const char *cookie = apr_table_get(req->headers_in, "Cookie");
	if (!cookie || !(sv = parse_cookieval(cookie, &svlen)) ||
		svlen != CHALLENGE_LEN+SHA256_LEN) {
		error("missing session");
		return HTTP_BAD_REQUEST;
	}
	memcpy(hmac, sv, CHALLENGE_LEN);
	memcpy(hmac+CHALLENGE_LEN, chmackey, CHMACKEY_LEN);
	sha256(hmac, CHALLENGE_LEN+CHMACKEY_LEN, hash);
	memset(hmac, 0, sizeof(hmac));
	if (memcmp(sv+CHALLENGE_LEN, hash, SHA256_LEN) != 0) {
		free(sv);
		error("bad session contents");
		return HTTP_BAD_REQUEST;
	}
	memcpy(sess_chall, sv, CHALLENGE_LEN);
	free(sv);
	if (!ctype || strcmp(ctype, "application/json") != 0) {
		error("content-type must be application/json");
		return HTTP_UNSUPPORTED_MEDIA_TYPE;
	}

	postdata = apr_get_postdata(req, &postlen);
	if ((errstr = parse_assertation(req, postdata, postlen, &ar))) {
		debug("parse error in posted assertation data: %s", errstr);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* XXX: check if credential.id is one of the allowCredentials, if that
	 * has been given */
	/* XXX: maybe some fido_assert_* functions can be used to make some of
	 * the checks below */
	
	if (strcmp(ar.cd_type, "webauthn.get") != 0) {
		error("parse error in posted assertation data: %s", errstr);
		return HTTP_BAD_REQUEST;
	}
	/* check correct origin (should be https:// + our name or localhost, where
	 * also http is allowed) */
	if (!(streq(ar.cd_origin, "http://localhost") ||
		  strprefix(ar.cd_origin, "http://localhost:") ||
		  ((p = strprefix(ar.cd_origin, "https://")) &&
		   streq(p, req->hostname)))) {
		warn("wrong origin (%s vs. expected %s)",
			 ar.cd_origin+strlen("https://"), req->hostname);
		return HTTP_BAD_REQUEST;
	}
	/* check challenge is the same */
	if (ar.cd_challenge_len != CHALLENGE_LEN ||
		memcmp(sess_chall, ar.cd_challenge, CHALLENGE_LEN) != 0) {
		error("challenge in reply is different from state");
		return HTTP_BAD_REQUEST;
	}

	authenticator_data_t authdata;
	if (ar.authdata_len != sizeof(raw_authenticator_data_t)) {
		warn("bad authenticator_data length (%ld vs. expected %ld",
			 ar.authdata_len, sizeof(raw_authenticator_data_t));
		return HTTP_BAD_REQUEST;
	}
	decode_authenticator_data(&authdata,
							  (raw_authenticator_data_t*)ar.authdata);
	/* check that rp_id hash is correct */
	if (memcmp(authdata.rp_id_hash, conf->rpid_hash, SHA256_LEN) != 0) {
		error("RP-ID hash mismatch");
		return HTTP_BAD_REQUEST;
	}
	/* check for user present bit, and user verified if requested by conf */
	if (!(authdata.flags & ADF_UP)) {
		warn("user present flag missing");
		return HTTP_BAD_REQUEST;
	}
	if (conf->require_UV && !(authdata.flags & ADF_UV)) {
		error("user not verified");
		return HTTP_BAD_REQUEST;
	}

	debug("credID from client = %s", ar.credid);
	fido2_user_t *uent;
	if (!(uent = getuser_bycredid(req, conf, ar.credid))) {
		error("known credential ID %s", ar.credid);
		return HTTP_BAD_REQUEST;
	}

	/* XXX: actually verify the signature! */
	
	/* after the checks: generate a JWT ticket */
	jwt_t *jwt;
	apr_time_t now = apr_time_sec(apr_time_now());
	
 	if (jwt_new(&jwt)) {
		error("creating token: %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	/* XXX: key rotation */
	if (jwt_set_alg(jwt, JWT_ALG_HS256, jwtkey, JWTKEY_LEN)) {
		error("token_set_alg failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	jwt_add_grant(jwt, "aud", conf->rpid_str);
	jwt_add_grant(jwt, "user", uent->name);
	jwt_add_grant_int(jwt, "iat", now);
	jwt_add_grant_int(jwt, "exp", now + conf->token_validity);

	req->user = (char*)uent->name;
	ap_set_content_type(req, "application/json");
	ap_rprintf(req, "{\"token\":\"%s\"}", jwt_encode_str(jwt));
	jwt_free(jwt);

	return OK;
}

static int fido2_handler(request_rec *req)
{
	fido2_config_t *conf =
		ap_get_module_config(req->per_dir_config, &authnz_fido2_module);
    const char *auth_type = ap_auth_type(req);
	char *auth_line;

	debug("called, auth_type='%s'", auth_type);
    if (!auth_type || strcasecmp(auth_type, "fido2") != 0)
        return DECLINED;
	
	/* Check the HTTP header */
	auth_line = (char*)apr_table_get(
		req->headers_in,
		(req->proxyreq == PROXYREQ_PROXY) ?
		  "Proxy-Authorization" : "Authorization");
   if (!auth_line) {
	   /* If there's no Authorization: header, redirect this to the login
		* page */
	   debug("no Authorization: header");

	   if (strcmp(req->method, "GET") == 0) {
		   debug("GET, reply with login HTML");
		   return send_webauthn_code(req, conf);
	   }
	   else if (strcmp(req->method, "POST") == 0) {
		   return process_webauthn_reply(req, conf);
	   }
	   else {
		   debug("other method: %s", req->method);
		   return HTTP_INTERNAL_SERVER_ERROR;
	   }
   }
   else {
	   /* check JWT */
	   debug("auth_line='%s'", auth_line);

	   /* XXX: check the token */
   }
   
    return DECLINED;
}

/* ---------------------------------------------------------------------- */
/* registration															  */

static int init_mod_fido2(apr_pool_t *pconf, apr_pool_t *plog,
						  apr_pool_t *ptemp, server_rec *s)
{
	request_rec *req = (request_rec*)s; // just for error/warn macros
	
    ap_add_version_component(pconf, NAME "/" VERSION);

	/* Use OpenSSL secure heap for our keys -- protect them as good as
	 * possible. */
	if (!CRYPTO_secure_malloc_initialized()) {
		switch(CRYPTO_secure_malloc_init(8*1024, 16)) {
		  case 0:
			error("secure_malloc_init failed");
			return HTTP_INTERNAL_SERVER_ERROR;
		  case 2:
			warn("(no OpenSSL secured memory available)");
			break;
		}
	}
	if (!(jwtkey = OPENSSL_secure_malloc(JWTKEY_LEN)) ||
		!(chmackey = OPENSSL_secure_malloc(CHMACKEY_LEN))) {
		error("secure_malloc failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	RAND_bytes(jwtkey, JWTKEY_LEN);
	RAND_bytes(chmackey, CHMACKEY_LEN);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authn(fido2_handler, NULL, NULL,
						APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_URI);
	ap_hook_post_config(init_mod_fido2, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authnz_fido2) = {
	STANDARD20_MODULE_STUFF,
	create_authnz_fido2_config,
	merge_authnz_fido2_config,
	NULL, /* create per-server config structure */
	NULL, /* merge per-server config structure */
	authnz_fido2_cmds,
	register_hooks
};
