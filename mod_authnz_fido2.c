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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <jansson.h>

#include "mod_authnz_fido2.h"


#define NAME		"mod_authn_fido2"
#define VERSION 	"0.1"

typedef struct {
	uint8_t *sessiondata;
	size_t  sessiondata_len;
	char *credid;
	uint8_t *authdata;
	size_t  authdata_len;
	uint8_t *signature;
	size_t  signature_len;
	uint8_t *cdata;
	size_t  cdata_len;
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

uint8_t *jwtkey;
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
	function enc(arr) {\n\
		return btoa(String.fromCharCode.apply\n\
					(null, new Uint8Array(arr)));\n\
	}\n\
	function dec(str) {\n\
		return Uint8Array.from(Array.prototype.map.call(atob(str),\n\
			   function(x) { return x.charCodeAt(0); }));\n\
	}\n\
    navigator.credentials.get(%s)\n\
    .then((ar) => {\n\
      return fetch('%s', {\n\
        method: 'POST',\n\
        headers: {'Content-Type': 'application/json'},\n\
        body: '{ '+\n\
		  '\"sessiondata\":\"%s\",'+\n\
		  '\"credentialId\":\"'+enc(ar.rawId)+'\", '+\n\
		  '\"authenticatorData\":\"\'+enc(ar.response.authenticatorData)+'\", '+\n\
		  '\"clientDataJSON\":\"'+enc(ar.response.clientDataJSON)+'\", '+\n\
		  '\"signature\":\"'+enc(ar.response.signature)+'\" }'\n\
      })})\n\
    .then((res) => {\n\
	  if (res.ok) { return res.text(); }\n\
	  else { alert('Authentication failed.'); throw 'failed'; }\n\
    }, (reason) => {\n\
      alert(reason); throw 'failed';\n\
    })\n\
    .then((token) => {\n\
      document.cookie='%s='+token;\n\
      window.location.reload();\n\
    }, (reason) => {});\n\
  </script>\n\
</body></html>\n\
";
	

/* ---------------------------------------------------------------------- */


static int send_webauthn_code(request_rec *req, fido2_config_t *conf)
{
	uint8_t challenge[CHALLENGE_LEN];
	uint8_t hash[CHMACSTAMP_LEN+SHA256_LEN];
	time_t  stamp;
	char sessiondata_str[SHA256_LEN*2];
	char challenge_str[CHALLENGE_LEN*2];
	char allowed_ids[1024] = "";
	const char *cookie_name = conf->cookie_name ?: "modfido2session";

	/* A simple HMAC with a short key (128b currently) and a timestamp
	 * should be enough to avoid challenge trickeries.
	 * The layout for hashing and sessiondata is:
	 *
	 *    chall (32B)  time (4B)  hmackey (16B)
	 *    |            |       |              |
	 *    +------------------------hashed-----+ => hash (32B)
	 *                 |       |                   |        |
	 *                 +-------+  =>  base64  <=   +--------+
	 *                             sessiondata
	 */
	RAND_bytes(challenge, CHALLENGE_LEN);
	time(&stamp);
	memcpy(hash, &stamp, CHMACSTAMP_LEN);
	sha256_3buf(challenge, CHALLENGE_LEN,
				(uint8_t*)&stamp, CHMACSTAMP_LEN,
				chmackey, CHMACKEY_LEN,
				hash+CHMACSTAMP_LEN);
	apr_base64_encode(sessiondata_str, hash, CHMACSTAMP_LEN+SHA256_LEN);
	apr_base64_encode(challenge_str, challenge, CHALLENGE_LEN);
	memset(challenge, 0, sizeof(challenge));

	if (conf->offer_all_users) {
		char *idstr = allowed_ids;
		size_t idlen = sizeof(allowed_ids), l;
		int first = 1;

		int add_credid(const fido2_user_t *u) {
			l = snprintf(idstr, idlen, "%s{'type':'public-key','id':dec('%s')}",
						 first ? "" : ", ", u->credid);
			idstr += l; idlen -= l;
			first = 0;
			return 0;
		}

		l = snprintf(idstr, idlen, ", 'allowCredentials':[");
		idstr += l; idlen -= l;
		for_all_users(req, conf, add_credid);
		l = snprintf(idstr, idlen, "]");
		idstr += l; idlen -= l;
	}

	char *obj_str = apr_psprintf(
		req->pool,
		"{ 'publicKey': { "
		"'rpId': '%s', "
		"'userVerification': '%s', "
		"'timeout': %d, "
		"'challenge': dec('%s')"
		"%s"
		"} }",
		get_rpid(req, conf),
		conf->require_UV ? "required" : "discouraged",
		conf->auth_timeout * 1000,
		challenge_str,
		allowed_ids
		);

	req->user = "nobody";
	ap_set_content_type(req, "text/html; charset=US-ASCII");
	apr_table_setn(req->headers_out, "Cache-Control", "no-cache");
	ap_rprintf(req, login_html, obj_str, req->uri, sessiondata_str, cookie_name);

	memset(sessiondata_str, 0, sizeof(sessiondata_str));
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
	get_base64_attr(top, "sessiondata", resp->sessiondata);
	get_str_attr(top, "credentialId", resp->credid);
	get_base64_attr(top, "authenticatorData", resp->authdata);
	get_base64_attr(top, "signature", resp->signature);

	get_base64_attr(top, "clientDataJSON", resp->cdata);
	jcdata = json_loadb(resp->cdata, resp->cdata_len,
						JSON_DISABLE_EOF_CHECK, &jerr);
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
	out->counter = in->counter[3] |
				   (in->counter[2]<<8) |
				   (in->counter[1]<<16) |
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
	uint8_t hash[SHA256_LEN];
	apr_time_t now = apr_time_sec(apr_time_now());
	time_t stamp;
	
	if (!ctype || strcmp(ctype, "application/json") != 0) {
		error("content-type must be application/json");
		return HTTP_UNSUPPORTED_MEDIA_TYPE;
	}

	postdata = apr_get_postdata(req, &postlen);
	if ((errstr = parse_assertation(req, postdata, postlen, &ar))) {
		debug("parse error in posted assertation data: %s", errstr);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* NB: The WebAuthn standard says in 7.2.1 "If the allowCredentials option
	 * was given, verify that credential.id identifies one of those that were
	 * listed in allowCredentials." This is deliberately not implemented here,
	 * as we either give no credentials in that list, or all of them; so this
	 * check is pointless. */

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

	/* check challenge HMAC */
	if (ar.cd_challenge_len != CHALLENGE_LEN) {
		error("bad challenge size in response");
		return HTTP_BAD_REQUEST;
	}
	if (ar.sessiondata_len != CHMACSTAMP_LEN+SHA256_LEN) {
		error("bad sessiondata size in response");
		return HTTP_BAD_REQUEST;
	}
	sha256_3buf(ar.cd_challenge, CHALLENGE_LEN,
				ar.sessiondata, CHMACSTAMP_LEN,
				chmackey, CHMACKEY_LEN, hash);
	if (memcmp(ar.sessiondata+CHMACSTAMP_LEN, hash, SHA256_LEN) != 0) {
		error("challenge HMAC failure in reply");
		return HTTP_BAD_REQUEST;
	}
	memcpy(&stamp, ar.sessiondata, CHMACSTAMP_LEN); // copy for alignment
	/* The timestamp in sessiondata (= when challenge has been generated)
	 * must be not older then the authentication timeout plus a generous 15s
	 * for network delays. It also must not be in future.
	 */
	//debug("sessiondata tstamp=%ld age=%ld", stamp, now-stamp);
	if (stamp > now || stamp < now - conf->auth_timeout - 15) {
		error("challenge in reply outside allowed time range");
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

	fido2_user_t *uent;
	if (!(uent = getuser_bycredid(req, conf, ar.credid))) {
		error("unknown credential ID %s", ar.credid);
		return HTTP_BAD_REQUEST;
	}
	//debug("credID=%s -> user %s", ar.credid, uent->name);
	
	/* hash authdata || clientdata */
	sha256(ar.cdata, ar.cdata_len, hash);
	uint8_t catbuf[ar.authdata_len+SHA256_LEN];
	memcpy(catbuf, ar.authdata, ar.authdata_len);
	memcpy(catbuf+ar.authdata_len, hash, SHA256_LEN);
	sha256(catbuf, sizeof(catbuf), hash);

	unsigned pkey_len = apr_base64_decode_len(uent->pubkey);
	uint8_t pkey_data[pkey_len];
	const uint8_t *pkey = pkey_data;
	pkey_len = apr_base64_decode(pkey_data, uent->pubkey);

	int verified = 0;
	unsigned long e;
	if (streq(uent->ktype, "es256")) {
		EC_KEY *ec = d2i_EC_PUBKEY(NULL, &pkey, pkey_len);
		if (!ec) {
			error("failed to parse EC pubkey");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		verified = ECDSA_verify(0, hash, SHA256_LEN,
								ar.signature, ar.signature_len, ec);
		e = ERR_get_error();
		EC_KEY_free(ec);
	}
	else if (streq(uent->ktype, "rs256")) {
		RSA *rk = d2i_RSA_PUBKEY(NULL, &pkey, pkey_len);
		if (!rk) {
			error("failed to parse RSA pubkey");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		verified = RSA_verify(NID_sha256, hash, SHA256_LEN,
							  ar.signature, ar.signature_len, rk);
		e = ERR_get_error();
		RSA_free(rk);
	}
	else {
		error("unsupported key type '%s'", uent->ktype);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	debug("signature verified=%d", verified);

	if (!verified) {
		char ebuf[1024];
		ERR_error_string_n(e, ebuf, sizeof(ebuf));
		debug("OpenSSL error %lu: %s", e, ebuf);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char *token_str;
	if (!(token_str = create_token(req, conf, uent)))
		return HTTP_INTERNAL_SERVER_ERROR;
	ap_set_content_type(req, "application/json");
	ap_rwrite(token_str, strlen(token_str), req);

	req->user = (char*)uent->name;
	return DONE;
}

static int fido2_handler(request_rec *req)
{
	fido2_config_t *conf =
		ap_get_module_config(req->per_dir_config, &authnz_fido2_module);
	const char *cookie_name = conf->cookie_name ?: "modfido2session";
    const char *auth_type = ap_auth_type(req);
    const char *auth_name = ap_auth_name(req);
	char *session;

	debug("called, auth_type='%s'", auth_type);
	if (!auth_type || strcasecmp(auth_type, "fido2") != 0)
		return DECLINED;
	// XXX still needed?
	if (!auth_name) {
		error("no AuthName defined");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	/* Check for session cookie with access token */
	session = parse_cookie(req, cookie_name);
	if (session && *session) {
		char *user;
		int rv;

		/* check JWT */
		if ((rv = check_token(req, conf, session, &user)) == OK)
			req->user = user;
		return rv;
	}
	else {
		/* If there's no Authorization: header, redirect GET to login page
		 * and process reply in POST handler
		 */
		if (strcmp(req->method, "GET") == 0) {
			debug("no session, GET, reply with login HTML");
			return send_webauthn_code(req, conf);
		}
		else if (strcmp(req->method, "POST") == 0) {
			debug("no session, POST, process auth data");
			return process_webauthn_reply(req, conf);
		}
		else {
			debug("other method: %s", req->method);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
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
