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
#include <apr_want.h>
#include <ap_config.h>
#include <apr_strings.h>
#include <httpd.h>
#include <http_core.h>
#include <http_request.h>
#include <http_log.h>
#include <openssl/rand.h>
#include <jwt.h>

#include "mod_authnz_fido2.h"

static apr_time_t jwtkey_lastrot = 0;
static unsigned jwtkey_curr = 0;
static uint8_t *jwtkey;

void jwtkey_init(uint8_t *mem)
{
	jwtkey = mem;
	jwtkey_curr = 0;
	RAND_bytes(jwtkey, JWTKEY_LEN);
	jwtkey_lastrot = apr_time_sec(apr_time_now());
}

static uint8_t *jwtkey_maybe_rotate(request_rec *req, fido2_config_t *conf)
{
	apr_time_t now = apr_time_sec(apr_time_now());

	if (now - jwtkey_lastrot > conf->jwtkey_lifetime*60) {
		jwtkey_curr = (jwtkey_curr + 1) % JWTKEY_NUM;
		jwtkey_lastrot = now;
		RAND_bytes(jwtkey+jwtkey_curr*JWTKEY_LEN, JWTKEY_LEN);
		debug("rotated JWT signing key, now #%u is current", jwtkey_curr);
	}
	return jwtkey + jwtkey_curr*JWTKEY_LEN;
}


char *create_token(request_rec *req, fido2_config_t *conf, fido2_user_t *uent)
{
	const char *rpid = get_rpid(req, conf);
	apr_time_t now = apr_time_sec(apr_time_now());
	uint8_t *jk;
	jwt_t *jwt;
	char *path, *str;
	
 	if (jwt_new(&jwt)) {
		error("creating token: %s", strerror(errno));
		return NULL;
	}
	jk = jwtkey_maybe_rotate(req, conf);
	if (jwt_set_alg(jwt, JWT_ALG_HS256, jk, JWTKEY_LEN)) {
		error("token_set_alg failed");
		return NULL;
	}
	jwt_add_grant(jwt, "iss", rpid);
	jwt_add_grant(jwt, "aud", rpid);
	jwt_add_grant(jwt, "user", uent->name);
	jwt_add_grant_int(jwt, "iat", now);
	jwt_add_grant_int(jwt, "exp", now + conf->token_validity);

	/* Some browsers store cookies twice if the path is just a little bit
	 * different, e.g. by trailing '/' */
	path = apr_pstrdup(req->pool, req->uri);
	remove_slashes(path);
	
	str = apr_psprintf(req->pool, "%s;Path=%s;SameSite=Strict%s",
					   jwt_encode_str(jwt),
					   path,
					   streq(req->hostname, "localhost") ? "" : ";Secure");
	debug("return token=%s val=%s", jwt_dump_str(jwt,0), jwt_encode_str(jwt));
	jwt_free(jwt);

	return str;
}

void set_auth_error(request_rec *req, fido2_config_t *conf,
					const char *err, const char *text)
{
	const char *cookie_name = conf->cookie_name ?: "modfido2session";
	char *cookie = apr_psprintf
				   (req->pool, "%s=;%s;SameSite=Strict",
					cookie_name,
					streq(req->hostname, "localhost") ? "" : "Secure;");

	error("check_token failed: %s: %s", err, text);
	/* clear the cookie to allow re-authentication */
	// XXX: this automatically sets the cookie path; I'd rather use the
	// AuthName, is that possible??
	apr_table_setn(req->err_headers_out, "Set-Cookie", cookie);
	// XXX: must do something different for error now Bearer isn't used anymore
	apr_table_setn(req->err_headers_out, "WWW-Authenticate",
				   apr_pstrcat(req->pool,
							   "Bearer realm=\"", ap_auth_name(req),"\", "
							   "error=\", err, \", "
							   "error_description=\"", text, "\"", NULL));
}

int check_token(request_rec *req, fido2_config_t *conf,
				const char *tokstr, char **user)
{
	jwt_t *jwt;
	const char *rpid = get_rpid(req, conf);
	const char *p;
	apr_time_t now = apr_time_sec(apr_time_now());
	long expire;
	unsigned i, j;

	//debug("jwt token str = %s", tokstr);

	/* Check if any of our keys can decode the token (so we still accept
	 * previous tokens from before rotation), but start with the current one
	 * (most likely) and then go backwards.  */
	for(i = 0; i < JWTKEY_NUM ; ++i) {
		j = (jwtkey_curr+JWTKEY_NUM-i) % JWTKEY_NUM;
		if (!jwt_decode(&jwt, tokstr, jwtkey+j*JWTKEY_LEN, JWTKEY_LEN)) {
			debug("jwtkey #%u decoded correctly", j);
			break;
		}
	}
	if (i >= JWTKEY_NUM) {
		set_auth_error(req, conf, "invalid_token",
					   "token is malformed or signature invalid");
		return HTTP_UNAUTHORIZED;
	}
	if (jwt_get_alg(jwt) != JWT_ALG_HS256) {
		set_auth_error(req, conf, "invalid_token", "bad signature algorithm");
		return HTTP_UNAUTHORIZED;
	}
	if (!(p = jwt_get_grant(jwt, "iss")) || !streq(p, rpid)) {
		set_auth_error(req, conf, "invalid_token", "token issuer invalid");
		return HTTP_UNAUTHORIZED;
	}
	if (!(p = jwt_get_grant(jwt, "aud")) || !streq(p, rpid)) {
		set_auth_error(req, conf, "invalid_token", "token audience invalid");
		return HTTP_UNAUTHORIZED;
	}
	
	expire = jwt_get_grant_int(jwt, "exp");
	if (expire <= 0) {
		set_auth_error(req, conf, "invalid_token", "token expiration missing");
		return HTTP_UNAUTHORIZED;
	}
	if (expire < now) {
		set_auth_error(req, conf, "invalid_token", "token expired");
		return HTTP_UNAUTHORIZED;
	}
	
	*user = apr_pstrdup(req->pool, jwt_get_grant(jwt, "user"));
	debug("check_token: ok, user=%s", *user);
	return OK;
}

