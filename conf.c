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
#define APR_WANT_STRFUNC
#include <apr_want.h>
#include <ap_config.h>
#include <ap_provider.h>
#include <httpd.h>
#include <http_config.h>

#include "mod_authnz_fido2.h"


const command_rec authnz_fido2_cmds[] = {
	AP_INIT_TAKE1("AuthFIDO2RelyingPartyID", ap_set_string_slot,
				  (void *)APR_OFFSETOF(fido2_config_t, rpid_str),
				  OR_AUTHCFG,
				  "The (textual) relying party ID, usually the domain name of "
				  "the website or similar."),
	AP_INIT_TAKE1("AuthFIDO2UserFile", ap_set_file_slot,
				  (void *)APR_OFFSETOF(fido2_config_t, user_file),
				  OR_AUTHCFG,
				  "The filename of allowed users config."),
	AP_INIT_TAKE1("AuthFIDO2CookieName", ap_set_string_slot,
				  (void *)APR_OFFSETOF(fido2_config_t, cookie_name),
				  OR_AUTHCFG,
				  "The name of the session cookie used."),
	AP_INIT_TAKE1("AuthFIDO2Timeout", ap_set_int_slot,
				  (void *)APR_OFFSETOF(fido2_config_t, auth_timeout),
				  OR_AUTHCFG,
				  "Timeout (in seconds) for the authenticator at client side."),
	AP_INIT_TAKE1("AuthFIDO2TokenValidity", ap_set_int_slot,
				  (void *)APR_OFFSETOF(fido2_config_t, token_validity),
				  OR_AUTHCFG,
				  "Valid time of a token (in minutes)."),
	AP_INIT_FLAG("AuthFIDO2OfferAllUsers", ap_set_flag_slot,
				 (void *)APR_OFFSETOF(fido2_config_t, offer_all_users),
				 OR_AUTHCFG,
				 "Offer all known users in allowedCredentials as "
				 "workaround if RPID-based authentication doesn't work."),
	AP_INIT_FLAG("AuthFIDO2RequireUserVerification", ap_set_flag_slot,
				 (void *)APR_OFFSETOF(fido2_config_t, require_UV),
				 OR_AUTHCFG,
				 "Request and require FIDO2 user verification flag."),
	{ NULL }
};

void *create_authnz_fido2_config(apr_pool_t *p, char *dirspec)
{
	fido2_config_t *conf = apr_pcalloc(p, sizeof(*conf));

	conf->rpid_str = NULL;
	memset(conf->rpid_hash, 0, sizeof(conf->rpid_hash));
	conf->user_file = NULL;
	conf->cookie_name = NULL;
	conf->offer_all_users = -1;
	conf->require_UV = -1;
	conf->auth_timeout = -1;
	conf->token_validity = -1;
	return conf;
}

void *merge_authnz_fido2_config(apr_pool_t *p, void *base_conf, void *add_conf)
{
	fido2_config_t *base = base_conf;
	fido2_config_t *add  = add_conf;
	fido2_config_t *res  = apr_pcalloc(p, sizeof(*res));

#define merge_config(field,dflt)									\
	do {															\
		res->field = add->field >= 0 ? add->field : base->field;	\
		if (res->field < 0)											\
			res->field = dflt;										\
	} while(0)

	if (add->rpid_str) {
		res->rpid_str = add->rpid_str;
		sha256_str(res->rpid_str, res->rpid_hash);
	}
	else {
		res->rpid_str = base->rpid_str;
		memcpy(res->rpid_hash, base->rpid_hash, sizeof(res->rpid_hash));
	}
	res->user_file = add->user_file ?: base->user_file;
	res->cookie_name = add->cookie_name ?: base->cookie_name;

	merge_config(offer_all_users, DEFAULT_OFFER_ALL);
	merge_config(require_UV, DEFAULT_REQUIRE_UV);
	merge_config(auth_timeout, DEFAULT_AUTH_TIMEOUT);
	merge_config(token_validity, DEFAULT_TOKEN_VALID);
	return res;
}

