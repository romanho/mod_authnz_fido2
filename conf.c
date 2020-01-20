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
	AP_INIT_TAKE1("AuthFIDO2Timeout", ap_set_int_slot,
				  (void *)APR_OFFSETOF(fido2_config_t, timeout),
				  OR_AUTHCFG,
				  "Timeout (in seconds) for the authenticator at client side."),
	{ NULL }
};

void *create_authnz_fido2_config(apr_pool_t *p, char *dirspec)
{
	fido2_config_t *conf = apr_pcalloc(p, sizeof(*conf));

	conf->user_file = NULL;
	conf->rpid_str = NULL;
	memset(conf->rpid_hash, 0, sizeof(conf->rpid_hash));
	conf->offer_all_users = 0;
	conf->require_UV = 0;
	conf->timeout = -1;
	conf->token_validity = 10*60;
	return conf;
}

void *merge_authnz_fido2_config(apr_pool_t *p, void *base_conf, void *add_conf)
{
	fido2_config_t *base = base_conf;
	fido2_config_t *add  = add_conf;
	fido2_config_t *res  = apr_pcalloc(p, sizeof(*res));

	if (add->rpid_str) {
		res->rpid_str = add->rpid_str;
		sha256_str(res->rpid_str, res->rpid_hash);
	}
	else {
		res->rpid_str = base->rpid_str;
		memcpy(res->rpid_hash, base->rpid_hash, sizeof(res->rpid_hash));
	}
	res->user_file = add->user_file ?: base->user_file;
	res->timeout = add->timeout >= 0 ? add->timeout: base->timeout;
	return res;
}

