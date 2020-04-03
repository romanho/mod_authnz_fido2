#ifndef _mod_authnz_fido2_h
#define _mod_authnz_fido2_h

/* mod_authn_fido2
 * Apache module for authentication with FIDO2 (WebAuthn)
 *
 * Roman Hodek <roman@hodek.net>
 *
 */

#include <string.h>
#include <stdint.h>
#include <httpd.h>
#include <http_config.h>

#define CHALLENGE_LEN	32
#define SHA256_LEN		32
#define JWTKEY_LEN		32
#define JWTKEY_NUM		2
#define CHMACKEY_LEN	16
#define CHMACSTAMP_LEN	sizeof(time_t)

#define ADF_UP 0x01	/* user present */
#define ADF_UV 0x04	/* user verified */
#define ADF_AT 0x40	/* attestation present */
#define ADF_ED 0x80	/* extension included */



typedef struct {
	const char *rpid_str;
	uint8_t rpid_hash[SHA256_LEN];
	const char *user_file;
	const char *cookie_name;
	int offer_all_users;
	int require_UV;
    int auth_timeout;
	int token_validity;
	int jwtkey_lifetime;
} fido2_config_t;

#define DEFAULT_OFFER_ALL		0
#define DEFAULT_REQUIRE_UV		0
#define DEFAULT_AUTH_TIMEOUT	30
#define DEFAULT_TOKEN_VALID		60
#define DEFAULT_JWTKEY_LIFETIME	720

typedef struct {
	const char *name;
	const char *credid;
	const char *ktype;
	const char *pubkey;
	unsigned counter;
} fido2_user_t;

#define streq(a,b)     (strcmp((a),(b)) == 0)
static __inline__ const char *strprefix(const char *a, const char *b) {
	size_t len = strlen(b);
	return (strncmp(a, b, len) == 0) ? a+len : NULL;
}

#define debug(fmt, args...) \
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req, "%s: " fmt, __func__, ##args)
#define info(fmt, args...) \
	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, req, "%s: " fmt, __func__, ##args)
#define warn(fmt, args...) \
	ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, req, "%s: " fmt, __func__, ##args)
#define error(fmt, args...) \
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s: " fmt, __func__, ##args)

/* conf.c */
void *create_authnz_fido2_config(apr_pool_t *p, char *dirspec);
void *merge_authnz_fido2_config(apr_pool_t *p, void *base_conf, void *add_conf);
extern const command_rec authnz_fido2_cmds[];

/* token.c */
void jwtkey_init(uint8_t *mem);
char *create_token(request_rec *req, fido2_config_t *conf, fido2_user_t *uent);
int check_token(request_rec *req, fido2_config_t *conf, const char *tokstr, char **user);

/* util.c */
fido2_user_t *getuser_byname(request_rec *req, fido2_config_t *conf, const char *name);
fido2_user_t *getuser_bycredid(request_rec *req, fido2_config_t *conf, const char *credid);
void for_all_users(request_rec *req, fido2_config_t *conf, int (*callback)(const fido2_user_t *u));
const char *get_rpid(request_rec *req, fido2_config_t *conf);
char *parse_cookie(request_rec *req, const char *cookiename);
void base64url2normal(char *str);
void remove_slashes(char *str);
int get_ktype(const char *str);
void *get_pubkey(int ktype, const char *kdata);
void free_pubkey(int ktype, void *pk);
int sha256(const uint8_t *in, size_t inlen, uint8_t *out);
int sha256_2buf(const uint8_t *in1, size_t in1len, const uint8_t *in2, size_t in2len, uint8_t *out);
int sha256_3buf(const uint8_t *in1, size_t in1len, const uint8_t *in2, size_t in2len, const uint8_t *in3, size_t in3len, uint8_t *out);
int sha256_str(const char *str, uint8_t *out);
void log_bytearray(request_rec *req, const char *prefix, uint8_t *data, size_t len);

#endif /* _mod_authnz_fido2_h */

