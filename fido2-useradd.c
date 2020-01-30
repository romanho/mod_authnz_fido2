/* fido2-useradd
 * Add users to mod_authnz_fido2 users file
 *
 * Roman Hodek <roman@hodek.net>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <termios.h>
#include <signal.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <fido.h>
#include <fido/es256.h>
#include <fido/rs256.h>
#include <fido/eddsa.h>

int verbose = 0;


#define fatal(fmt, args...)						\
	do {										\
		fprintf(stderr, fmt "\n", ##args);		\
		exit(1);								\
	} while(0)
#define streq(a,b)     (strcmp((a),(b)) == 0)


static char *base64_encode(const uint8_t *p, size_t len)
{
	BIO  *bio_b64 = NULL;
	BIO  *bio_mem = NULL;
	char *b64_ptr = NULL;
	size_t rlen;
	char *ret;

	if (!(bio_b64 = BIO_new(BIO_f_base64())) ||
		!(bio_mem = BIO_new(BIO_s_mem())))
		return NULL;

	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(bio_b64, bio_mem);
	BIO_write(bio_b64, p, (int)len);
	BIO_flush(bio_b64);
	rlen = BIO_get_mem_data(bio_b64, &b64_ptr);
	if (rlen <= 0 || !(ret = malloc(rlen)))
		return NULL;
	memcpy(ret, b64_ptr, rlen);
	BIO_free(bio_b64);
	BIO_free(bio_mem);
	return ret;
}

static char *pkey_encode(EVP_PKEY *pkey)
{
	BIO  *bio_b64 = NULL;
	BIO  *bio_mem = NULL;
	char *b64_ptr = NULL;
	size_t rlen;
	char *ret;

	if (!(bio_b64 = BIO_new(BIO_f_base64())) ||
		!(bio_mem = BIO_new(BIO_s_mem())))
		return NULL;

	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(bio_b64, bio_mem);
	if (!i2d_PUBKEY_bio(bio_b64, pkey))
		fatal("i2d failed");
	BIO_flush(bio_b64);
	rlen = BIO_get_mem_data(bio_b64, &b64_ptr);
	if (rlen <= 0 || !(ret = malloc(rlen)))
		return NULL;
	memcpy(ret, b64_ptr, rlen);
	BIO_free(bio_b64);
	BIO_free(bio_mem);
	return ret;
	
}

#if 0
static void biob64_prep(BIO **bio_b64, BIO **bio_mem)
{
	*bio_b64 = BIO_new(BIO_f_base64());
	*bio_mem = BIO_new(BIO_s_mem());
}
static char *biob64_get(BIO *bio_b64, BIO *bio_mem)
{
	char *b64_ptr = NULL;
	size_t rlen;
	char *ret;

	BIO_flush(bio_b64);
	rlen = BIO_get_mem_data(bio_b64, &b64_ptr);
	if (rlen <= 0 || !(ret = malloc(rlen)))
		return NULL;
	memcpy(ret, b64_ptr, rlen);
	BIO_free(bio_b64);
	BIO_free(bio_mem);
	return ret;
}
#endif

static void readpin(const char *prompt, char *pin, size_t pinlen)
{
	int ifd = 0, ofd = 2;
	struct termios tio_old, tio_new;
	sigset_t sigs_old, sigs_new;
	char c, *p, *end;

	if (!isatty(ifd)) {
		if ((ifd = open("/dev/tty", O_RDWR)) < 0)
			fatal("/dev/tty: %s", strerror(errno));
		ofd = ifd;
	}
	write(ofd, prompt, strlen(prompt));

	/* turn terminal's ECHO off */
	if (tcgetattr(ifd, &tio_old))
		fatal("tcgetattr: %s", strerror(errno));
	tio_new = tio_old;
    tio_new.c_lflag &= ~(ECHO|ECHONL);
    if (tcsetattr(ifd, TCSAFLUSH, &tio_new))
		fatal("tcsetattr: %s", strerror(errno));

	/* block deadly signals as long as ECHO is off, to avoid leaving the user
	 * with a defunct terminal */
	sigemptyset(&sigs_new);
	sigaddset(&sigs_new, SIGINT);
	sigaddset(&sigs_new, SIGQUIT);
	sigaddset(&sigs_new, SIGHUP);
	sigaddset(&sigs_new, SIGALRM);
	sigaddset(&sigs_new, SIGPIPE);
	sigaddset(&sigs_new, SIGTSTP);
	sigaddset(&sigs_new, SIGTTIN);
	sigaddset(&sigs_new, SIGTTOU);
	if (sigprocmask(SIG_BLOCK, &sigs_new, &sigs_old))
		fatal("sigprocmask: %s", strerror(errno));

	p = pin;
	end = pin+pinlen-1;
	while(read(ifd, &c, 1) == 1 && c != '\n' && c != '\r') {
		if (p < end)
			*p++ = c;
	}
	*p = '\0';
	write(ofd, "\n", 1); /* newline isn't echoed, too */

	if (sigprocmask(SIG_SETMASK, &sigs_old, NULL))
		fatal("sigprocmask: %s", strerror(errno));
    if (tcsetattr(ifd, TCSAFLUSH, &tio_new))
		fatal("tcsetattr: %s", strerror(errno));
}

static void usage(void)
{
	fprintf(stderr, "Usage: fido2-useradd [-d DEVICE] [-t KEYTYPE] USERNAME\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	int c;
	int err;
	const char *devname = NULL;
	const char *username = NULL;
	int ktype = COSE_ES256;
	const char *ktype_str = "es256";
	fido_dev_t *dev;
	fido_cred_t *cred = NULL;
	char *credid;
	char *pubkey;
	
	while((c = getopt(argc, argv, "vd:t:")) != EOF) {
		switch(c) {
		  case 'v':
			++verbose;
			break;
		  case 'd':
			devname = optarg;
			break;
		  case 't':
			if (streq(optarg, "es256"))
				ktype = COSE_ES256;
			else if (streq(optarg, "rs256"))
				ktype = COSE_RS256;
			else if (streq(optarg, "eddsa"))
				ktype = COSE_EDDSA;
			else
				fatal("unsupported key type %s (not in: es256, rs256, eddsa)",
					  optarg);
			ktype_str = optarg;
			break;
		  default:
			usage();
		}
	}
	if (argc-optind != 1)
		usage();
	username = argv[optind];
	if (!username || !*username)
		usage();

	fido_init(0);

	if (!devname) {
		fido_dev_info_t *devlist;
		size_t ndevs;
		
		if (!(devlist = fido_dev_info_new(1)))
			fatal("fido_dev_info_new failed");
		if (fido_dev_info_manifest(devlist, 1, &ndevs) != FIDO_OK)
			fatal("FIDO2 device search error (%u devices available)",
				  (unsigned)ndevs);
		if (ndevs < 1)
			fatal("no FIDO2 device found");
		if (!(devname = strdup(fido_dev_info_path(fido_dev_info_ptr(devlist, 0)))))
			fatal("out of memory");
		fido_dev_info_free(&devlist, ndevs);

		if (verbose)
			printf("(using first FIDO2 device %s)\n", devname);
	}
	
	if (!(dev = fido_dev_new()))
		fatal("fido_dev_new failed");
	if ((err = fido_dev_open(dev, devname)) != FIDO_OK)
		fatal("fido_dev_open %s: %s", devname, fido_strerr(err));
		
	uint8_t cdh[32]; memset(cdh, 0, sizeof(cdh));
	const char *rpid = "localhost";

	if (!(cred = fido_cred_new()))
		fatal("fido_cred_new failed");
	if ((err = fido_cred_set_type(cred, ktype)) != FIDO_OK)
		fatal("fido_cred_set_type: %s", fido_strerr(err));
	if ((err = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh))) != FIDO_OK)
		fatal("fido_cred_set_cdhash: %s", fido_strerr(err));
	if ((err = fido_cred_set_rp(cred, rpid, NULL)) != FIDO_OK)
		fatal("fido_cred_set_rp: %s", fido_strerr(err));
	if ((err = fido_cred_set_user(cred, username, strlen(username),
								  username, NULL, NULL)) != FIDO_OK)
		fatal("fido_cred_set_user: %s", fido_strerr(err));
		
	err = fido_dev_make_cred(dev, cred, NULL);
	if (err == FIDO_ERR_PIN_REQUIRED) {
		char prompt[256], pin[256];
		snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ", devname);
		readpin(prompt, pin, sizeof(pin));
		err = fido_dev_make_cred(dev, cred, pin);
		memset(pin, 0, sizeof(pin));
	}
	if (err != FIDO_OK)
		fatal("fido_dev_make_cred: %s", fido_strerr(err));

	err = fido_cred_x5c_ptr(cred) ?
		  fido_cred_verify(cred) : fido_cred_verify_self(cred);
	if (err != FIDO_OK)
		fatal("fido_cred_verify: %s", fido_strerr(err));

	if (!(credid = base64_encode(fido_cred_id_ptr(cred), fido_cred_id_len(cred))))
		fatal("could not convert credid");

	EVP_PKEY *pkey = NULL;
	const void *pkey_data = fido_cred_pubkey_ptr(cred);
	size_t pkey_len = fido_cred_pubkey_len(cred);
	
	switch(ktype) {
	  case COSE_ES256: {
		  es256_pk_t *pk;
		  if (!(pk = es256_pk_new()) ||
			  es256_pk_from_ptr(pk, pkey_data, pkey_len) != FIDO_OK ||
			  !(pkey = es256_pk_to_EVP_PKEY(pk)))
			  fatal("could not convert ECC key");
		  break;
	  }  
	  case COSE_RS256: {
		  rs256_pk_t *pk;
		  if (!(pk = rs256_pk_new()) ||
			  rs256_pk_from_ptr(pk, pkey_data, pkey_len) != FIDO_OK ||
			  !(pkey = rs256_pk_to_EVP_PKEY(pk)))
			  fatal("could not convert RSA key");
		  break;
	  }  
	  case COSE_EDDSA: {
		  rs256_pk_t *pk;
		  if (!(pk = eddsa_pk_new()) ||
			  eddsa_pk_from_ptr(pk, pkey_data, pkey_len) != FIDO_OK ||
			  !(pkey = eddsa_pk_to_EVP_PKEY(pk)))
			  fatal("could not convert RSA key");
		  break;
	  }  
	  default:
		fatal("unsupported key type");
	}
	pubkey = pkey_encode(pkey);
	
	printf("%s:%s:%s:%s:0\n",
		   username,
		   credid,
		   ktype_str,
		   pubkey);
	return 0;
}
