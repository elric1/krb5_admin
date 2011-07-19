/*  */

/* Blame: Roland Dowdeswell <elric@imrryr.org> */

/*
 * XXXrcd: nice comments here.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Kerberos includes */

#include <k5-int.h>

#include <krb5.h>
#include <kadm5/admin.h>

#define BAIL(x, y)	do {						\
		ret = x;						\
		if (ret) {						\
			snprintf(croakstr, sizeof(croakstr),		\
			    "%s: %s", #x, y);				\
			ret = 1;					\
			goto done;					\
		}							\
	} while (0)

#define K5BAIL(x)	BAIL(x, error_message(ret))

typedef	void *kadm5_handle;

struct _key {
	char		*princ;
	krb5_timestamp	 timestamp;
	int	 	 kvno;
	krb5_keyblock	 key;
	struct _key	*next;
};

typedef struct _key *key;

#include "C.h"

kadm5_handle
krb5_get_kadm5_hndl(krb5_context ctx, char *dbname)
{
	kadm5_config_params	 params;
	kadm5_ret_t		 ret;
	kadm5_handle		 hndl;
	const char		*princstr = "root";
	char			 croakstr[2048] = "";

	memset((char *) &params, 0, sizeof(params));	

	if (dbname) {
		params.mask   = KADM5_CONFIG_DBNAME;
		params.dbname = dbname;
	}

	K5BAIL(kadm5_init_with_password((char *)princstr, NULL, NULL, &params,
	    KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, &hndl));

done:
	if (ret)
		croak(croakstr);

	return hndl;
}

kadm5_principal_ent_rec
krb5_query_princ(krb5_context ctx, kadm5_handle hndl, char *in)
{
	kadm5_principal_ent_rec	 dprinc;
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	char			 croakstr[2048] = "";

	memset(&dprinc, 0, sizeof(dprinc));

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_get_principal(hndl, princ, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK));

done:
	if (princ)
		krb5_free_principal(ctx, princ);
	/* XXXrcd: free dprinc */

	if (ret)
		croak(croakstr);

	return dprinc;
}

#define HUMAN_PASSWD_SIZE	10
#define PROID_PASSWD_SIZE	15
char c_num[]	= "2345679";
char c_low[]	= "qwertyuipasdfghjkzxcvbnm";
char c_cap[]	= "QWERTYUPASDFGHJKLZXCVNM";
char c_all[] =	"2345679"      "2345679"
		"QWERTYUPASDFGHJKLZXCVNM"
		"qwertyuipasdfghjkzxcvbnm"
		"qwertyuipasdfghjkzxcvbnm"
		"!@#$%^&*()-+=[]{};:,.<>?"
		;

static char *
random_passwd(krb5_context ctx, int len)
{
	krb5_keyblock	 key;
	krb5_error_code	 ret;
	char		 croakstr[256];
	char		*passwd = NULL;
	int		 i;

	passwd = malloc(len + 1);
	if (!passwd) {
		snprintf(croakstr, sizeof(croakstr), "Out of memory");
		ret = errno;
		goto done;
	}

	/* We lamely convert a key into a string for the passwd */
	K5BAIL(krb5_c_make_random_key(ctx, 18, &key));

	/*
	 * We are contructing what we presume to be a relatively good
	 * passwd here.  First, we select a single character from each
	 * of three character classes.  We do this up front to ensure
	 * that all passwds contain at least 3 character classes.  We
	 * could generate and then test, but we don't.  We looking to
	 * weight things a little away from the symbols and towards
	 * simplicity.  So, let's say that lower or upper case characters
	 * have about 4.5 bits of strength given that we've selected
	 * 23 of them.  The numbers have about 2.2 or so.  Our c_all[]
	 * is also a little skewed.  We have 79 possible characters but
	 * we're skewing towards lower case to make it easier to type.
	 * So, we're not really getting over 6 bits out of it.  Still,
	 * let's say that we're getting 5.5, then our 10 char passwd
	 * is:
	 *
	 *	2.2 + 4.5 + 4.5 + 7 * 5.5 = 49 bits.
	 *
	 * XXXrcd:
	 * Also note that because of our use of simple modulo arith,
	 * we're slightly biasing results towards the fronts of each
	 * of these character classes...
	 *
	 * Good enough.  Certainly better than the users will choose for
	 * themselves.
	 */

	passwd[0] = c_low[key.contents[0] % (sizeof(c_low) - 1)];
	passwd[1] = c_cap[key.contents[1] % (sizeof(c_cap) - 1)];
	passwd[2] = c_num[key.contents[2] % (sizeof(c_num) - 1)];
	for (i=3; i < len; i++)
		passwd[i] = c_all[key.contents[i] % (sizeof(c_all) - 1)];
	krb5_free_keyblock_contents(ctx, &key);
	passwd[i] = '\0';

done:
	if (ret) {
		free(passwd);
		croak(croakstr);
	}

	return passwd;
}

char *
krb5_createprinc(krb5_context ctx, kadm5_handle hndl,
		 kadm5_principal_ent_rec p, long mask, char *passwd)
{
	kadm5_ret_t	 ret;
	char		 croakstr[256];

	if (!passwd)
		passwd = random_passwd(ctx, HUMAN_PASSWD_SIZE);
	mask |= KADM5_PRINCIPAL;
	K5BAIL(kadm5_create_principal(hndl, &p, mask, passwd));

done:
	if (ret) {
		free(passwd);
		croak(croakstr);
	}

	return passwd;
}

void
krb5_modprinc(krb5_context ctx, kadm5_handle hndl, kadm5_principal_ent_rec p,
              long mask)
{
	kadm5_ret_t	ret;
	char		croakstr[256];

	K5BAIL(kadm5_modify_principal(hndl, &p, mask));

done:
	if (ret)
		croak(croakstr);
}

void
krb5_deleteprinc(krb5_context ctx, kadm5_handle hndl, char *in)
{
	krb5_principal	princ = NULL;
	kadm5_ret_t	ret;
	char		croakstr[1024];

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_delete_principal(hndl, princ));

done:
	/* XXXrcd: free the princ. */
	if (ret)
		croak(croakstr);
}

key
krb5_getkey(krb5_context ctx, kadm5_handle hndl, char *in)
{
	kadm5_principal_ent_rec	 dprinc;
	krb5_principal		 princ = NULL;
	kadm5_config_params	 params;
	kadm5_ret_t		 ret;
	int			 i;
	char			 croakstr[2048] = "";
	key			 k;
	key			 ok = NULL;
	key			 first = NULL;

	memset((char *) &params, 0, sizeof(params));	
	memset(&dprinc, 0, sizeof(dprinc));

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_get_principal(hndl, princ, &dprinc, 
	    KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

	for (i=0; i < dprinc.n_key_data; i++) {
		krb5_key_data	*kd = &dprinc.key_data[i];

		k = calloc(sizeof(struct _key), 1);
		if (!first)
			first = k;
		if (ok)
			ok->next = k;
		ok = k;

		/*
		 * Here we elide both duplicated DES keys and
		 * keys with invalid encryption types.
		 */

#if 0
		if (kd->key_data_type[0] == ENCTYPE_NULL ||
		    (des_done && kd->key_data_type[0] == ENCTYPE_DES_CBC_CRC))
			continue;
		des_done = 1;
#endif

		k->princ = in;
		k->timestamp = dprinc.last_pwd_change;
		k->kvno = kd->key_data_kvno;
		ret = kadm5_decrypt_key(hndl, &dprinc, kd->key_data_type[0],
		    -1 /*salt*/, kd->key_data_kvno, &k->key, NULL, NULL);
	}

done:
	/* XXXrcd: free up used data structures! */

	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret) {
#if 0 /* XXXrcd: clean up */
		key_free(ok);
#endif
		croak(croakstr);
	}

	return first;
}

void
krb5_createkey(krb5_context ctx, kadm5_handle hndl, char *in)
{
	kadm5_principal_ent_rec	 dprinc;
	krb5_key_salt_tuple	 enctypes[8];
	kadm5_config_params	 params;
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	int			 i;
	char			 croakstr[2048] = "";
	char			 dummybuf[256];

	memset((char *) &params, 0, sizeof(params));	
	memset(dummybuf, 0x0, sizeof(dummybuf));
	memset(&dprinc, 0, sizeof(dprinc));

	K5BAIL(krb5_parse_name(ctx, in, &princ));

	for (i=0; i < sizeof(dummybuf); i++)
		dummybuf[i] = 32 + (i % 80);

	dprinc.principal = princ;
	dprinc.attributes = KRB5_KDB_DISALLOW_ALL_TIX;
	K5BAIL(kadm5_create_principal(hndl, &dprinc, KADM5_PRINCIPAL|
	     KADM5_ATTRIBUTES, dummybuf));

	/*
	 * XXXrcd: for now, hardcode AES, DES3 and RC4, we'll take this
	 *         out later, when we can update the configuration.
	 */
	enctypes[0].ks_enctype  = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	enctypes[0].ks_salttype = 0;
	enctypes[1].ks_enctype  = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	enctypes[1].ks_salttype = 0;
	enctypes[2].ks_enctype  = ENCTYPE_ARCFOUR_HMAC;
	enctypes[2].ks_salttype = 0;
	enctypes[3].ks_enctype  = ENCTYPE_DES3_CBC_SHA1;
	enctypes[3].ks_salttype = 0;

	K5BAIL(kadm5_randkey_principal_3(hndl, dprinc.principal, 0,
	    4, enctypes, NULL, NULL));

        dprinc.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
        K5BAIL(kadm5_modify_principal(hndl, &dprinc, KADM5_ATTRIBUTES));

done:
	/* XXXrcd: free up used data structures! */

	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret)
		croak(croakstr);
	return;
}

static int
max_kvno(kadm5_principal_ent_rec dprinc)
{
	int	 i;
	int	 max_kvno = 0;

	for (i=0; i < dprinc.n_key_data; i++) {
		krb5_key_data	*kd = &dprinc.key_data[i];

		if (max_kvno < kd->key_data_kvno)
			max_kvno = kd->key_data_kvno;
	}

	return max_kvno;
}

void
krb5_setkey(krb5_context ctx, kadm5_handle hndl, char *in, int kvno,
	    krb5_keyblock *keys)
{
	kadm5_principal_ent_rec	 dprinc;
	kadm5_config_params	 params;
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	int			 n_keys;
	int			 locked = 0;
	char			 croakstr[2048] = "";

	memset((char *) &params, 0, sizeof(params));	
	memset(&dprinc, 0, sizeof(dprinc));

	/*
	 * We expect that our typemap will give us an array of keys that
	 * is terminated with an extra invalid entry.
	 */

	for (n_keys = 0; keys[n_keys].magic == KV5M_KEYBLOCK; n_keys++)
		;

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_lock(hndl));
	locked = 1;

	if (kvno >= 2) {
		K5BAIL(kadm5_get_principal(hndl, princ, &dprinc, 
		    KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA));

		if (max_kvno(dprinc) != (kvno - 1)) {
			snprintf(croakstr, sizeof(croakstr), "not the next "
			    "key");
			ret = 1;
			goto done;
		}
	}

	K5BAIL(kadm5_setkey_principal_3(hndl, princ, TRUE, 0, NULL,
	    keys, n_keys));

#if 0
	/* XXXrcd: this is a little L4M3.  Maybe a different function? */
	dprinc.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
	K5BAIL(kadm5_modify_principal(hndl, &dprinc, KADM5_ATTRIBUTES));
#endif

done:
	/* XXXrcd: free up used data structures! */

	if (princ)
		krb5_free_principal(ctx, princ);
	if (locked) {
		/*
		 * Strangely, writes are tossed if you do not unlock before
		 * destroying the DB.  Also, don't flush while you have a
		 * lock.  That tosses writes...
		 */
		kadm5_unlock(hndl);
	}

	if (ret)
		croak(croakstr);
	return;
}

char *
krb5_randpass(krb5_context ctx, kadm5_handle hndl, char *in)
{
	krb5_principal		 princ = NULL;
	kadm5_ret_t		 ret;
	char			 croakstr[2048] = "";
	char			*passwd = NULL;

	passwd = random_passwd(ctx, PROID_PASSWD_SIZE);
	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_chpass_principal_3(hndl, princ, FALSE, 0, NULL, passwd));

done:
	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret) {
		free(passwd);
		croak(croakstr);
	}
	return passwd;
}

void
krb5_setpass(krb5_context ctx, kadm5_handle hndl, char *in, char *passwd)
{
	krb5_principal		princ = NULL;
	kadm5_ret_t		ret;
	char			croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	K5BAIL(kadm5_chpass_principal_3(hndl, princ, FALSE, 0, NULL, passwd));

done:
	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret)
		croak(croakstr);
	return;
}

void
krb5_randkey(krb5_context ctx, kadm5_handle hndl, char *in)
{
	krb5_principal		princ = NULL;
	krb5_key_salt_tuple	enctypes[1];
	kadm5_ret_t		ret;
	char			croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));

	/*
	 * Random keys are hardcoded to AES for now: we're only actually
	 * using them for proids...
	 */
	enctypes[0].ks_enctype  = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	enctypes[0].ks_salttype = 0;
	K5BAIL(kadm5_randkey_principal_3(hndl, princ, FALSE, 1, enctypes,
	    NULL, NULL));

done:
	if (princ)
		krb5_free_principal(ctx, princ);

	if (ret)
		croak(croakstr);
	return;
}

krb5_keyblock
get_kte(krb5_context ctx, char *kt, char *in)
{
	krb5_principal		princ = NULL;
	krb5_keytab		keytab = NULL;
	krb5_keytab_entry	e;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	K5BAIL(krb5_parse_name(ctx, in, &princ));
	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, kt, &keytab));
	else
		K5BAIL(krb5_kt_default(ctx, &keytab));

	K5BAIL(krb5_kt_get_entry(ctx, keytab, princ, 0, 0, &e));

done:
	/* XXXrcd: free up keytab and stuff */
	if (ret)
		croak(croakstr);
	return e.key;
}

void
kt_remove_entry(krb5_context ctx, char *kt, krb5_keytab_entry *e)
{
	krb5_keytab		keytab = NULL;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, kt, &keytab));
	else
		K5BAIL(krb5_kt_default(ctx, &keytab));

	K5BAIL(krb5_kt_remove_entry(ctx, keytab, e));

done:
	if (keytab)
		krb5_kt_close(ctx, keytab);

	if (ret) {
		croak(croakstr);
	}
}

key
read_kt(krb5_context ctx, char *ktname)
{
	krb5_keytab		 kt;
	krb5_keytab_entry	 e;
	krb5_kt_cursor		 c;
	key			 k;
	key			 first = NULL;
	key			 ok = NULL;
	krb5_error_code		 ret;
	char			 croakstr[2048] = "";

	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, ktname, &kt));
	else
		K5BAIL(krb5_kt_default(ctx, &kt));

	K5BAIL(krb5_kt_start_seq_get(ctx, kt, &c));

	while (!(ret = krb5_kt_next_entry(ctx, kt, &e, &c))) {
		k = calloc(sizeof(*k), 1);
		if (!first)
			first = k;
		if (ok)
			ok->next = k;
		ok = k;

		K5BAIL(krb5_unparse_name(ctx, e.principal, &k->princ));
		k->kvno = e.vno;
		k->timestamp = e.timestamp;
		K5BAIL(krb5_copy_keyblock_contents(ctx, &e.key, &k->key));
	}

	if (ret != KRB5_KT_END) {
		/* do some sort of error here... */
	}

	/* XXXrcd: should this be below the done: ?? */
	K5BAIL(krb5_kt_end_seq_get(ctx, kt, &c));

done:

	/* XXXrcd: clean up memory and stuff! */

	if (ret)
		croak(croakstr);

	return first;
}

void
write_kt(krb5_context ctx, char *kt, krb5_keytab_entry *e)
{
	krb5_keytab		keytab = NULL;
	krb5_keytab_entry	old;
	krb5_error_code		ret;
	char			croakstr[2048] = "";

	if (kt)
		K5BAIL(krb5_kt_resolve(ctx, kt, &keytab));
	else
		K5BAIL(krb5_kt_default(ctx, &keytab));

	/*
	 * Because the MIT Kerberos libraries seem to just add duplicate
	 * keys, we must purge incorrect and keys while not removing the
	 * correct keys.  We do this so that we can ensure that the keytab
	 * is always in a consistent state.
	 */

	for (;;) {
		ret = krb5_kt_get_entry(ctx, keytab, e->principal, e->vno,
		    e->key.enctype, &old);

		if (ret)
			break;

		if (memcmp(old.key.contents,e->key.contents,old.key.length)) {
			K5BAIL(krb5_kt_remove_entry(ctx, keytab, &old));
		} else {
			/* we found a matching key, so nothing to do... */
			ret = 0;
			goto done;
		}
	}

	K5BAIL(krb5_kt_add_entry(ctx, keytab, e));

done:
	if (keytab)
		krb5_kt_close(ctx, keytab);

	if (ret) {
		croak(croakstr);
	}
}

char *
krb5_get_realm(krb5_context ctx)
{
	krb5_error_code	 ret;
	char		*realm;
	char		 croakstr[2048] = "";

	K5BAIL(krb5_get_default_realm(ctx, &realm));

done:
	if (ret)
		croak(croakstr);

	return realm;
}

char **
krb5_get_kdcs(krb5_context ctx, char *realm)
{
	krb5_data	  realm_data;
	krb5_error_code	  ret;
	char		 *def_realm = NULL;
	char		**hostlist = NULL;
	char		  croakstr[2048] = "";

	if (!realm || !realm[0]) {
		K5BAIL(krb5_get_default_realm(ctx, &def_realm));
		realm = def_realm;
	}

	realm_data.data = realm;
	realm_data.length = strlen(realm);

	K5BAIL(krb5_get_krbhst(ctx, &realm_data, &hostlist));

done:
	if (def_realm)
		krb5_free_default_realm(ctx, def_realm);

	if (ret) {
		/* XXX free host list? */
		return NULL;
	}
	return hostlist;
}

char **
krb5_list_pols(krb5_context ctx, kadm5_handle hndl, char *exp)
{
        kadm5_ret_t       ret;
	char		**out = NULL;
        char            **pols = NULL;
	char		  croakstr[2048] = "";
        int               count;
	int		  i;

	K5BAIL(kadm5_get_policies(hndl, exp, &pols, &count));

	/* We must null terminate the string because of our typemap. */
	out = malloc((count + 1) * sizeof(*out));
	if (!out) {
		snprintf(croakstr, sizeof(croakstr), "krb5_list_pols"
		    "(): malloc failed");
		ret = 1;
		goto done;
	}
	for (i=0; i < count; i++)
		out[i] = pols[i];
	out[i] = NULL;

done:
        /* XXXrcd: leaks like a sieve. */
	if (ret)
		croak(croakstr);
        return out;
}

char **
krb5_list_princs(krb5_context ctx, kadm5_handle hndl, char *exp)
{
        kadm5_ret_t       ret;
	char		**out = NULL;
        char            **princs = NULL;
	char		  croakstr[2048] = "";
        int               count;
	int		  i;

        K5BAIL(kadm5_get_principals(hndl, exp, &princs, &count));

	/* We must null terminate the string because of our typemap. */
	out = malloc((count + 1) * sizeof(*out));
	if (!out) {
		snprintf(croakstr, sizeof(croakstr), "krb5_list_princs"
		    "(): malloc failed");
		ret = 1;
		goto done;
	}
	for (i=0; i < count; i++)
		out[i] = princs[i];
	out[i] = NULL;

done:
        /* XXXrcd: leaks like a sieve. */
	if (ret)
		croak(croakstr);
        return out;
}


krb5_keyblock
krb5_make_a_key(krb5_context ctx, krb5_enctype enctype)
{
	krb5_error_code	ret = 0;
	krb5_keyblock	key;
	char		croakstr[2048] = "";

	K5BAIL(krb5_c_make_random_key(ctx, enctype, &key));

done:
	if (ret)
		croak(croakstr);
	return key;
}
