
/*
 * The following macros help deal with the many little differences
 * between the Heimdal and MIT krb5 APIs.
 */

#ifdef HAVE_HEIMDAL

/* krb5_keyblock stuff */
#define	KEYBLOCK_ENCTYPE(k)	((k).keytype)
#define	KEYBLOCK_CONTENT_LEN(k)	((k).keyvalue.length)
#define	KEYBLOCK_CONTENTS(k)	((k).keyvalue.data)
#define	KV5M_KEYBLOCK		1
#define	KEYBLOCK_MAGIC(k)	KV5M_KEYBLOCK
#define	KEYBLOCK_SET_MAGIC(k)

#define CREDS_MAGIC(c)		1
#define CREDS_SET_MAGIC(c)
#define CREDS_KEYBLOCK(c)	((c).session)
#define CREDS_FLAGS(c)		((c).flags.i)

/* krb5_keytab_entry stuff */
#define	KEYTABENT_KEYBLOCK(kte)	((kte).keyblock)

#define	PRINC_REALM(ctx, p)	  krb5_principal_get_realm(ctx, p)
#define	PRINC_REALM_LEN(ctx, p)	  strlen(PRINC_REALM(ctx, p))
#define	PRINC_NCOMPS(ctx, p)	  krb5_principal_get_num_comp(ctx, p)
#define	PRINC_COMP(ctx, p, n)	  krb5_principal_get_comp_string(ctx, p, n)
#define	PRINC_COMP_LEN(ctx, p, n) strlen(PRINC_COMP(ctx, p, n))

#define	STRING_TO_ENCTYPE(s, e) krb5_string_to_enctype(NULL, s, e)

#else
#ifdef HAVE_MIT

#define	KEYBLOCK_ENCTYPE(k)	((k).enctype)
#define	KEYBLOCK_CONTENT_LEN(k)	((k).length)
#define	KEYBLOCK_CONTENTS(k)	((k).contents)
#define	KEYBLOCK_MAGIC(k)	((k).magic)
#define	KEYBLOCK_SET_MAGIC(k)	((k).magic = KV5M_KEYBLOCK)

#define CREDS_MAGIC(c)		((c).magic)
#define CREDS_SET_MAGIC(c)	((c).magic) = KV5M_CREDS)
#define CREDS_KEYBLOCK(c)	((c).keyblock)
#define CREDS_FLAGS(c)		((c).ticket_flags)

#define	KEYTABENT_KEYBLOCK(kte) ((kte).key)

#define	PRINC_REALM(ctx, p)	  (krb5_princ_realm(ctx, p)->data)
#define	PRINC_REALM_LEN(ctx, p)	  (krb5_princ_realm(ctx, p)->length)
#define	PRINC_NCOMPS(ctx, p)	  (krb5_princ_size(ctx, p))
#define	PRINC_COMP(ctx, p, n)	  (krb5_princ_component(ctx, p, n)->data)
#define	PRINC_COMP_LEN(ctx, p, n) (krb5_princ_component(ctx, p, n)->length)

#define	STRING_TO_ENCTYPE(s, e) krb5_string_to_enctype(s, e)

#else
#error "Must define either HAVE_HEIMDAL or HAVE_MIT"
#endif /* HAVE_MIT */
#endif /* HAVE_HEIMDAL */

/* Continued accessor macros defined in terms of prior */

#define	KEYTABENT_ENCTYPE(kte)	   KEYBLOCK_ENCTYPE(KEYTABENT_KEYBLOCK(kte))
#define	KEYTABENT_CONTENT_LEN(kte) KEYBLOCK_CONTENT_LEN(KEYTABENT_KEYBLOCK(kte))
#define	KEYTABENT_CONTENTS(kte)	   KEYBLOCK_CONTENTS(KEYTABENT_KEYBLOCK(kte))

#define CREDS_KEYBLOCK_SET_MAGIC(c)	KEYBLOCK_SET_MAGIC(CREDS_KEYBLOCK(c))
#define CREDS_KEYBLOCK_ENCTYPE(c)	KEYBLOCK_ENCTYPE(CREDS_KEYBLOCK(c))
#define CREDS_KEYBLOCK_CONTENTS(c)	KEYBLOCK_CONTENTS(CREDS_KEYBLOCK(c))
#define CREDS_KEYBLOCK_CONTENT_LEN(c)	KEYBLOCK_CONTENT_LEN(CREDS_KEYBLOCK(c))

key	  krb5_getkey(krb5_context, kadm5_handle, char *);
void	  krb5_createkey(krb5_context, kadm5_handle, char *);
key	  read_kt(krb5_context, char *);
void	  write_kt(krb5_context, char *, krb5_keytab_entry *);
void	  kt_remove_entry(krb5_context, char *, krb5_keytab_entry *);
void	  krb5_setkey(krb5_context, kadm5_handle, char *, int, krb5_keyblock *);
void	  krb5_setpass(krb5_context, kadm5_handle, char *, char *);
char	 *krb5_randpass(krb5_context, kadm5_handle, char *);
void	  krb5_randkey(krb5_context, kadm5_handle, char *);
char	**krb5_get_kdcs(krb5_context, char *);
char	 *krb5_get_realm(krb5_context);
char	**krb5_list_princs(krb5_context, kadm5_handle, char *);
char	**krb5_list_pols(krb5_context, kadm5_handle, char *);

void	  init_store_creds(krb5_context, char *, krb5_creds *);

krb5_creds		*mint_ticket(krb5_context, kadm5_handle, char *, int,
				     int);
krb5_keyblock		 get_kte(krb5_context, char *, char *);
krb5_keyblock		 krb5_make_a_key(krb5_context, krb5_enctype);
kadm5_principal_ent_rec	 krb5_query_princ(krb5_context, kadm5_handle, char *);
kadm5_handle		 krb5_get_kadm5_hndl(krb5_context, char *);

void	 krb5_modprinc(krb5_context, kadm5_handle, kadm5_principal_ent_rec,
		       long);
char	*krb5_createprinc(krb5_context, kadm5_handle,
                 	  kadm5_principal_ent_rec, long, char *);
void	 krb5_deleteprinc(krb5_context, kadm5_handle, char *);

krb5_error_code	krb5_init_context(krb5_context *);
krb5_error_code	krb5_parse_name(krb5_context, const char *, krb5_principal *);
