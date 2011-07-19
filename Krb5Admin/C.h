
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


krb5_keyblock		get_kte(krb5_context, char *, char *);
krb5_keyblock		krb5_make_a_key(krb5_context, krb5_enctype);
kadm5_principal_ent_rec	krb5_query_princ(krb5_context, kadm5_handle, char *);
kadm5_handle		krb5_get_kadm5_hndl(krb5_context, char *);

void	 krb5_modprinc(krb5_context, kadm5_handle, kadm5_principal_ent_rec,
		       long);
char	*krb5_createprinc(krb5_context, kadm5_handle,
                 	  kadm5_principal_ent_rec, long, char *);
void	 krb5_deleteprinc(krb5_context, kadm5_handle, char *);

krb5_error_code	krb5_init_context(krb5_context *);
krb5_error_code	krb5_parse_name(krb5_context, const char *, krb5_principal *);
