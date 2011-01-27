
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
char	**krb5_list_princs(krb5_context, kadm5_handle, char *);
char	**krb5_list_pols(krb5_context, kadm5_handle, char *);


krb5_keyblock		get_kte(krb5_context, char *, char *);
krb5_keyblock		krb5_make_a_key(krb5_context, krb5_enctype);
krb5_keyblock		krb5_v4_password(krb5_context, char *);
kadm5_principal_ent_rec	krb5_query_princ(krb5_context, kadm5_handle, char *);
kadm5_handle		krb5_get_kadm5_hndl(char *);

void	 krb5_modprinc(krb5_context, kadm5_handle, kadm5_principal_ent_rec,
		       long);
char	*krb5_createprinc(krb5_context, kadm5_handle,
                 	  kadm5_principal_ent_rec, long, char *);
void	 krb5_deleteprinc(krb5_context, kadm5_handle, char *);

krb5_error_code	krb5_init_context(krb5_context *);
krb5_error_code krb5_auth_con_init(krb5_context, krb5_auth_context *);
krb5_error_code krb5_auth_con_genaddrs(krb5_context, krb5_auth_context, int,
				       int);
krb5_error_code krb5_mk_rep(krb5_context, krb5_auth_context, krb5_data *);

krb5_error_code hack_addrs(krb5_context, krb5_auth_context);

void krb5_rd_req_mine(krb5_context, krb5_auth_context, krb5_data *in);
krb5_error_code krb5_rd_priv_mine(krb5_context, krb5_auth_context, krb5_data *,
				  krb5_data *);
krb5_error_code krb5_mk_priv_mine(krb5_context, krb5_auth_context, krb5_data *,
				  krb5_data *);
