%module "Krb5Admin::C"
%{

/*
 * First we define lots of nasty macros to put things in and get things
 * out of hashes quickly:
 */

#define HV_FETCH_FULL(hv, lhs, rhs, success, bail) do {			\
		lhs = hv_fetch(hv, rhs, strlen((rhs)), 0);		\
		if (!lhs && bail) {					\
			snprintf(croakstr, sizeof(croakstr),		\
			    "Hash argument did not "			\
			    "contain %s", (rhs));			\
			ret = 1;					\
			goto done;					\
		} 							\
		if (lhs) { 						\
			success;					\
		}							\
	} while (0)

#define HV_FETCH(hv, lhs, rhs)	HV_FETCH_FULL(hv, lhs, rhs,, 1)

#define HV_FETCH_INTO_FULL(hv, lhs, rhs, func, success, bail) do {	\
		SV	**__hv_f_sv;					\
									\
		HV_FETCH_FULL(hv, __hv_f_sv, rhs, success, bail);	\
		if (__hv_f_sv)						\
			lhs = func(*__hv_f_sv);				\
	} while (0)

#define HV_FETCH_INTO(hv, lhs, rhs, func)				\
	HV_FETCH_INTO_FULL(hv, lhs, rhs, func,, 1)

#define HV_FETCH_INTO_FULLS(hv, base, key, func, success, bail)		\
	HV_FETCH_INTO_FULL(hv, base.key, #key, func, success, bail)

#define HV_FETCH_INTO_STRLEN(hv, lhs_str, lhs_len, rhs) do {		\
		SV	**__hv_f_sv;					\
		STRLEN	  __len;					\
									\
		HV_FETCH(hv, __hv_f_sv, rhs);				\
		lhs_str = SvPV(*__hv_f_sv, __len);			\
		lhs_len = __len;					\
	} while (0)

#define HV_STORE_INTERNAL_F(hv, key, sv) 				\
	(void)hv_store((hv), (key), strlen((key)), sv, 0)

#define HV_STORE_PVN_LEN_F(hv, key, val, len) do {			\
		if (val) 						\
			HV_STORE_INTERNAL_F(hv, key, newSVpvn(val,	\
			    len));					\
	} while (0)

#define HV_STORE_PVN_LEN(hv, base, key, len)				\
	HV_STORE_PVN_LEN_F(hv, #key, base . key, base . len)

#define HV_STORE_PVN_F(hv, key, val) 					\
	HV_STORE_PVN_LEN_F(hv, key, val, strlen(val));

#define HV_STORE_PVN(hv, base, key) HV_STORE_PVN_F(hv, #key, base . key)
#define HV_STORE_IV_F(hv, key, val) HV_STORE_INTERNAL_F(hv, key, newSViv(val))
#define HV_STORE_IV(hv, base, key)  HV_STORE_IV_F((hv), #key, base . key)

#include "C.c"

%}

%typemap(in,numinputs=0) krb5_context * {
	$1 = calloc(sizeof(krb5_context), 1);
}
%typemap(argout) krb5_context * {
	$result = SWIG_NewPointerObj($1, SWIGTYPE_p_krb5_context,
	    SWIG_POINTER_OWN);
	argvi++;
}
%typemap(in) krb5_auth_context * {
	if (!SvOK($input)) {
		$1 = calloc(sizeof(krb5_auth_context), 1);
	}
}
%typemap(argout) krb5_auth_context * {
	$result = SWIG_NewPointerObj($1, SWIGTYPE_p_krb5_auth_context,
	    SWIG_POINTER_OWN);
	argvi++;
}

%typemap(out) krb5_error_code {
	if ($1) {
#ifdef HAVE_HEIMDAL 
		krb5_error_code	 ret = $1;
		krb5_context	 nullctx = 0;
		char		 croakstr[2048] = "";
		const char	*tmp; 

		tmp = krb5_get_error_message(nullctx, ret);
		if (tmp) {
			snprintf(croakstr, sizeof(croakstr), "%s", tmp);
			krb5_free_error_message(nullctx, tmp);
		} else {
			snprintf(croakstr, sizeof(croakstr),
			"unknown error: %ld", (long)ret);
		}
		croak(croakstr);
#else
		croak(error_message($1));
#endif
	}
}

%typemap(out) key {
	key	k;

	/* XXXrcd: clean up the data while I am using it... */

	for (k=$1; k; k = k->next) {
		HV		*hv = newHV();

		EXTEND(sp,1);

		HV_STORE_PVN(hv, (*k), princ);
		HV_STORE_IV(hv, (*k), kvno);
		if (k->timestamp != -1)
			HV_STORE_IV(hv, (*k), timestamp);

		HV_STORE_IV(hv, (*k), enctype);
		HV_STORE_PVN_LEN_F(hv, "key", k->data, k->length);

		$result = sv_2mortal(newRV_noinc((SV*)hv));
		argvi++;
	}
	/* XXXrcd: memory leak. */
}


%typemap(out) krb5_keyblock {
	HV	*hv = newHV();

	HV_STORE_IV_F(hv, "enctype", KEYBLOCK_ENCTYPE($1));
	HV_STORE_PVN_LEN_F(hv, "key", KEYBLOCK_CONTENTS($1),
	    KEYBLOCK_CONTENT_LEN($1));

	$result = sv_2mortal(newRV_noinc((SV*)hv));
	argvi++;
}

%typemap(in) (kadm5_principal_ent_rec, long) {
	krb5_context		  ctx;
	kadm5_principal_ent_rec	  p;
	HV			 *hv;
	SV			**sv;
	long			  mask = 0;
	int			  ret = 0;
	char			 *tmp = NULL;
	char			  croakstr[256] = "";

	/*
	 *
	 */

	if (!SvROK($input))
		croak("Argument $argnum is not a reference.");
	if (SvTYPE(SvRV($input)) != SVt_PVHV)
		croak("Argument $argnum is not a hash ref.");

	K5BAIL(krb5_init_context(&ctx));

	hv = (HV*)SvRV($input);

	HV_FETCH_INTO(hv, tmp, "principal", SvPV_nolen);
	K5BAIL(krb5_parse_name(ctx, tmp, &p.principal));

#define FETCH(key, sm) HV_FETCH_INTO_FULLS(hv,p,key,SvIV,mask|=sm, 0)
	FETCH(attributes,         KADM5_ATTRIBUTES);
	FETCH(max_life,           KADM5_MAX_LIFE);
	FETCH(princ_expire_time,  KADM5_PRINC_EXPIRE_TIME);
	FETCH(pw_expiration,      KADM5_PW_EXPIRATION);
	FETCH(max_renewable_life, KADM5_MAX_RLIFE);
	FETCH(fail_auth_count,    KADM5_FAIL_AUTH_COUNT);
#undef FETCH

	HV_FETCH_FULL(hv, sv, "policy",, 0);
	if (sv && SvOK(*sv)) {
		p.policy = SvPV_nolen(*sv);
		mask |= KADM5_POLICY;
	}
	if (sv && ! SvOK(*sv)) {
		mask |= KADM5_POLICY_CLR;
	}
done:
	if (ret)
		croak("%s", croakstr);

	/*
	 * XXXrcd: &p is about to go out of scope, we can't play fast and
	 *         loose like this.
	 */

	$1 = p;
	$2 = mask;
}

%typemap(out) kadm5_principal_ent_rec {
	krb5_context	 ctx;
	HV		*hv = newHV();
	char		*tmp = NULL;

	krb5_init_context(&ctx);

	krb5_unparse_name(ctx, $1.principal, &tmp);
	HV_STORE_PVN_F(hv, "principal", tmp);
	free(tmp);
	tmp = NULL;

	HV_STORE_IV(hv, $1, princ_expire_time);
	HV_STORE_IV(hv, $1, last_pwd_change);
	HV_STORE_IV(hv, $1, pw_expiration);
	HV_STORE_IV(hv, $1, max_life);

	krb5_unparse_name(ctx, $1.mod_name, &tmp);
	HV_STORE_PVN_F(hv, "mod_name", tmp);
	free(tmp);

	HV_STORE_IV(hv, $1, mod_date);
	HV_STORE_IV(hv, $1, attributes);
	HV_STORE_IV(hv, $1, kvno);
	HV_STORE_IV(hv, $1, mkvno);
	HV_STORE_PVN(hv, $1, policy);
	HV_STORE_IV(hv, $1, aux_attributes);

	/* version 2 fields */

	HV_STORE_IV(hv, $1, max_renewable_life);
	HV_STORE_IV(hv, $1, last_success);
	HV_STORE_IV(hv, $1, last_failed);
	HV_STORE_IV(hv, $1, fail_auth_count);

	/* these are probably useless... */

	HV_STORE_IV(hv, $1, n_key_data);
	HV_STORE_IV(hv, $1, n_tl_data);

	/* these are unimplemented */

//        krb5_int16 n_key_data;
//        krb5_int16 n_tl_data;
//        krb5_tl_data *tl_data;
//        krb5_key_data *key_data;

	$result = sv_2mortal(newRV_noinc((SV*)hv));
	argvi++;
}

%typemap(in) krb5_data * {
	krb5_data	*d;

	d = malloc(sizeof(*d));
	/* XXXrcd: croak if error. */
	d->length = 0;
	d->data = NULL;

	if (SvOK($input))
		d->data = SvPV($input, (d->length));
	$1 = d;
}

%typemap(argout) krb5_data * {
	$result = newSVpvn($1->data, $1->length);
	argvi++;
}

//
//  This typemap allocates a krb5_keytab_entry and fills it with
//  the appropriate information from a Perl hash ref.  The key
//  contents are optional, as some functions do not require them.

%typemap(in) krb5_keytab_entry * {
	HV			 *hv;
	krb5_context		  ctx = NULL;
	krb5_keytab_entry	 *e = NULL;
	krb5_error_code		  ret;
	char			 *tmp;
	char			  croakstr[256] = "";

	if (!SvROK($input) || SvTYPE(SvRV($input)) != SVt_PVHV)
		croak("Argument $argnum is not a hash ref.");

	e = calloc(1, sizeof(*e));
	/* XXXrcd: croak if error. */

	K5BAIL(krb5_init_context(&ctx));

	hv  = (HV*)SvRV($input);
	HV_FETCH_INTO(hv, tmp, "princ", SvPV_nolen);
	K5BAIL(krb5_parse_name(ctx, tmp, &e->principal));
	HV_FETCH_INTO(hv, e->vno, "kvno", SvIV);

	KEYBLOCK_SET_MAGIC(KEYTABENT_KEYBLOCK(*e));
	HV_FETCH_INTO(hv, KEYTABENT_ENCTYPE(*e), "enctype",
	    SvIV);
	HV_FETCH_INTO_STRLEN(hv, KEYTABENT_CONTENTS(*e),
	    KEYTABENT_CONTENT_LEN(*e), "key");

done:
	if (ctx)
		krb5_free_context(ctx);

	if (ret) {
		free(e);
		croak("%s", croakstr);
	}

	$1 = e;
}

%typemap(in) krb5_enctype {
	krb5_enctype		 enctype;
	krb5_error_code		 ret;
	STRLEN			 len;
	char			*tmp;

	tmp = SvPV($input, len);
	ret = STRING_TO_ENCTYPE(tmp, &enctype);
	if (ret)
		enctype = atoi(tmp);

	if (enctype == 0)
		croak("unrecognised enctype \"%s\"", tmp);

	if (!krb5_c_valid_enctype(enctype))
		croak("invalid enctype \"%s\".", tmp);

	$1 = enctype;
}

%typemap(in) krb5_keyblock * {
	HV			 *hv;
	AV			 *av;
	krb5_context		  ctx;
	krb5_keyblock		 *k = NULL;
	krb5_error_code		  ret = 0;
	SV			**sv;
	char			 *tmp;
	STRLEN			  len;
	char			  croakstr[256] = "";
	int			  n_keys;
	int			  i;

	if (!SvROK($input) || SvTYPE(SvRV($input)) != SVt_PVAV)
		croak("Argument $argnum is not an array ref.");

	/* XXXrcd:
	 * We allocate one extra krb5_keyblock and put in a zero'd key
	 * which is how the called functions know the length of the
	 * array...
	 */

	av = (AV*)SvRV($input);
	n_keys = av_len(av) + 1;
	k = calloc(n_keys + 1, sizeof(*k));
	if (!k) {
		ret = errno;
		goto done;
	}

	K5BAIL(krb5_init_context(&ctx));

	for (i=0; i < n_keys; i++) {
		sv = av_fetch(av, i, 0);
		if (!SvROK(*sv) || SvTYPE(hv = (HV *)SvRV(*sv)) != SVt_PVHV)
			croak("Argument $argnum contains a list element %d "
			    "that is not a hash ref.", i);

		KEYBLOCK_SET_MAGIC(k[i]);
		HV_FETCH(hv, sv, "enctype");
		KEYBLOCK_ENCTYPE(k[i])  = SvIV(*sv);
		if (!KEYBLOCK_ENCTYPE(k[i])) {
			tmp = SvPV(*sv, len);
			ret = STRING_TO_ENCTYPE(tmp, &KEYBLOCK_ENCTYPE(k[i]));
			if (ret) {
				snprintf(croakstr, sizeof(croakstr),
				    "invalid enctype \"%s\".", tmp);
				goto done;
			}
			/* XXXrcd: memory leak? */
		}
		if (!krb5_c_valid_enctype(KEYBLOCK_ENCTYPE(k[i])))
			croak("Invalid enctype \"%d\".",
			    KEYBLOCK_ENCTYPE(k[i]));
		HV_FETCH_INTO_STRLEN(hv, KEYBLOCK_CONTENTS(k[i]),
		    KEYBLOCK_CONTENT_LEN(k[i]), "key");
	}

done:
	/* XXXrcd: free ctx.  mondo memory leak... */
	if (ret) {
		free(k);
		croak("%s", croakstr);
	}

	$1 = k;
}

%typemap(in,numinputs=0) krb5_keyblock *OUTPUT (krb5_keyblock tmp) {
	$1 = &tmp;
}
%typemap(argout) krb5_keyblock *OUTPUT {
	HV	*hv = newHV();

	HV_STORE_IV_F(hv, "enctype", KEYBLOCK_ENCTYPE((*$1)));
	HV_STORE_PVN_LEN_F(hv, "key", KEYBLOCK_CONTENTS((*$1)),
	    KEYBLOCK_CONTENT_LEN((*$1)));

	$result = sv_2mortal(newRV_noinc((SV*)hv));
	argvi++;
}

%typemap(in) krb5_principal {
	krb5_error_code	 ret;
	krb5_context	 ctx = NULL;
	STRLEN		 len;
	char		*tmp;
	char		 croakstr[2048] = "";

	tmp = SvPV($input, len);

	ret = krb5_init_context(&ctx);
	if (!ret)
		ret = krb5_parse_name(ctx, tmp, &($1));

	if (ctx)
		krb5_free_context(ctx);
	if (ret) {
#ifdef HAVE_HEIMDAL 
		krb5_context	 nullctx = 0;
		char		 croakstr[2048] = "";
		const char	*tmp; 

		tmp = krb5_get_error_message(nullctx, ret);
		if (tmp) {
			snprintf(croakstr, sizeof(croakstr), "%s", tmp);
			krb5_free_error_message(nullctx, tmp);
		} else {
			snprintf(croakstr, sizeof(croakstr),
			"unknown error: %ld", (long)ret);
		}
		croak(croakstr);
#else
		croak(error_message(ret));
#endif
	}
}

%typemap(in,numinputs=0) krb5_principal * {
	$1 = calloc(sizeof(krb5_principal), 1);
}
%typemap(argout) krb5_principal * {
	krb5_error_code	ret;
	krb5_context	ctx;
	krb5_principal	princ;
	int		i;
	char		croakstr[2048] = "";

	K5BAIL(krb5_init_context(&ctx));

	princ = *($1);

	EXTEND(sp,1);
	$result = sv_2mortal(newSVpvn(PRINC_REALM(ctx, princ),
	    PRINC_REALM_LEN(ctx, princ)));
	argvi++;

	for (i=0; i < PRINC_NCOMPS(ctx, princ); i++) {
		EXTEND(sp,1);
		$result = sv_2mortal(newSVpvn(PRINC_COMP(ctx, princ, i),
		    PRINC_COMP_LEN(ctx, princ, i)));
		argvi++;
	}

done:
	if (ret)
		croak("%s", croakstr);
	krb5_free_principal(ctx, princ);
	free($1);
}

%typemap(in) krb5_creds * {
	HV			 *hv;
	HV			 *hvsession;
	krb5_context		  ctx;
	krb5_creds		 *creds = NULL;
	krb5_error_code		  ret = 0;
	SV			**sv;
	char			 *tmp;
	STRLEN			  len;
	char			  croakstr[256] = "";

	if (!SvROK($input) || SvTYPE(SvRV($input)) != SVt_PVHV)
		croak("Argument $argnum is not a hash ref (krb5_creds).");

	hv = (HV*)SvRV($input);

	K5BAIL(krb5_init_context(&ctx));

	creds = malloc(sizeof(*creds));
	if (!creds) {
		ret = ENOMEM;
		goto done;
	}

	memset(creds, 0x0, sizeof(*creds));

	HV_FETCH_INTO(hv, tmp, "client", SvPV_nolen);
	K5BAIL(krb5_parse_name(ctx, tmp, &creds->client));

	HV_FETCH_INTO(hv, tmp, "server", SvPV_nolen);
	K5BAIL(krb5_parse_name(ctx, tmp, &creds->server));

	HV_FETCH(hv, sv, "keyblock");

	if (!SvROK(*sv) || SvTYPE(SvRV(*sv)) != SVt_PVHV)
		croak("keyblock is not a hash ref (krb5_creds).");

	hvsession = (HV*)SvRV(*sv);

	/* Deal with keyblock (or session in Heimdal) */
	CREDS_KEYBLOCK_SET_MAGIC(*creds);
	HV_FETCH(hvsession, sv, "enctype");
	CREDS_KEYBLOCK_ENCTYPE(*creds) = SvIV(*sv);
	if (!CREDS_KEYBLOCK_ENCTYPE(*creds)) {
		tmp = SvPV(*sv, len);
		ret = STRING_TO_ENCTYPE(tmp, &CREDS_KEYBLOCK_ENCTYPE(*creds));
		if (ret) {
			snprintf(croakstr, sizeof(croakstr),
			    "invalid enctype \"%s\".", tmp);
			goto done;
		}
		/* XXXrcd: memory leak? */
	}

	if (!krb5_c_valid_enctype(CREDS_KEYBLOCK_ENCTYPE(*creds)))
		croak("Invalid enctype \"%d\".",
		    CREDS_KEYBLOCK_ENCTYPE(*creds));

	HV_FETCH_INTO_STRLEN(hvsession, CREDS_KEYBLOCK_CONTENTS(*creds),
	    CREDS_KEYBLOCK_CONTENT_LEN(*creds), "key");

	HV_FETCH_INTO_FULL(hv, creds->times.authtime, "authtime", SvIV,,0);
	HV_FETCH_INTO(hv, creds->times.starttime, "starttime", SvIV);
	HV_FETCH_INTO(hv, creds->times.endtime, "endtime", SvIV);
	HV_FETCH_INTO_FULL(hv, creds->times.renew_till, "renew_till", SvIV,,0);
	HV_FETCH_INTO(hv, CREDS_FLAGS(*creds), "flags", SvIV);

	HV_FETCH_INTO_STRLEN(hv, creds->ticket.data, creds->ticket.length,
	    "ticket");

	/* XXXrcd: Punt on second ticket */
	/* XXXrcd: Punt on authdata */
	/* XXXrcd: Punt on addresses */

done:
	/* XXXrcd: free ctx.  mondo memory leak... */
	if (ret)
		croak("%s", croakstr);

	$1 = creds;
}

%typemap(in) (int, krb5_key_salt_tuple *) {
	krb5_error_code		  ret;
	int			  n_ks_tuple = 0;
	krb5_key_salt_tuple	 *ks_tuple = NULL;
	int			  i;
	AV			 *av;
	SV			**sv;
	char			  errstr[2048];

	if (!SvROK($input) || SvTYPE(SvRV($input)) != SVt_PVAV)
		croak("Argument $argnum is not an array ref.");

	av = (AV*)SvRV($input);
	n_ks_tuple = av_len(av) + 1;
	if (n_ks_tuple > 0)
		ks_tuple = calloc(n_ks_tuple, sizeof(*ks_tuple));

	for (i=0; i < n_ks_tuple; i++) {
		char	*str;

		sv = av_fetch(av, i, 0);
		str = SvPV_nolen(*sv);
		ks_tuple[i].ks_enctype = atoi(str);

		if (!ks_tuple[i].ks_enctype) {
			ret = STRING_TO_ENCTYPE(str, &ks_tuple[i].ks_enctype);
			if (ret) {
				snprintf(errstr, sizeof(errstr),
				    "bad enctype %s", str);
				break;
			}
		}

		ks_tuple[i].ks_salttype = SALTTYPE_NORMAL;
	}

	$1 = n_ks_tuple;
	$2 = ks_tuple;

	if (ret)
		croak("%s", errstr);
}
%typemap(freearg) (int, krb5_key_salt_tuple *) {
	free($2);
}

#ifdef HAVE_HEIMDAL

%typemap(out) krb5_creds * {
	krb5_context	 ctx;
	HV		*hv = newHV();
	HV		*hvsession = newHV();
	krb5_creds	*creds;
	char		*tmp = NULL;
	krb5_error_code	 ret;
	char		 croakstr[256] = "";

	creds = $1;

	K5BAIL(krb5_init_context(&ctx));

	krb5_unparse_name(ctx, creds->client, &tmp);
	HV_STORE_PVN_F(hv, "client", tmp);
	free(tmp);
	tmp = NULL;

	krb5_unparse_name(ctx, creds->server, &tmp);
	HV_STORE_PVN_F(hv, "server", tmp);
	free(tmp);
	tmp = NULL;

	HV_STORE_IV_F(hvsession, "enctype", KEYBLOCK_ENCTYPE(creds->session));
	HV_STORE_PVN_LEN_F(hvsession, "key", KEYBLOCK_CONTENTS(creds->session),
	    KEYBLOCK_CONTENT_LEN(creds->session));

	hv_store(hv, "keyblock", 8, newRV_noinc((SV *)hvsession), 0);

	HV_STORE_IV(hv, (creds->times), authtime);
	HV_STORE_IV(hv, (creds->times), starttime);
	HV_STORE_IV(hv, (creds->times), endtime);
	HV_STORE_IV(hv, (creds->times), renew_till);

	HV_STORE_IV_F(hv, "flags", creds->flags.i);

	HV_STORE_PVN_LEN_F(hv, "ticket", creds->ticket.data,
	    creds->ticket.length);

done:
	/* XXXrcd: free ctx.  mondo memory leak... */
	if (ret)
		croak("%s", croakstr);

	$result = sv_2mortal(newRV_noinc((SV*)hv));
	argvi++;
}
#endif

#if 0
%typemap(out) char ** {
	int i = 0;

	for (i = 0; $1 && $1[i] ; i++) {
		EXTEND(sp,1);
		$result = sv_2mortal(newSVpvn($1[i], strlen($1[i])));
		argvi++;
	}
}
#endif

%typemap(out) char ** {
	AV *myav;
	SV **svs;
	int i = 0,len = 0;

	/* Figure out how many elements we have */
	while ($1 && $1[len])
		len++;
	svs = (SV **) malloc(len*sizeof(SV *));
	for (i = 0; i < len ; i++) {
		svs[i] = sv_newmortal();
		sv_setpv((SV*)svs[i],$1[i]);
	};
	myav =	av_make(len,svs);
	free(svs);
	$result = newRV((SV*)myav);
	sv_2mortal($result);
	argvi++;
}


%include C.h
