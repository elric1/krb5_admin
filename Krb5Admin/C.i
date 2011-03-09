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
									\
		HV_FETCH(hv, __hv_f_sv, rhs);				\
		lhs_str = SvPV(*__hv_f_sv, lhs_len);			\
	} while (0)

#define HV_STORE_INTERNAL_F(hv, key, sv) 				\
	hv_store((hv), (key), strlen((key)), sv, 0)

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
		croak(error_message($1));
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

		HV_STORE_IV(hv, (*k).key, enctype);
		HV_STORE_PVN_LEN_F(hv, "key", (*k).key.contents,
		    (*k).key.length);

		$result = sv_2mortal(newRV_noinc((SV*)hv));
		argvi++;
	}
	/* XXXrcd: memory leak. */
}


%typemap(out) krb5_keyblock {
	HV	*hv = newHV();

	HV_STORE_IV(hv, $1, enctype);
	HV_STORE_PVN_LEN_F(hv, "key", $1.contents, $1.length);

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
		croak(croakstr);

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
	krb5_context		  ctx;
	krb5_keytab_entry	 *e = NULL;
	krb5_error_code		  ret;
	char			 *tmp;
	char			  croakstr[256];

	if (!SvROK($input) || SvTYPE(SvRV($input)) != SVt_PVHV)
		croak("Argument $argnum is not a hash ref.");

	e = calloc(1, sizeof(*e));
	/* XXXrcd: croak if error. */

	K5BAIL(krb5_init_context(&ctx));

        hv  = (HV*)SvRV($input);
	HV_FETCH_INTO(hv, tmp, "princ", SvPV_nolen);
	K5BAIL(krb5_parse_name(ctx, tmp, &e->principal));
	HV_FETCH_INTO(hv, e->vno, "kvno", SvIV);

	e->key.magic    = KV5M_KEYBLOCK;
	HV_FETCH_INTO(hv, e->key.enctype, "enctype", SvIV);
	HV_FETCH_INTO_STRLEN(hv, e->key.contents, e->key.length, "key");

done:
	/* XXXrcd: free ctx */
	if (ret) {
		free(e);
		croak("%s", croakstr);
	}

	$1 = e;
}

%typemap(in) krb5_enctype {
	krb5_enctype		 enctype;
	krb5_error_code		 ret = 0;
	STRLEN			 len;
	char			*tmp;

	tmp = SvPV($input, len);
	ret = krb5_string_to_enctype(tmp, &enctype);
	if (ret)
		enctype = atoi(tmp);

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
	char			  croakstr[256];
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

		k[i].magic = KV5M_KEYBLOCK;
		HV_FETCH(hv, sv, "enctype");
		k[i].enctype  = SvIV(*sv);
		if (!k[i].enctype) {
			tmp = SvPV(*sv, len);
			ret = krb5_string_to_enctype(tmp, &k[i].enctype);
			if (ret) {
				snprintf(croakstr, sizeof(croakstr),
				    "invalid enctype \"%s\".", tmp);
				goto done;
			}
			/* XXXrcd: memory leak? */
		}
		if (!krb5_c_valid_enctype(k[i].enctype))
			croak("Invalid enctype \"%d\".", k[i].enctype);
		HV_FETCH_INTO_STRLEN(hv, k[i].contents, k[i].length, "key");
	}

done:
	/* XXXrcd: free ctx.  mondo memory leak... */
	if (ret) {
		free(k);
		croak("%s", croakstr);
	}

	$1 = k;
}

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
	while ($1[len])
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
