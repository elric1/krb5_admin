#!/bin/bash -e


function get_princ {
	opu=$(/usr/sbin/krb5_keytab -$3v $1 2>&1)
	if [[ $? -ne $2 ]] ; then 
		echo $1 " failed"
		echo $opu
		exit 1
	fi
	
	o=$(/opt/heimdal/sbin/ktutil -k /var/spool/keytabs/$(id -un) list | grep $1)
	rc=$?
	if [[ $2 -eq 0 && $rc -eq 0 ]]; then
		echo $1 " success"
		return 0
	fi

	if [[ $2 -ne 0 && $rc -ne 0 ]]; then
		echo $1 " success"
		return 0
	fi
	
	echo $1 " failed" $rc
	exit 2 
}

krb5_admin query_hostmap testcluster.twosigma.com | grep $(uname -n)
krb5_admin principal_map_query $(id -un) testingmapped/testcluster.twosigma.com |grep 0 
krb5_admin principal_map_query $(id -un) HTTP1/$(uname -n) |grep 0 



set +e
code=""

if [[ ! -f /var/spool/keytabs/$(id -un) ]]; then
	code="c"
fi




echo "Allowed, username subdomain"
get_princ "anything/$(id -un).$(uname -n)" 0 $code

echo "Allowed, username service"
get_princ "$(id -un)/$(uname -n)" 0 $code

echo "Allowed, username subdomain"
get_princ "HTTP/$(id -un).$(uname -n)" 0 $code

echo "Not Allowed"
get_princ "HTTP1/$(uname -n)" 1 $code

echo "Not Allowed, not my username subdomain"
get_princ "something/vm7.$(uname -n)" 1 $code 

echo "Allowed, Local service map"
find /etc/krb5/krb5_keytab.service2user.d -type f -print | xargs -exec grep testing
get_princ "testing/$(uname -n)" 0 $code

echo "Not Allowed"
get_princ "testing11/$(uname -n)" 1 $code

echo "Allowed, any granted name on a cluster i'm mapped to"
get_princ "testing/testcluster.twosigma.com" 0 "c" 
krb5_admin query_hostmap testcluster.twosigma.com | grep $(uname -n)
krb5_admin principal_map_query $(id -un) testing/testcluster.twosigma.com |grep 1 

echo "Not allowed, names i'm not mapped to on clusters"
get_princ "testingmapped/testcluster.twosigma.com" 1 $code
krb5_admin query_hostmap testcluster.twosigma.com | grep $(uname -n)
krb5_admin principal_map_query $(id -un) testingmapped/testcluster.twosigma.com |grep 0 


