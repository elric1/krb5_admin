package Krb5Admin::Krb5Host::Keytabs;

use DBI;
use Data::Dumper;

use Krb5Admin::C;
use Kharon::dbutils qw/sql_exec generic_query/;

use strict;
use warnings;

my %field_desc = (
	generator_keys => {
		pkey	=> [qw/name kvno enctype/],
		uniq	=> [qw//],
		fields	=> [qw/name kvno enctype key/],
	},
	keytabs => {
		pkey	=> [qw/path/],
		uniq	=> [qw/path/],
		fields	=> [qw/path uid/],
		lists	=> [[qw/keys keytab princ/]],
	},
	keys => {
		pkey	=> [qw/princ keytab/],
		uniq	=> [qw//],
		fields	=> [qw/princ keytab/],
		lists	=> [[qw/princs princ generator/]],
	},
);

our %fl_opts = (
	ctx		=> undef,
	sqldbname	=> '/var/spool/keytabs/.ktabs',
	dbh		=> undef,
);

sub new {
	my ($proto, %args) = @_;
	my $class = ref($proto) || $proto;

	my $self = { %fl_opts };

	bless($self, $class);

	$self->set_opt(%args);

	if (!defined($self->{dbh})) {
		$self->connect_sqlite();
	}

	return $self;
}

sub connect_sqlite {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	my $init = 0;

	return if defined($dbh);

	$init = 1 if !-f $self->{sqldbname};

	my $oldmask = umask(0077);
	$dbh = DBI->connect("dbi:SQLite:$self->{sqldbname}", "", "",
	    {RaiseError => 1, PrintError => 0, AutoCommit => 1,
	    sqlite_use_immediate_transaction => 1});
	die "Could not open database " . DBI::errstr if !defined($dbh);
	$dbh->do("PRAGMA foreign_keys = ON");
	$dbh->do("PRAGMA journal_mode = WAL");

	$self->{dbh} = $dbh;
	$self->init_db() if $init;
	umask($oldmask);
}

sub internal_set_opt {
	my ($self, $opt, $val) = @_;

	die "Unrecognised option: $opt.\n" if !exists($fl_opts{$opt});

	if (!defined($val)) {
		$self->{$opt} = $fl_opts{$opt};
		return;
	}

	if (defined($fl_opts{$opt}) && ref($fl_opts{$opt}) ne ref($val)) {
		die "Option $opt must be of type " . ref($fl_opts{$opt}) .
		    " but is of type " . ref($val) . "\n";
	}

	$self->{$opt} = $val;
}

sub set_opt {
	my ($self, %opts) = @_;

	for my $opt (keys %opts) {
		$self->internal_set_opt($opt, $opts{$opt});
	}
}

sub init_db {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	sql_exec($dbh, q{
		CREATE TABLE IF NOT EXISTS generators (
			name		VARCHAR NOT NULL,

			PRIMARY KEY(name)
				ON CONFLICT REPLACE
		)
	});

	sql_exec($dbh, q{
		CREATE TABLE IF NOT EXISTS generator_keys (
			name		VARCHAR NOT NULL,
			kvno		INTEGER NOT NULL,
			enctype		INTEGER NOT NULL,
			key		BLOB NOT NULL,

			PRIMARY KEY (name, kvno, enctype)
				ON CONFLICT REPLACE
			FOREIGN KEY (name) REFERENCES generators(name)
		)
	});

	sql_exec($dbh, q{
		CREATE TABLE IF NOT EXISTS keytabs (
			path		VARCHAR PRIMARY KEY,
			uid		INTEGER NOT NULL
		)
	});

	sql_exec($dbh, q{
		CREATE TABLE IF NOT EXISTS princs (
			princ		VARCHAR NOT NULL,
			generator	VARCHAR NOT NULL,

			PRIMARY KEY (princ)
				ON CONFLICT REPLACE
			FOREIGN KEY (generator) REFERENCES generators(name)
		)
	});

	sql_exec($dbh, q{
		CREATE TABLE IF NOT EXISTS keys (
			keytab		VARCHAR NOT NULL,
			princ		VARCHAR NOT NULL,

			PRIMARY KEY (keytab, princ)
				ON CONFLICT REPLACE
			FOREIGN KEY (keytab)	REFERENCES keytabs(path)
			FOREIGN KEY (princ)	REFERENCES princs(princ)
		)
	});
}

sub mk_generator {
	my ($self, $name, $key) = @_;
	my $dbh = $self->{dbh};

	eval {
		sql_exec($dbh, q{
		    INSERT INTO generators (name)
		      VALUES (?)
		}, $name);

		sql_exec($dbh, q{
		    INSERT INTO generator_keys (name, kvno, enctype, key)
		      VALUES (?,?,?,?)
		}, $name, $key->{kvno}, $key->{enctype}, $key->{key});
	};
	die $@ if $@;	# XXXrcd: more later...

	return;
}

sub rm_generator {
	my ($self, $name, $kvno, $enctype) = @_;
	my $dbh = $self->{dbh};

	#
	# XXXrcd: should we eliminate the generator itself?
	#         maybe cascading?  Etc.

	sql_exec($dbh, q{
	    DELETE FROM generator_keys
	      WHERE name = ? AND kvno = ? AND enctype = ?
	}, $name, $kvno, $enctype);

	return;
}

sub discover_generator {
	my ($self, $princ) = @_;
	my $dbh = $self->{dbh};

	#
	# XXXrcd: this is likely not optimal, we should optimise it.

	my $ctx = Krb5Admin::C::krb5_init_context();
	my ($realm, $service, $fqdn) =
	    Krb5Admin::C::krb5_parse_name($ctx, $princ);
	my @parts = split(/\./, $fqdn);

	my @wheres;
	push(@wheres, $princ);
	while (@parts > 0) {
		push(@wheres, join('.', @parts) . '@' . $realm);
		shift(@parts);
	}

	my $stmt = q{SELECT name FROM generators WHERE };

	$stmt .= join(' OR ', map {"name = ?"} @wheres);

	my $sth = sql_exec($dbh, $stmt, @wheres);
	my $result =$sth->fetchall_arrayref([]);

	my $ret;
	for my $g (@{$result}) {
		if (!defined($ret) || length($g->[0]) > length($ret)) {
			$ret = $g->[0];
		}
	}

	return $ret;
}

sub list_generators {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	my $ret = generic_query($dbh, \%field_desc, 'generator_keys');

	#
	# Eliminate key material from the output:

	for my $g (keys %$ret) {
		for my $k (@{$ret->{$g}}) {
			delete $k->{key};
		}
	}

	return $ret;
}

sub mk_keytab {
	my ($self, $path, $uid) = @_;
	my $dbh = $self->{dbh};

	eval {
		sql_exec($dbh, q{
		    INSERT INTO keytabs (path, uid) VALUES (?,?)
		}, $path, $uid);
	};

	if ($@) {
		if ($@ =~ m{UNIQUE constraint failed}) {
			my $kt = $self->query_keytab($path)->[0];
			return if $kt->{uid} == $uid;
			die "Can't change the UID of existing keytab " .
			    "\"$path\": from $kt->{uid} to $uid\n";
		}
		die $@;
	}

	return;
}

sub rm_keytab {
	my ($self, $path) = @_;
	my $dbh = $self->{dbh};

	sql_exec($dbh, q{
	    DELETE FROM keytabs WHERE path = ?
	}, $path);

	return;
}

sub query_keytab {
	my ($self, $path) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'keytabs', ['path'], path => $path);
}

sub list_keytabs {
	my ($self, @path) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'keytabs');
}

sub add_key {
	my ($self, $keytab, $princ) = @_;
	my $dbh = $self->{dbh};

	my $generator = $self->discover_generator($princ);
	if (!defined($generator)) {
		die [500, "Can't find a generator for $princ.\n"];
	}

	sql_exec($dbh, q{
	    INSERT INTO princs (princ, generator) VALUES (?,?)
	}, $princ, $generator);

	sql_exec($dbh, q{
	    INSERT INTO keys (keytab, princ) VALUES (?,?)
	}, $keytab, $princ);

	return;
}

sub rm_key {
	my ($self, $keytab, $princ) = @_;
	my $dbh = $self->{dbh};

	sql_exec($dbh, q{
	    DELETE FROM keys WHERE keytab = ? AND princ = ?
	}, $keytab, $princ);
}

sub list_keys {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'keys');
}

sub hashify_it {
	my ($ctx, $princ, $h) = @_;
	my $tmp;

	$h->{princ} = $princ;
	$tmp = Krb5Admin::C::krb5_derive_namespace_key($ctx,
	    $princ, $h->{enctype}, [$h]);

	$h->{key} = $tmp->{key};
	return $h;
}

sub get_full_keys_for_princ {
	my ($self, $princ) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	my $sth = sql_exec($dbh, q{
		SELECT kvno, enctype, key FROM generator_keys
		JOIN princs ON princs.generator = generator_keys.name
		WHERE princs.princ = ?
	}, $princ);

	my $keys = $sth->fetchall_arrayref({});

	return [map { hashify_it($ctx, $princ, $_) } @$keys];

}

1;
