package Krb5Admin::dbutils;

use Kharon::dbutils qw/sql_command generic_query generic_modify/;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw{ generic_query_union };

use warnings;
use strict;

# Create a union of data from $table1 and $table2
# both tables must have the same schema from tabledesc
# XXX -MSW- at some point clean this up, and add it to Kharon.

sub generic_query_union {
	my ($dbh, $schema, $table1, $table2, $qfields, %query) = @_;

	#
	# XXXrcd: validation should be done.

	my @where;
	my @bindv;

	my $tabledesc = $schema->{$table1};

	my $key_field = $tabledesc->{fields}->[0];
	# my %fields = map { $table1.'.'.$_ => 1 } @{$tabledesc->{fields}};
	my %fields = map {'A.'.$_ => 1 } @{$tabledesc->{fields}};

	my $lists = $tabledesc->{lists};

	my @join;

	for my $l (@$lists) {
		my ($ltable, $kfield, $vfield, $as) = @$l;
		push(@join, "LEFT JOIN $ltable ON " .
		    "A.$key_field = $ltable.$kfield");

		if (defined($as)) {
			$fields{"$ltable.$vfield AS $as"} = 1;
		} else {
			$fields{"$ltable.$vfield"} = 1;
		}

		if (exists($query{$vfield})) {
			my $v = $query{$vfield};
			if (ref($v) eq 'ARRAY') {
				my @tmpwhere;

				for my $i (@$v) {
					push(@tmpwhere, "$ltable.$vfield = ?");
					push(@bindv, $i);
				}

				if (@$v) {
					push(@where, '(' .
					    join(' OR ', @tmpwhere) .
					    ')');
				}
			} else {
				push(@where, "$ltable.$vfield = ?");
				push(@bindv, $v);
			}

			delete $query{$vfield};
		}
	}

	my @errfields;
	for my $field (keys %query) {
		if (!exists($fields{'A.'.$field})) {
			push(@errfields, $field);
			next;
		}

		push(@where, "A.$field = ?");
		push(@bindv, $query{$field});
	}

	if (@errfields) {
		die [500, "Fields: " . join(',', @errfields) .
		    " do not exist in $table1 table"];
	}

	# XXXrcd: BROKEN! BROKEN! must deal with $ltable...
	for my $field (@$qfields) {
		delete $fields{'A.'.$field};
	}

	my $join = join(' ', @join);

	my $where = join( ' AND ', @where );
	$where = "WHERE $where" if length($where) > 0;

	my $fields;
	my $stmt = '';
	if (scalar(keys %fields) > 0) {
		my %tmp_fields = %fields;

		$tmp_fields{'A.'.$key_field} = 1;
		$fields = join(',', keys %tmp_fields);
		$stmt = "SELECT $fields FROM $table1 AS A " .
		    "$join $where UNION SELECT $fields " .
		    "FROM $table2 AS A $join $where";
	} else {
		$fields = "COUNT($key_field)";
		$stmt = "SELECT ( SELECT $fields FROM $table1 AS A " .
		    "$join $where) + " .
		    "(SELECT $fields FROM $table2 AS A $join $where) " .
		    "AS total";
	}

	my $sth = sql_command($dbh, $stmt, @bindv, @bindv);

	#
	# We now reformat the result to be comprised of the simplest
	# data structure we can imagine that represents the query
	# results:

	if (scalar(keys %fields) == 0) {
		return $sth->fetch()->[0];
	}

	my $results = $sth->fetchall_arrayref({});

	my $ret;
	if (scalar(keys %fields) == 1 && $tabledesc->{wontgrow}) {
		$fields = join('', keys %fields);
		$fields =~ s/^[^.]*\.//o;
		for my $result (@$results) {
			push(@$ret, $result->{$fields});
		}

		return $ret;
	}

	my $is_uniq = grep {$key_field eq $_} @{$tabledesc->{uniq}};

	my $single_result = 0;
	if (scalar(keys %fields) == 2 && $tabledesc->{wontgrow}) {
		$single_result = 1;
	}

	for my $result (@$results) {
		my $key = $result->{$key_field};

		delete $result->{$key_field};

		if ($single_result) {
			my $result_key = join('', keys %$result);
			$result = $result->{$result_key};
		}

		if ($is_uniq) {
			merge_result($lists, \$ret, $key, $result);
		} else {
			push(@{$ret->{$key}}, $result);
		}
	}

	if ($is_uniq) {
		$ret = finalise_result($lists, $ret);
	}

	if ($is_uniq && grep {$key_field eq $_} (@$qfields)) {
		#
		# this should mean that we get only a single
		# element in our resultant hashref.

		return $ret->{$query{$key_field}};
	}

	return $ret;
}

1;
