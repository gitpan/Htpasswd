#!/usr/bin/perl5

##
# Access to htpasswd-format password files (same as /etc/passwd).
# Steve Purkis <spurkis@engsoc.carleton.ca>
# August 8, 1998
##

package Htpasswd;

require Exporter;
use vars qw( @ISA @EXPORT_OK $VERSION $Debug );

@ISA = qw( Exporter );
$VERSION = 0.1;
@EXPORT_OK = qw( ht_add ht_del ht_mod ht_check );
#$Debug = 1;

##
# OO functions
##

sub new {
	my ($class, %args) = @_;
	my $self = {};

	$self->{File} = delete $args{File} or return;
	%{$self->{HTP}} = _parse_htp($self->{File});

	bless $self, $class;
}

sub add {
	my ($self, $user, $passwd) = @_;
	my %htp = %{$self->{HTP}};

	# make sure user doesn't already exist:
	if (exists($htp{$user})) {
		warn "$user already exists!\n" if $Debug;
		return ();
	}

	# add the new user:
	$htp{$user} = _crypt($passwd);
	%{$self->{HTP}} = %htp;
}

sub del {
	my ($self, $user) = @_;
	my %htp = %{$self->{HTP}};
	delete $htp{$user} or return;
	%{$self->{HTP}} = %htp;
	1;	# incase all entries deleted
}

sub mod {
	my ($self, $user, $newpasswd) = @_;
	my %htp = %{$self->{HTP}};
	$htp{$user} = _crypt($newpasswd);
	%{$self->{HTP}} = %htp;
}

sub check {
	my ($self, $user, $passwd) = @_;
	my %htp = %{$self->{HTP}};
	return _check_pwd($htp{$user}, $passwd);
}

sub save {
	my $self = shift;
	return _save_htp($self->{File}, %{$self->{HTP}});
}

##
# Export-ok functions
##

sub ht_add {
	my ($pwdfile, $user, $passwd) = @_;

	my %htp = _parse_htp($pwdfile);

	# make sure user doesn't already exist:
	if (exists($htp{$user})) {
		warn "$user already exists!\n" if $Debug;
		return ();
	}

	# add the new user:
	$htp{$user} = _crypt($passwd);
	return _save_htp($pwdfile, %htp);
}

sub ht_del {
	my ($pwdfile, $user) = @_;
	my %htp = _parse_htp($pwdfile);
	delete $htp{$user} or return;
	return _save_htp($pwdfile, %htp);
}

sub ht_mod {
	my ($pwdfile, $user, $newpasswd) = @_;
	my %htp = _parse_htp($pwdfile);
	$htp{$user} = _crypt($newpasswd);
	return _save_htp($pwdfile, %htp);
}

sub ht_check {
	my ($pwdfile, $user, $passwd) = @_;
	my %htp = _parse_htp($pwdfile);
	return _check_pwd($htp{$user}, $passwd);
}

##
# Internal functions:
##

sub _parse_htp {
	my $file = shift;
	my %users;

	open (HTP, $file) or return;
	for (<HTP>) {
		chomp;
		my ($user, $passwd) = split(/\:/, $_) or next;
		$users{$user} = $passwd;
	}
	close HTP;
	return %users;
}

sub _check_pwd {
	my ($crypt_pwd, $txt_pwd) = @_;
	my $salt = substr($crypt_pwd, 0, 2);
	my $passwd = crypt($txt_pwd, $salt);
	if ($passwd eq $crypt_pwd) { return 1; }
	return ();
}

sub _crypt {
	my $passwd = shift;
	# choose a random number as salt:
	my $rand = rand(10);
	my $salt = substr($rand, 2, 2);
	return crypt($passwd, $salt);
}

sub _save_htp {
	my ($file, %htp) = @_;

	unless (open (HTP, "> $file")) {
		warn "error saving file $file!\n";
		return;
	}
	foreach (keys(%htp)) {
		print HTP $_ . ':' . $htp{$_} . "\n";
	}
	close HTP;
}

1;

__END__

=head1 NAME

Htpasswd - access to unix-type passwords for web access.


=head1 SYNOPSIS

  # for non-oo use:
  use Htpasswd qw(ht_add ht_del ht_mod ht_check);

  ht_add( $file, $user, $passwd );
  ht_check( $file, $user, $passwd );
  ht_mod( $file, $user, $newpasswd );
  ht_del( $file, $user );

  # oo use: not yet available

=head1 DESCRIPTION

This is an interface to Unix-style password files for web access (ie:
Apache).  It allows the programmer to add/delete/modify/check passwords.
It was originally created for use in conjunction with .htaccess files.

=head1 SUBROUTINES

=over 4

All subroutines return boolean values.

=back

=head1 TODO

=over 4

Object oriented subs.

=back

=head1 AUTHOR

Steve Purkis <spurkis@engsoc.carleton.ca>

=head1 COPYRIGHT

Copyright (c) 1997 Steve Purkis. All rights reserved. This program is free
software; you can redistribute it and/or modify it under the same terms as
Perl itself.

=head1 SEE ALSO

I<http://www.apache.org/docs/misc/FAQ.html> for instructions on how
to use .htaccess files.

=cut
