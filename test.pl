#!/usr/bin/perl

##
# test suite for Htpasswd
# Steve Purkis <spurkis@engsoc.carleton.ca>
# August 8, 1998
##

BEGIN {
	$| = 1;
	print "1..17\n";
	sub ok  { $i++; print "ok $i\n"; }
	sub nok { $i++; print "not ok $i\n"; }
}
END { print "Fatal: I couldn't load Htpasswd!\n" unless $loaded; }

$file = 'test.htp';
$newpass = rand(10);


{ # test oo side
	use Htpasswd;
	$loaded = 1;
	ok;						#1

	unless ($htp = new Htpasswd( File => $file )) {
		nok;
		die "Fatal error: could not create Htpasswd object!\n";
	}
	ok;						#2
	$htp->add('test', 'test') ? ok : nok;		#3
	$htp->add('test', 'test2') ? nok : ok;		#4
	$htp->check('test', 'test') ? ok : nok;		#5
	$htp->mod('test', $newpass) ? ok : nok;		#6
	$htp->check('test', $newpass) ? ok : nok;	#7
	$htp->check('test', 'test') ? nok : ok;		#8
	$htp->del('test') ? ok : nok;			#9
	$htp->save() ? ok : nok;			#10
}

{ # test non-oo side
	use Htpasswd qw( ht_add ht_check ht_mod ht_del );

	ht_add($file, 'test', 'test') ? ok : nok;	#11
	ht_add($file, 'test', 'test2') ? nok : ok;	#12
	ht_check($file, 'test', 'test') ? ok : nok;	#13
	ht_mod($file, 'test', $newpass) ? ok : nok;	#14
	ht_check($file, 'test', $newpass) ? ok : nok;	#15
	ht_check($file, 'test', 'test') ? nok : ok;	#16
	ht_del($file, 'test') ? ok : nok;		#17
}

unlink $file;
