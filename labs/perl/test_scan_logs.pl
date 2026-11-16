use strict;
use warnings;
use Test::More tests => 3;
require './labs/perl/scan_logs.pl';

my $logs = "INFO ready\nWARN password=secret-value\nERROR authentication failed\n";
open my $stream, '<', \$logs or die $!;
my $result = summary($stream);
is($result->{credential_exposure}, 1, 'secret exposure counted');
is($result->{failed_auth}, 1, 'failed login counted');
ok(!exists $result->{secret}, 'secrets are not stored in summary');
