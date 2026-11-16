#!/usr/bin/env perl
use strict;
use warnings;

# Count suspicious log events without displaying or persisting the secrets.
sub summary {
    my ($input) = @_;
    my %counts = (credential_exposure => 0, failed_auth => 0);
    while (my $line = <$input>) {
        $counts{credential_exposure}++ if
            $line =~ /\b(?:api[_-]?key|access[_-]?token|password)\s*[:=]\s*\S+/i;
        $counts{failed_auth}++ if
            $line =~ /\b(?:authentication failed|invalid credentials|login denied)\b/i;
    }
    return \%counts;
}

unless (caller) {
    my $file = shift @ARGV or die "Usage: perl scan_logs.pl logfile\n";
    open my $input, '<', $file or die "Cannot open specified log file: $!\n";
    my $result = summary($input);
    close $input;
    print "credential_exposure=$result->{credential_exposure}\n";
    print "failed_auth=$result->{failed_auth}\n";
}
1;
