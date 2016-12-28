#!/usr/bin/env perl

package Local::DataLocker;

use strict;
use warnings;

use Digest::SHA qw(sha256_base64);
use LWP::UserAgent;
use File::Path qw(make_path);
use File::Basename qw(fileparse);
use File::Touch qw(touch);
use DateTime;
use URI::URL;
use Proc::ProcessTable;
use List::Util qw(first);
use Log::Log4perl;

my $BASE_DIR;
my $DEBUG = 1;

Log::Log4perl->init($BASE_DIR . "/.logconf");
my $logger = Log::Log4perl->get_logger(__PACKAGE__);

# Given a string of content data, return a path (as a list) that provides a
# filename-safe base64 encoded SHA256 digest of the content, with two levels
# of hashed directories based on the first four characters of the digest.
sub build_store_path {
    my $data = shift;

    my $digest = sha256_base64($data);
    $digest =~ tr:+/:-_:;  # Make the base64 digest filename-safe

    my $dir1 = substr($digest, 0, 2); # First two chars of digest
    my $dir2 = substr($digest, 2, 2); # Third and fourth chars of digest

    return ($dir1, $dir2, $digest);
}

# Just a wrapper for make_path that lops off the filename first, then creates
# all the directories, if needed.
sub make_path_for_file {
    my $fn = shift;

    my ($basename, $path, undef) = fileparse($fn);
    make_path($path);
}

# For given input content, calculate the SHA digest filename, store it there,
# and return the filename.
sub store_content {
    my $content = shift;

    my @path = build_store_path($content);

    # Build the name of the output file and then make sure it exist.
    my $outpath = join("/", $BASE_DIR, '.store', @path);
    make_path_for_file($outpath);

    # We may have already stored this content, but it may have gotten
    # corrupted.  Since we already have the data, and we're not worried about
    # IO write operations, we just write it out anyway, possibly overwriting
    # the old data with the same content.
    open OUTPATH, ">$outpath" 
        or die "Cannot open file $outpath for write: $!\n";
    print OUTPATH $content;
    close OUTPATH;

    return $outpath;
}

# Given a URL, return a path (including $BASE_DIR) that includes the hostname
# and the file name.
sub source_base_path {
    my $url = shift;

    my $urlobj = URI::URL->new($url);
    my $host = $urlobj->host;
    my $fn = ($urlobj->path_components)[-1];

    return join('/', $BASE_DIR, $host, $fn);
}

# For a given URL, return a path to the file that stores the last modified
# data.
sub lastmod_file {
    my $url = shift;
    
    return source_base_path($url) . '/'  . '.last_modified';
}

# Build text for the if-modified-since header
sub if_modified_since_header {
    my $url = shift;

    my $lastmod_file = lastmod_file($url);
    if (-r $lastmod_file) {
        my $mtime = DateTime->from_epoch(epoch => (stat($lastmod_file))[9]);
        return $mtime->strftime("%a, %d %h %Y %T GMT");
    } else {
        return '';
    }
}

# Create a link in the source/datetime hierarchy
sub make_source_datetime_link {
    my $storepath = shift;
    my $url = shift;
    my $time = shift || DateTime->now(); 

    my $link_path = source_base_path($url) . '/' . 
        $time->strftime('%Y/%h/%d/%H%M%S');

    make_path_for_file($link_path);
    link $storepath, $link_path
        or die "Cannot make link from $storepath to $link_path: $!\n";
}

# Just touch the lastmod file for the given url
sub touch_lastmod {
    my $url = shift;

    my $lastmod = lastmod_file($url);
    touch($lastmod) 
        or die "Cannot touch last modified file $lastmod; $!\n";
}

sub lock_file_path {
    my $url = shift;

    return source_base_path($url) . '/' . '.lock';
}

# Attempt to lock the URL. Return 1 if successful, 0 otherwise.
sub lock_url {
    my $url = shift;

    my $lockfile = lock_file_path($url);
    make_path_for_file($lockfile);

    if ( -r $lockfile ) {
        # The lockfile exists. Let's get the PID from the lockfile.
        open LF, $lockfile;
        my $lockpid = <LF>;
        close LF;
        chomp $lockpid;

        # Now check the process table to see if that PID actually exists.
        my $proctable = Proc::ProcessTable->new();
        my $proc = first { $_->pid == $lockpid } @{$proctable->table};
        if ($proc and $proc->cmndline =~ /datalocker/) {
            # There's an active process still working on this. How long has it
            # been running?
            my $lock_mtime = DateTime->from_epoch(
                epoch => (stat($lockfile))[9]);
            if (DateTime->now()->subtract( minutes => 3 ) < $lock_mtime) {
                # The PID in the lockfile is young enough that work may still
                # be going on.  Refuse the lock.
                $logger->debug("Lock on $lockfile by $$ failed -- " .
                               "file locked by $lockpid\n");
                return 0;
            } else {
                # The old lock is more than three minutes old. Kill it and
                # relock.
                kill 'STOP', $lockpid;
            }
        }
    }

    # If we made it this far, we've decided that the lock either doesn't exist
    # or is stale. Grab it.
    open LF, ">$lockfile"
        or die "Cannot open lock file $lockfile for write: $!\n";
    print LF "$$\n";
    close LF;
    return 1;
    
}

# Unlock the URL. Make sure that it's our lock before we remove it.
sub unlock_url {
    my $url = shift;

    my $lockfile = lock_file_path($url);

    if ( ! -r $lockfile ) {
        $logger->debug("Unlock on $lockfile by PID $$ failed " .
                       "because lockfile was already removed.\n");
        return;
    }

    open LF, $lockfile
        or die "Cannot open lock file $lockfile for read: $!\n";
    my $lockpid = <LF>;
    close LF;
    chomp $lockpid;

    if ( $lockpid == $$ ) {
        unlink $lockfile;
        return;
    } else {
        $logger->debug("Unlock on $lockfile by PID $$ failed " .
                       "because someone else has the lock!\n");
        return;
    }
}

# Walk through the URL list and update each one.
sub update_url_list {
    foreach (@_) {
        my $url = $_;
        $logger->debug("Working on url = $url\n");

        if (lock_url($url)) {
            my $ua = LWP::UserAgent->new( keep_alive => 10 );
            my $response = $ua->get(
                $url, 'If-Modified-Since' => if_modified_since_header($url));
            if ($response->code == 304) {
                $logger->info(
                    "URL $url has not been modified since last fetch: " .
                    $response->status_line . "\n");
            } elsif ($response->is_error) {
                $logger->info("URL $url returned an error: ".
                              $response->status_line . "\n");
            } else { 
                my $storepath = store_content($response->content);
                make_source_datetime_link($storepath, $url);
                touch_lastmod($url);
            }
            unlock_url($url);
        }
    }
}

sub run {
    $BASE_DIR = $ARGV[0] || '/tmp/datalocker';

    my $urlfile = $BASE_DIR . '/.urllist';
    open URLFILE, $urlfile
        or die "Cannot open URL list $urlfile: $!\n";

    foreach my $url (<URLFILE>) {
        chomp $url;
        $url =~ s/#.*$//; # Allow comments in file
        update_url_list($url) if $url;
    }
}

__PACKAGE__->run( @_ ) unless caller();

1;
