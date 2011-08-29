#!/usr/bin/perl
#
#	blacklist.pl
#
# Modified by:	green-ponies / jgen <jgen.tech@gmail.com>
# Date:		July/Aug 2011
# Version:		0.1
# License:		GNU GPL
#
# This is a modified version of "sshblack.pl Version 2.8.1" (See http://www.sshblack.com),
# which itself was based on mailmgr (c) 2003, Julian Haight, released under the GNU GPL.
#
# The original script is licensed under a "GNU General Public License" license.
# Available at:  http://www.gnu.org/licenses/gpl.txt
# This script is modified according to the terms and conditions of the GNU GPL.
#
# The main modification to this script is the addition of a config file, which allows
# specific settings to be contained in a file for each log to monitor.
#
#	Warning:
#	----------
#
#	This script needs ROOT ACCESS as it is modifiying iptables !
#	The config file for this script should be writeable by ROOT ONLY!
#
#	Otherwise, you have a huge potential for security problems!
#
# -------------------------------------------------------
#   ORIGINAL DESCRIPTION OF SSHBLACK:
# -------------------------------------------------------
# This is a script which tails the security log file and dynamically blocks
# connections from hosts which meet certain criteria, using
# command-line kernel-level firewall configuration tools provided by
# the operating system (specifically, iptables).
# If you prefer to use something other than iptables, you can have
# the script execute any command for blocking and unblocking hosts by
# modifying $ADDRULE and $DELRULE.  Please see the sshblack homepage
# for many examples.
# As the script is modifying iptables, it will need root access.
#
# Note: this script can also be modified to monitor ANY log file
# including apache (web) logs and sendmail (mail) logs.  The
# aggressiveness can be adjusted by setting the variables in the
# first few lines.  It will probably work well right out of the box.
#
# Setup:  You need to create the initial chain that ssh-black will work with.
##      For iptables, you would do this:
# iptables -N BLACKLIST
##      This creates a new chain called BLACKLIST
##      Then you would do this:
# iptables -A INPUT -p tcp -m tcp --dport 22 --syn -j BLACKLIST
##      Send all TCP port 22 packets through the chain.  We will be adding
##      DROP jumps to this chain with the program below. Note this example
##      command uses the add (-A) command which will place the new rule at
##      the END of the INPUT chain.  Move it as necessary or use the
##      insert (-I) command instead.
##
#
# If you have the DAEMONIZE variable set below, you can run the script by
# simply typing the filename from the command prompt. If you clear the
# DAEMONIZE variable, you will need to place it in the background manually
# or let it run from the console prompt.
# -------------------------------------------------------

# Load required modules
use strict;
use warnings;
use Socket;
use Getopt::Std;
use Config::Std;

#############################################
# Begin

$|=1;	# Turn Output Buffering OFF

# Get the command line options
my %options;
getopt('c:', \%options );

# Check if a config file was given
if (exists($options{'c'}) && $options{'c'}) {
	print 'Using config file: ' . $options{'c'} ."\n";
} else {
	die('No config file specified. Quiting.');
}

# Make sure file exists and is readable
if ( !( -e $options{'c'} ) || !( -r $options{'c'} ) ) {
	die('The config file is either missing, or unaccessable.  (File: '.$options{'c'}.')'); }
# Check if file is 0 bytes
if (-z $options{'c'}) {
	die('The config file is empty [0 bytes].  (File: '.$options{'c'}.')'); }
# Check if file is a link
if (-l $options{'c'}) {
	die('The config file given is a link.  (File: '.$options{'c'}.')'); }

if ((stat($options{'c'}))[7] > 4024 ) {
	die ('The config file is too large. I don\'t feel safe opening it. (size > 4 kB)'."\n"); }


# Load config file into hash.
read_config $options{'c'} => my %config;


##############################################################################

my($OCT) = '(?:25[012345]|2[0-4]\d|1?\d\d?)';
my($IP_PATTERN) = $config{'log'}{'ip_prefix'}.'('. $OCT . '\.' . $OCT . '\.' . $OCT . '\.' . $OCT .')';

if ( $config{'main'}{'daemonize'} ) {
	# Fork off a daemon (replaces Proc::Daemon::Init;)
	my($pid);
	if ( defined( $pid = fork() ) ) {
		# This is the Parent (original, to be exited)
		if ( $pid ) {
			exit 0;
		}
		# This is the Child (daemon, keep running)
		else {
		      # Send STDOUT and STDERR to LOGFILE
		      open (STDOUT, '>>'.$config{'main'}{'output_log'}) or die('failed to open STDOUT');
		      open (STDERR, ">&STDOUT") or die('Failed to open STDERR');
		}
	} else {
		# Something went wrong attempting to fork: bail out
		die 'Unable to fork: '.$!;
	}
}

logit('Blacklist is Starting...','1','0');

# Poor man's touch command
open (TOUCH, '>> '.$config{'main'}{'cache'} ); close (TOUCH);

# Start the monitoring
taillog();

sub taillog {
	my($offset, $name, $line, $ip, $reason, $stall, $ind, $doscount) = '';
	my (@loser, @buildlist) = ();

	# Save the size of the logfile in bytes in $offset.
	$offset = (-s $config{'log'}{'logfile'}); # Don't start at beginning, go to end

	logit('Monitoring the log file for future attacks.',$config{'main'}{'verbose'},'0');

	# Infinite Loop
	while (1) {
		sleep(1);		# Sleep for 1 second.
		$| = 1;			# Turn Output Buffering OFF
		$stall += 1;

		if ((-s $config{'log'}{'logfile'}) < $offset) {
			logit('Log shrunk, resetting...','1','0') ;
			$offset = 0;
		}
		open(TAIL, $config{'log'}{'logfile'}) || print STDERR 'Error opening '.$config{'log'}{'logfile'}.': '.$!."\n";

		if (seek(TAIL, $offset, 0)) {
			# found offset, log not rotated
		} else {
			# log reset, follow
			$offset=0;
			seek(TAIL, $offset, 0);
		}

		# Read in all newly added lines from the logfile.
		while ($line = <TAIL>) {
			chomp($line);	# remove newline from the end.

			# Check if we have a match
			if (($config{'log'}{'reasons'} ne "") && ($line =~ m/$config{'log'}{'reasons'}/)) {
				$reason = $1;
				if ($line =~ m/$IP_PATTERN/g) {
					$ip = $1;

					logit('Watching '.$ip.' as potential attacker',$config{'main'}{'verbose'},'0');

					open(LIST, $config{'main'}{'cache'}) || print STDERR 'Error opening '.$config{'main'}{'cache'}.': '.$!."\n";
					$ind = 0;
					@buildlist = <LIST>;
					foreach $line(@buildlist) {
						@loser = split(/,/, $line);
						# [0] is IP, [1] is time, [2] is hits
						if ($loser[0] eq $ip) {
							# Already listed, increase count
							$loser[2] += 1;

							if ($loser[2] >= $config{'log'}{'maxhits'}) {
								# See ya!
								logit($ip.' being blocked because of '.$reason, '1', $config{'main'}{'email_notify'});
								blockIp($ip);
								$loser[2] += 1; # Avoid double listings (???)
							}
							$line = join(',', @loser); # put back together for saving
							$line .= "\n";
							$buildlist[$ind] = $line;
							$ip = 'logged';
						} # End if already listed
						$ind += 1;
					} # End foreach read
					 
					close (LIST);

					if ($ip ne 'logged') {
						# IP was not found in the Cache file, Thus, New IP address. Add it to the Cache file.
						$line = $ip . ',' . time() . ',' . 1 . "\n";
						push (@buildlist, $line);
					}
					
					# Update the cache file, save the list to the file.
					open (LIST, '>'.$config{'main'}{'cache'}) || print STDERR 'Error opening '.$config{'main'}{'cache'}.': '.$!."\n";
					print LIST @buildlist;
					close (LIST);
				} # End if IP
				next;
			} # End if match reasons
		} # End while read line
		$offset=tell(TAIL);
		close(TAIL);

		if ($stall >= $config{'log'}{'cleanup'}) {
			# Time to do cleanup. At period config{'log'}{'cleanup'} we look at all listings from the
			# database to see if they are a) blacklisted and have served their time
			# which is set by config{'log'}{'release_days'} or b) not blacklisted but have not hit
			# with MAXHITS in the past AGEOUT seconds or c) not blacklisted and have
			# not been in the database for AGEOUT seconds.  If we find either condition
			# (a) or (b) we remove them from the database and (if required) remove
			# them from the iptables blacklist.

			$stall = 0; # Clear out cleanup timer
			$doscount = 0; # Clear the denial-of-service counter
			@buildlist = ();
			open(LIST, $config{'main'}{'cache'}) || print STDERR 'Error opening '.$config{'main'}{'cache'}.': '.$!."\n";
			while ($line = <LIST>) {
				$doscount += 1;
				@loser = split(/,/, $line);
				# [0] is IP, [1] is time, [2] is hits
				if ($loser[2] >= $config{'log'}{'maxhits'}) {
					# already blacklisted
					if (($loser[1] + $config{'log'}{'release_sec'}) > time()) {
						# have not served their time on the blacklist
						push (@buildlist, $line);
					} else {
						freeIp($loser[0]);
						logit('Freeing '.$loser[0], $config{'main'}{'verbose'}, $config{'main'}{'email_notify'});
					} #set free after $config{'log'}{'release_days'}
					
				} elsif (($loser[1] + $config{'log'}{'ageout_sec'}) > time()) {
					# Not listed and not aged out
					push (@buildlist, $line);
				}
				# If we have more than DOSBAIL listings, we are probably
				# under denial of service attack.  Hibernate so we don't
				# fill up the iptables chain or route table.
				if ($doscount > $config{'log'}{'dosbail'}) {
					logit('Possible DOS attack. Sleeping.','1',$config{'main'}{'email_notify'});
					sleep(86400);	# sleep for 1 day (24 hours)
				}
			} # End while reading
			close (LIST);
			# open for writing
			open (LIST, '>'.$config{'main'}{'cache'}) || print STDERR 'Error opening '.$config{'main'}{'cache'}.': '.$!."\n";
			print LIST @buildlist;
			close (LIST);
			@buildlist = ();
		} # End cleanup check

	} # End while endless loop
} # End sub taillog

#################################################
sub blockIp
{
	# This subroutine executes the actual command that does the blacklisting
	# action.  It first checks for a whitelisted host/network.  If the attacking
	# IP address is not in the whitelist, the literal string 'ipaddress' in the
	# $config{'iptables'}{'add_rule'} string is replaced with the IP address of the attacker and the command
	# is executed.
	my($ip) = @_;
	my($rule) = $config{'iptables'}{'add_rule'};

	if ($ip =~ m/$config{'main'}{'whitelist'}/) {
		logit('Whitelisted host at '.$ip.' -- NOT BLACKLISTING','1','0');
		return;
	}

	$rule =~ s/ipaddress/$ip/;

	system($rule);	# This is very unsafe. $rule is executed as the same user that this script runs as. In most cases, this is ROOT!

	return;
} # End sub blockIp

#############################################
sub freeIp
{
	# This subroutine removes an attacker from the blacklist.  The literal string
	# 'ipaddress' in the "$config{'iptables'}{'del_rule'}" string is replaced with the IP address of the attacker
	# and the command is executed.
	my($ip) = @_;
	my($rule) = $config{'iptables'}{'del_rule'};

	$rule =~ s/ipaddress/$ip/;

	system($rule);	# This is very unsafe. $rule is executed as the same user that this script runs as. In most cases, this is ROOT!

	return;
} # End sub freeIp

#############################################
sub logit
{
	# Pass the following into logit:
	#     Text of message to be logged
	#     Output is to be printed in all cases-verbose (1) or not-brief (0)
	#     Message to be emailed to administrator (1) or not (0)
	my ($message, $chatty, $mailme) = @_;
	my ($notify_address) = $config{'main'}{'email_to'};

	if ($chatty) {
		print STDOUT '[', scalar localtime, ']  ', $message, "\n";
	}

	if ($mailme) {
		# This should be configurable based on where/what mail program is used.
		system('mail -s "'.$message.'" "'.$notify_address.'" < /dev/null >/dev/null 2>&1');
	}
	return;
}  # End sub logit

#
# End sshblack.pl
