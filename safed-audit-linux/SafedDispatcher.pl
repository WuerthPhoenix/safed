#!/usr/bin/perl
#
# SAFED AUDIT for Linux
# Author: Wuerth-Phoenix s.r.l.,
#  made starting from:
# Snare Audit Dispatcher for Linux
# (c) Copyright 2010 InterSect Alliance Pty Ltd
#
# This application will integrate into the native linux audit subsystem,
# and translate linux auditd log format data into something that can be
# parsed appropriately by apps that prefer one-line-per-event, such as the
# Snare audit daemon (for delivery to the Snare Server), or logwatch.
#
# INSTALLATION:
#
#	* Run the MakeTranslationTable program
#	  (optional, but highly recommended)
#         It will create /etc/safed-xlate.conf
#	* Copy SafedDispatchHelper to /usr/sbin/SafedDispatchHelper
#	* Save this file to /usr/sbin/SafedDispatcher.pl
#	* Add the following line to your /etc/auditd.conf file:
#		dispatcher = /usr/sbin/SafedDispatchHelper
#
# Issues:
#	* a0, a1, a2, a3 are practically useless, as string arguments are not
#	  supported. execve's are a particular problem.
#	* It is programatically difficult to determine how many 'lines' make
#         up an audit event. Some lines can be repeated, with slightly
#         different values.
#       * You can have multiple, identical tokens for an event (eg: two path=)
#	  we handle this by appending a count (after a colon).
#	* Event lines may be interleaved (ie: you might get two lines from
#	  event # 1000, then one line from event # 1001, then another line
#         from event # 1000).
#	* Some filename characters are translated into their HEX equivalents
#         which will make matching filenames difficult.
#           if (char == '"' || char < 0x21 || char > 0x7f)
#

use POSIX qw(strftime);
use Socket;
use Sys::Syslog qw ( :DEFAULT setlogsock );
use Digest::MD5 qw(md5 md5_hex);
use MIME::Base64;
use File::Basename;
use Fcntl;


use constant SUCCESS => 1;
use constant FAILURE => 2;

use constant WATCH => 1;
use constant NEWWATCH => 2;
use constant IGNORE => 3;

##LOG LEVEL
$DEBUG=0;
############# User Configurable options.

$CONFIGFILE="/etc/safed/safed.conf";

# Note: These two values can be configured using the config file.

# Should we care about the criticality?
# If not, no worries - we can return as soon as we find a single match,
# which will speed things up a little.
$USECRITICALITY=0;

# Should we manage the audit configuration? Or do we leave it to the native audit subsystem?
$MANAGEAUDIT=1;


# Should we use watches instead of system-wide syscalls?
$USEWATCH=1;


# Where are we sending events?
$SYSLOGDEST=0;

############# End user configurable options.

$VERSION="1.6.0";

$CONTINUE=1;

# Open our translation table.
$rc=open(XLATE,"/etc/safed-xlate.conf");
if($rc) {
	while($line=<XLATE>) {
		chomp($line);
		($num,$scall)=split(/:/,$line);
		$syscall{$num}=$scall;
		$nsyscall{$scall}=$num;
	}
	$syscall{-1}="login_auth";
	$syscall{-2}="login_start";
	$syscall{-3}="logout";
	$syscall{-4}="acct_mgmt";
	close(XLATE);
}


# Declare a UID/GID cache so we don't wind up getting into recursive
# audit event generation.
my %uidcache=();
my %unamecache=();
my %gidcache=();

# Event cache
%event=();

# Global filters array
%Filters=();
$FilterCount=0;
$WatchCount=0;
%WatchVal=();
%WatchExtra=();


$FQDN=`hostname --fqdn`;
chomp($FQDN);
$FQDN = "UNKNOWN" if ($FQDN eq "");

# Set up some select() related variables.
$rin = '';
vec($rin,fileno(STDIN),1) = 1;

LoadConfig() or exit;

# Set up our audit configuration based on our objectives.
SetAudit();

# Trap a few signals
$SIG{USR1}='Restart';
$SIG{PIPE}='Handler';
$SIG{CHLD}='IGNORE';
$SIG{HUP}='Handler';
$SIG{INT}='Handler';
$SIG{QUIT}='IGNORE';
$SIG{TERM}='Handler';

LogMsg("Safed Auditing for Linux $VERSION: Started and active.");



# Main reader loop.
while($CONTINUE>=1) {
	$nfound=select($rout=$rin,undef,undef,1);
	if($nfound > 0) {
		# Grab the version number
		$bytes=sysread(STDIN,$header,16);
		if($bytes==0) {
			if ($DEBUG) { LogMsg("DEBUG: Failed to get header\n"); }
			$CONTINUE=0;
			last;
		} elsif ($bytes==undef) {
			# Probably interrupted by a signal
			next;
		}

		# Eventtype 1302 = PATH
		# Eventtype 1300 = SYSCALL
		# Eventtype 1307 = CWD
		($eventtype,$contentsize,$eventnum,$datetime)=unpack("IIII",$header);
		# 8k sanity check. Hopefully, we'll resynchronise.
		if($contentsize > 0 && $contentsize < 16384) {
			sysread(STDIN,$line,$contentsize);
		} else {
			if($DEBUG) { LogMsg("Content is $contentsize! Discarding"); }
			sysread(STDIN,$line,$contentsize);
			next;
		}
	} else {
		$CONTINUE++ if ($CONTINUE);
		if($DEBUG>1) { LogMsg("NO DATA (timeout)! $CONTINUE"); }
		next;
	}


#DMM
	#SendEvent("LinuxTEST","$line\n");
	#print $OUTFILE "$line\n";
	#next;
	#chomp;
	if($DEBUG>=2) { LogMsg("\nLINE: $line"); }

	if($DEBUG>1) { LogMsg("datetime: $datetime eventnum: $eventnum tail: $line"); }

	if($datetime==0 || !$line || !$eventnum) {
		# Not interested
		next;
	}

	if($DEBUG>1) { LogMsg("DATE TIME = $datetime EVENTID = $eventnum eventtype = $eventtype"); }


	# Lets split this line up into element/content pairs.
	# First, lets check for msg strings and strip them out (to deal with them later)
	# msg is the only string that contains spaces
	if ($line =~ /msg='/) {
		if ($line =~ /(.* )msg='(.*?)'(.*)/) {		# Make gedit pretty: '
			$msg = $2;
			$line = $1.$3;
		}
	}
	if($DEBUG>=2) { LogMsg("LINE(-msg): $line"); }
	# Next, break apart by spaces that aren't inside inverted commas.
	#@elements=split(/\s+(?=(?:[^"]*"[^"]*")*[^"]*\z)/,$line);  # comment helper """
	@elements=split(/\s+/,$line);  # comment helper """
	#DMM - for encoded text
	# $txt =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg
	%event=();
	if($DEBUG>=2) { LogMsg("Elements contains " . @elements . " elements"); }
	foreach (@elements) {
		# Then, by the equals sign.
		($key,$val)=split(/=/,$_,2);
		next if ($val =~ /^$/);
		$val =~ s/"//g;		# Make gedit pretty: "
		#$val =~ s/^"(.*)"$/$1/;
		$count=0;
#			#push(@{$event{$key}},$val);//slighly slower
		while(defined($event{$key . ($count==0?"":":$count")})) {
			$count++;
		}
		$event{$key . ($count==0?"":":$count")}=$val;
		if($DEBUG>=4) { LogMsg("ASSIGN: $key:$count = $val"); }
	}
	# Now, do the same thing for the msg string, but add a few special clauses
	# Strip out any brackets
	# structure: msg='(messge|key=val): (message|key=val) \((key=val[, ]*)*\)'
	if (defined $msg) {
		if($DEBUG>=4) { LogMsg("MESSAGE: $msg"); }
		undef $key;
		#split the message again
		($hdr,$tail,$null) = split(/\((.*?)\)/,$msg);  # comment helper """
		if($DEBUG>=4) { LogMsg("MESSAGE HDR: $hdr"); }
		if($DEBUG>=4) { LogMsg("MESSAGE HDR: $tail"); }
		@elements=split(/[,]?[:\s]+(?=(?:[^"]*"[^"]*")*[^"]*\z)/,$hdr);  # comment helper """
		@elements2=split(/,?\s(?=(?:[^"]*"[^"]*")*[^"]*\z)/,$tail);  # comment helper """
		if($DEBUG>=2) { LogMsg("Elements contains " . @elements . " elements"); }
		if($DEBUG>=2) { LogMsg("Elements2 contains " . @elements2 . " elements"); }
		foreach $element (@elements, @elements2) {
			if($element=~/=/) {
				# Then, by the equals sign.
				($key,$val)=split(/=/,$element,2);
				$val =~ s/^"//;		# Make gedit pretty: "
				$val =~ s/"$//;		# Make gedit pretty: "
				$count=0;
				while(defined($event{$key . ($count==0?"":":$count")})) {
					$count++;
				}

				$event{$key . ($count==0?"":":$count")}=$val;
				#$event{$key}=$val;
				if($DEBUG>=4) { LogMsg("ASSIGN: $key.$count = $val"); }
			} else {
				if (!defined($key)) {
					$key = "msg";
					$event{$key} = $element;
					next;
				}
				# add the term to the previous key
				$event{$key . ($count==0?"":":$count")} .= " $element";
				if($DEBUG>=4) { LogMsg("ASSIGN: $key.$count = $element"); }
			}
		}
		undef $msg;
	}

	# Ok, we now have an array of key/value pairs.

	#always use the audit datetime
	@ltime=localtime($datetime);
	$sdatetime=strftime("%Y%m%d %T",@ltime);
	$event{"datetime"}=$sdatetime;

	# Eventtype 1302 = "PATH"
	# Eventtype 1300 = SYSCALL
	# Eventtype 1112 = "USER_LOGIN"
	# This should tell us when the end of a record comes through.
	if($eventtype == 1300) {
		# We have all the data we need! Send this event out the door.
		if($DEBUG>1) { LogMsg("Sending out Event $eventnum"); }
		PrepEvent();
	} elsif($eventtype == 1112 || $eventtype == 1100 || $eventtype == 1105 || $eventtype == 1106 || $eventtype == 1108) {
#1112,1100,1105 - authentication
#1106 - USER_END
#1108 - USER_CHAUTHTOK
#1104 - ??
		if($DEBUG>1) { LogMsg("User Login event detected, formatting and sending"); }
		if($DEBUG>1) { LogMsg("Sending out Event $eventnum"); }
		# set up some of the missing variables
		$event{"gid"}=0;
		$event{"exit"}=0;
		if (defined($event{"terminal"})) {
			$event{"comm"}=$event{"terminal"};
		} else {
			$event{"comm"}="-";
		}
		$event{"success"} = "no";
		if (defined($event{"res"}) && $event{"res"} =~ /success/i) {
			$event{"success"} = "yes";
		} elsif (defined($event{"result"}) && $event{"result"} =~ /Success/i) {
			$event{"success"} = "yes";
		} elsif (!defined($event{"res"}) && !defined($event{"result"}) && $event{"msg"} !~ /fail/i) {
			$event{"success"} = "yes";
		} else {
			$event{"success"} = "no";
		}
		# login/logout specifics
		if ($eventtype == 1106) {
			#USER_END
			$event{"syscall"}=-3;
		} elsif ($eventtype == 1108) {
			# USER_CHAUTHTOK
			$event{"syscall"}=-4;
		} else {
			#USER_AUTH, USER_START
			if ($eventtype == 1105) {
				$event{"syscall"}=-2;
			} else {
				$event{"syscall"}=-1;
			}
		}
		if (!defined($event{"msg"})) {
			$event{"msg"} = $event{"op"};
		} else {
			$event{"msg"} .= " " . $event{"op"};
		}
		delete $event{"op"};
		delete $event{"res"};
		PrepEvent();
	}
	undef $event;
}

if ($DEBUG) { LogMsg("DEBUG: Exit requested\n"); }

# disable audit
if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -e 0"); }
`/sbin/auditctl -e 0`;


# Flush our buffers
CloseOutputs();

exit;

#first transform pices of message in safed format (!!!!) then checkes if it match and prepares the message to send 
sub PrepEvent {
	# If we are sent a particular event number, flush it out.
		#if($DEBUG) { LogMsg("DEBUG: Eventnum is $eventnum"); }

	# If the event doesn't satisfy the basic requirements, dump it
	if(!defined($event{"syscall"}) ||
	   !defined($event{"datetime"}) ||
	   !defined($event{"uid"}) ||
	   !defined($event{"gid"}) ||
	   !defined($event{"pid"}) ||
	   !defined($event{"comm"}) ||
	   !defined($event{"exit"}) ||
	   !defined($event{"success"})) {
		if($DEBUG) {
			LogMsg(":::::::: Event does not contain all required data");
			@elements=keys %event;
			@values=values %event;
			LogMsg(":::::::: [@elements] [@values]");
		}

		return;
	}


	# Lets construct a token/data array in the order we wish to send things out, with
	# appropriate data extrapolated.
	my %tokens=();
	my @tokenlist=();

	$syscallname=$syscall{$event{"syscall"}};
	if(!$syscallname) {
		# Fall back to the number.
		$syscallname=$event{"syscall"};
	}
	delete $event{"syscall"};
	$tokens{"event"}="$syscallname," . $event{"datetime"};
	push(@tokenlist,"event");
	delete $event{"datetime"};
	if ($event{"uid"} == -1) {
		$uidname=$event{"acct"};
	} else {
		$uidname=getuid($event{"uid"});
	}
	$tokens{"uid"}=$event{"uid"} . ($uidname?",$uidname":"");
	push(@tokenlist,"uid");
	delete $event{"uid"};
	if (defined($event{"id"})) {
		$idname=getuid($event{"id"},($syscallname eq "acct_mgmt"?1:0));
		if (!defined($event{"acct"})) {
			$event{"acct"} = $idname;
		}
	}
	$tokens{"id"}=$event{"id"} . ($idname?",$idname":"");
	push(@tokenlist,"id");
	delete $event{"id"};
	$gidname=getgid($event{"gid"});
	$tokens{"gid"}=$event{"gid"} . ($uidname?",$gidname":"");
	push(@tokenlist,"gid");
	delete $event{"gid"};
	$euidname=getuid($event{"euid"});
	$tokens{"euid"}=$event{"euid"} . ($uidname?",$euidname":"");
	push(@tokenlist,"euid");
	delete $event{"euid"};
	$egidname=getgid($event{"egid"});
	$tokens{"egid"}=$event{"egid"} . ($uidname?",$egidname":"");
	push(@tokenlist,"egid");
	delete $event{"egid"};
	$tokens{"process"}=$event{"pid"} . "," . $event{"comm"};
	push(@tokenlist,"process");
	delete $event{"pid"};
	delete $event{"comm"};
	$tokens{"return"}=$event{"exit"} . "," . $event{"success"};
	push(@tokenlist,"return");
	delete $event{"exit"};
	delete $event{"success"};


	foreach $key (sort keys %event) {
		# Resolve names
		if($key =~ /^[eosa]uid(:[0-9]+)*$/ || $key =~ /^fsuid(:[0-9]+)*$/) {
			$eventstring = $event{$key};
			$name=getuid($event{$key});
			if($name) {
				$eventstring .= ",$name";
			}
		} elsif($key =~ /^[eosa]gid(:[0-9]+)*$/ || $key =~ /^fsgid(:[0-9]+)*$/) {
			$eventstring = $event{$key};
			$name=getgid($event{$key});
			if($name) {
				$eventstring .= ",$name";
			}
		} elsif($key =~ /^name(:[0-9]+)*$/ || $key =~ /^exe(:[0-9]+)*$/) {
			$tpath=$event{$key};
			#DMM - for encoded text
			# $txt =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg
			if($tpath =~ /^\// || !$event{"cwd"}) {
				$path = resolve_path($tpath);
			} else {
				$path = resolve_path($event{"cwd"} . "/" . $tpath);
			}
			$eventstring = $path;
		} else {
			$eventstring = $event{$key};
		}
		$tokens{$key}=$eventstring;
		push(@tokenlist,$key);
	}

	# Format of the filters:
	#$Filters{$ObjectiveCount}{$key}{$keymatch}{$ElementCount}{$AlternativeCount}=$alternative;
	#$Filters{0}{event}{0}{0}{0}="execve";
	$EventMatched=0;
	$EventCrit=0;
	FilterLOOP: for ($objectivecount=0; $objectivecount < $FilterCount;$objectivecount++) {
		$ObjectiveMatch=0;
		if($DEBUG>=3) { LogMsg("LOOP: objcount $objectivecount\n"); }
		foreach $key (keys(%{$Filters{$objectivecount}})) {
			if($DEBUG>=3) { LogMsg("LOOP: key $key\n"); }
			if($tokens{$key}) {
				foreach $keymatch (keys(%{$Filters{$objectivecount}{$key}})) {
					if($DEBUG>=3) { LogMsg("LOOP: keymatch $keymatch\n"); }
					foreach $elementcount (keys(%{$Filters{$objectivecount}{$key}{$keymatch}})) {
						if($DEBUG>=3) { LogMsg("LOOP: elementcount $elementcount\n"); }
						$result=0;
						foreach $alternativecount (keys(%{$Filters{$objectivecount}{$key}{$keymatch}{$elementcount}})) {
							if($DEBUG>=3) { LogMsg("LOOP: altcount $alternativecount\n"); }
							$match=$Filters{$objectivecount}{$key}{$keymatch}{$elementcount}{$alternativecount};
							$element=$tokens{$key};
							$negate=$FilterTypes{$objectivecount}{$key}{$keymatch};
							if($DEBUG>=2) { LogMsg("Match element $element against $match (negate is $negate)\n"); }

							# Special case:
							if($match eq "*") {
								$result=1;
							} else {
									
									if($DEBUG>1) { LogMsg("Match: $match against " . $element); }
									if($element =~ /$match/) {
										$result=!$negate;
									} else {
										$result=$negate;
									}
									
									
							}
							#if($result && !$negate || !$result && $negate) {}
							if($result) {
								# Yay - one of the alternatives matched
								if($DEBUG>1) { LogMsg("BREAKING out (result is $result, negate is $negate)"); }
								last;
							}else {
								if($DEBUG>1) { LogMsg("Match: No Match! (negate is $negate)"); }
							}
						}
						if($result) {
							$ObjectiveMatch=1;
						} else {
							$ObjectiveMatch=0;
							next FilterLOOP;
						}
					}
				}
			} else {
				# No token in this event that matches? Drop it.
				$ObjectiveMatch=0;
			}
		}

		if($ObjectiveMatch) {
			if ($Criticality[$objectivecount] < 0) {
				if($DEBUG>= 2) { LogMsg("BREAKING out, event should be ignored"); }
				return;
			}
			$EventMatched=1;
			# if you catch any new files, watch them too
			#if ($tokens{"event"} =~ /^open,/ && $tokens{"name"} !~ /\/$tokens{"watch"}$/) {
				#LogMsg(" TOKENS: " . $tokens{"watch"} . ":" . $tokens{"name"});
			#}
			#watch event relative to NEWWATCH dirs will have filterkey=dir  and name=pathname passed as argument to open (create new file)
			#when a file is created in a watched dir an event is trigered with ame=pathname passed as argument to open
			#if the watched dir is in NEWWATCH (filterkey=dir) then ad a watch on the fly to the created file!!!
			if ($tokens{"filterkey"} eq "dir" && $tokens{"name"} !~ /\/$tokens{"watch"}$/) {
				if ($tokens{"name"} && not defined $WatchExtra{$tokens{"name"}}) {
					ExtraWatch($tokens{"name"}, WATCH);
					$WatchExtra{$tokens{"name"}}=1;
				}
			}

			if($USECRITICALITY) {
				$tcrit=$Criticality[$objectivecount];
				if($tcrit > $EventCrit) {
					$EventCrit=$tcrit;
				}
			} else {
				$EventCrit=$Criticality[$objectivecount];
				last;
			}
		}
	}

	#check if it is a watch
	if(!$EventMatched){
		if(defined $tokens{"watch"} && defined $tokens{"name"} && $tokens{"name"} =~ /$tokens{"watch"}$/){
			$currentname=$tokens{"name"};
			$currentcwd="";
			if(defined $tokens{"cwd"}){
				$currentcwd=$tokens{"cwd"};
			}
			for ($watchcnt=0; $watchcnt < $WatchCount;$watchcnt++){
				$currentflag=$WatchVal{$watchcnt}{"flag"};
				$currentpath=$WatchVal{$watchcnt}{"path"};
				if($DEBUG>= 2) { LogMsg("CHECK WATCH: $currentcwd:$currentname against $currentpath:$currentflag"); }
				if($currentflag == WATCH){
					if((-d $currentpath) && ( $currentname  =~ /^$currentpath/)){
						$EventMatched=1;
						if($DEBUG>1) { LogMsg("FOUND WATCH3: $currentpath"); }
						last;						
					}elsif(-f $currentpath && ($currentpath eq $currentname )){
						$EventMatched=1;
						if($DEBUG>1) { LogMsg("FOUND WATCH2: $currentpath"); }
						last;			
					}
					
				}elsif($currentflag == NEWWATCH && ($currentname  =~ /^$currentpath/) ){
					$EventMatched=1;
					if($DEBUG>1) { LogMsg("FOUND WATCH1: $currentpath"); }
					last;					
				}
			}			
			if(!$EventMatched && ( defined $WatchExtra{$currentname})){
				$EventMatched=1;
				if($DEBUG>1) { LogMsg("FOUND WATCH0: $currentname"); }
			}			
		}
		
	}

	if(!$EventMatched) {
		# Ok, go to the next objective.
		# We're not interested in this one.
		return;
	}

	# Craft our tokens into a single string.
	$sendstring="criticality,$EventCrit";

	foreach $key (@tokenlist) {
		$sendstring .= "	$key,".$tokens{$key};
	}

	# Send this out.
	if($DEBUG) { LogMsg("OUTPUT: " . $sendstring); }

	SendEvent("$FQDN	LinuxKAudit","$sendstring\n");
}

sub SendEvent() {
	my($prefix,$string)=@_;
	my $original_string="$prefix\t$string";
	$success=0;
	if (defined $OUTPUTFILE) {
		print $OUTPUTFILE "$prefix\t$string";
		$success=1;
	}
}

sub CloseOutputs() {
	if(defined $OUTPUTFILE) {
		close($OUTPUTFILE);
	}
	undef $OUTPUTFILE;

}

sub LoadConfig() {
	@Criticality=();
	@Filters=();
	@FilterTypes=();
	%WatchVal=();
	%WatchExtra=();
	$WatchCount=0;

	$rc=open(CONFIG,"$CONFIGFILE");
	if(!$rc) {
		LogMsg("Cannot open Safed Configuration File! Exiting.");
		return(0);
	}
	$section="Unknown";
	$ObjectiveCount=0;

	LINE: while($line=<CONFIG>) {
		chomp($line);
		if($line =~ /^[ \t]*#/ || $line =~ /^[ \t#]*$/) {
			# Ignore
			next;
		} elsif ($line =~ /^[ \t]*\[[a-zA-Z]+\]/) {
			($null,$section)=split(/[\[\]]/,$line);
			$section =~ tr/a-z/A-Z/;
		} else {
			$line =~ s/^[ \t]+//;
			$line =~ s/[ \t]+/\t/g;
			$line =~ s/[ \t]+$//;

			if($DEBUG) { LogMsg("Config File: Loaded line $line\n"); }

			if($section eq "OUTPUT") {
				# Add this into our output file array
				if(!defined $OUTPUTFILE){
					$rc=OpenOutput("file=/tmp/safedpipe");
				}
				if($key eq "SYSLOG") {
					$SYSLOGDEST=$val;
				}elsif($key eq "SET_AUDIT") {
					$MANAGEAUDIT=$val;
				} 				
			} elsif($section eq "LOG") {
				if($key eq "LOGLEVEL") {
					$DEBUG=$val;
				}				
			} elsif($section eq "WATCH") {
				@elements=split(/\t/,$line);
				
				$path="";
				foreach $element(@elements) {
					($key,$check,$val)=split(/([\!~]?=)/,$element);
					if($key eq "path") {
						# paths must be absolute
						if($val !~ /^\//) {
							LogMsg("Watch only allows absolute paths, ignoring [$val]");
							next LINE;
						}
						$path = resolve_path($val);
						# make sure the path is valid and not the root dir (/)
						if ($path !~ /^\/$/) {
							# check if we should watch or ignore a given path
							if ($check eq "=" || $check eq "~=") {
								# watches need a valid path
								if (-e $path) {
									$WatchVal{$WatchCount}{"path"} = $path;
									LogMsg("WATCH for $path match $check");									
									if ($check eq "~=") {
										$WatchVal{$WatchCount}{"flag"} = NEWWATCH;
									} else {
										$WatchVal{$WatchCount}{"flag"} = WATCH;
									}
								} else {
									LogMsg("WATCH requires a valid path, ignoring [$val]");
									#$WatchVal{$path} = WATCH;
									next LINE;
								}
							} else {
								# ignore can be any value, just strip out backslash and double quotes
								$path =~ s/\\"//g;
								$WatchVal{$WatchCount}{"path"} = $path;
								$WatchVal{$WatchCount}{"flag"} = IGNORE;
							}
						} else {
							LogMsg("WATCH requires a valid path that is not /, ignoring [$val]");
							next LINE;
						}
					} else {
						LogMsg("Invalid keyword \"$key\" found in [Watch]");
					}
				}
				$WatchCount++;
			} elsif($section eq "AOBJECTIVES") {
				# Default value.
				$TEMPObjectiveCount = $ObjectiveCount;
				$Criticality[$TEMPObjectiveCount]=0;

				if (($line =~ /match=\(\*\)/) || ($line =~ /match!=\(\*\)/)){
					#from match=(*)  to ""
					$line =~ s/match=\(\*\)//;
					$line =~ s/match!=\(\*\)//;							
				}
				if (($line =~ /match=/) || ($line =~ /match!=/)){
					#from match=(exe=/bin/pwd cmd=ls)  to exe=/bin/pwd cmd=ls
					$line =~ s/match=\(//;
					$line =~ s/match!=\(//;
					$line =~ s/\)$//;												
				}
				if (($line =~ /user=\(\*\)/) || ($line =~ /user!=\(\*\)/)){
					#from user=(*)  to ""
					$line =~ s/user=\(\*\)//;
					$line =~ s/user!=\(\*\)//;							
				}

				if (($line =~ /user=/) || ($line =~ /user!=/)){
					#from user to uid
					$line =~ s/user=/uid=/;
					$line =~ s/user!=/uid!=/;							
				}
				
				if($key eq "user"){
					$key = "uid";
				}
				if (($line =~ /return=\(\*\)/) || ($line =~ /return!=\(\*\)/)){
					#from return=(*)  to ""
					$line =~ s/return=\(\*\)//;
					$line =~ s/return!=\(\*\)//;							
				}
				#from return=(Success/Failure)  to return=(yes/no)
				$line =~ s/return=\(?Success\)?/return=\(yes\)/;
				$line =~ s/return=\(?Failure\)?/return=\(no\)/;							
	
				while($line =~ /\t\t/){
					#from \t\t  to \t
					$line =~ s/\t\t/\t/;
				}
				

				LogMsg("INFO: $line\n");
				@elements=split(/\t/,$line);
				%OPEN_EVENTS=('open' => 1,'creat' => 1,'link' => 1,'symlink' => 1,'truncate' => 1,'ftruncate' => 1,'mknod' => 1,'rename' => 1,'truncate64' => 1,'ftruncate64' => 1,'access' => 1);


				
				foreach $element (@elements) {
					($key,$check,$val)=split(/(\!*=)/,$element);
					#substitute user with uid
					
					if($key eq "watch") {
						# ignore, these no longer belong here
						LogMsg("Please move all watches to [watch]");
						next;
					}
					if($key eq "criticality" && $val ne "") {
						$Criticality[$TEMPObjectiveCount]=$val;
						next;
					}

					@components=();
					@tcomponents=split(/,/,$val);
					while(@tcomponents) {
						#take a copy of tcomponents in case the brackets are invalid
						@temp_tc = @tcomponents;
						$component=shift(@tcomponents);
						if($component =~ /^\(/) {
					#LogMsg("DMM: check comp (:$component");
							while($component !~ /\)$/ && @tcomponents) {
								$component .= "," . shift(@tcomponents);
							}
							if ($component !~ /\)$/) {
								#bad use of brackets
								LogMsg("WARNING: Removing unmatched bracket");
								@tcomponents = @temp_tc;
								$component=shift(@tcomponents);
							}
							$component =~ s/^\(//;
							$component =~ s/\)$//;
						}
						#LogMsg("Put $component to components");
						push(@components,$component);
					}
						
					#if exe=\/sbin\/auditctl exe!=\/usr\/bin\/tail=> Adding \/sbin\/auditctl to 0:exe:0:0:0 and Adding \/usr\/bin\/tail to 0:exe:1:0:0 => number of times the same keyword has been found 
					#it is used for the match term only !!
					#if uid=root,pippo => Adding root to 0:uid:0:0:0 and Adding pippo to 0:uid:0:1:0 => alternatives in (,)
					#if uid=(root,pippo),(ciccio) => Adding root to 0:uid:0:0:0 , Adding pippo to 0:uid:0:0:1 and Adding ciccio to 0:uid:0:1:0 => number of (), elements
					#		Hash Filters
					# ObjectiveCount| 	Hash1
					# 				|key  |		  Hash2
					# 				|     |	keymatch| 	  		Hash3
					# 				|     |	        |element count| 				Hash4
					# 				|     |	        |             | alternative count| alternative									
					$ElementCount=0;
					$keymatch=keys(%{$Filters{$TEMPObjectiveCount}{$key}});#number of elements of Hash2 => number of times the same keyword has been found 
					foreach $component (@components) {
						$AlternativeCount=0;
						@alternatives = split(/,/,$component);
						foreach $alternative (@alternatives) {
							#number of objective:key:number of times the same keyword has been found  :number of () elements: alternatives in (,)
							LogMsg("Adding $alternative to $TEMPObjectiveCount:$key:$keymatch:$ElementCount:$AlternativeCount");
							$Filters{$TEMPObjectiveCount}{$key}{$keymatch}{$ElementCount}{$AlternativeCount}=$alternative;
							if($check eq "=") {
								# If the user has specified a positive match, and
								# Has identified an explicit event, then mark it to be turned on.
								if($key eq "event") {
									if (!($USEWATCH && $OPEN_EVENTS{$alternative} == 1)) {
										# put the events in a temporary list
										$temp_EventsON{$alternative}=SUCCESS + FAILURE;
									}
								} elsif($key eq "return") {
									# if we are only looking for a specific return code,
									# only enable the necessary auditing
									if ($alternative =~ /no/) {
										foreach $eventid (keys(%temp_EventsON)) {
											$temp_EventsON{$eventid}= $temp_EventsON{$eventid} | FAILURE;
										}
									} elsif ($alternative =~ /yes/) {
										foreach $eventid (keys(%temp_EventsON)) {
											$temp_EventsON{$eventid}= $temp_EventsON{$eventid} | SUCCESS;
										}
									}
								}
								#		Hash $FilterTypes
								# ObjectiveCount| 	Hash1
								# 				|key  |		  Hash2
								# 				|     |	keymatch|type of matching
								
								$FilterTypes{$TEMPObjectiveCount}{$key}{$keymatch}=0;
							} else {
								# Negate this match
								$FilterTypes{$TEMPObjectiveCount}{$key}{$keymatch}=1;
							}
							$AlternativeCount++;
						}
						$ElementCount++;
					}
				}
				foreach $eventid (keys(%temp_EventsON)) {
					$EventsON{$eventid} = $temp_EventsON{$eventid};
					delete $temp_EventsON{$eventid};
				}

				$ObjectiveCount++;
			}
		}
	}
	# remove WatchVal if we are not using watches
	undef %WatchVal if (!$USEWATCH);

	$FilterCount = $ObjectiveCount;
	return(1);
}

sub SetAudit() {
	if($MANAGEAUDIT == 1) {
		# temporarily disable audit while we modify the values
		if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -e 0"); }
		`/sbin/auditctl -e 0`;
		# Clear all audit events
		if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -D"); }
		`/sbin/auditctl -D`;
		HandleWatch(\%WatchVal);
		if(%EventsON) {
			$list_sf="";
			$list_s="";
			$list_f="";

			foreach $eventid (keys(%EventsON)) {
				if (defined($nsyscall{$eventid}) || defined($syscall{$eventid})) {
					if ($EventsON{$eventid} == (SUCCESS + FAILURE)) {
						if($DEBUG) { LogMsg("Turning on event $eventid"); }
						$list_sf .= " -S $eventid";
					} elsif ($EventsON{$eventid} == SUCCESS) {
						if($DEBUG) { LogMsg("Turning on event $eventid (SUCCESS only)"); }
						$list_s .= " -S $eventid";
					} elsif ($EventsON{$eventid} == FAILURE) {
						if($DEBUG) { LogMsg("Turning on event $eventid (FAILURE only)"); }
						$list_f .= " -S $eventid";
					} else {
						if($DEBUG) { LogMsg("fail $eventid"); }
					}
				} else {
					if($DEBUG) { LogMsg("Cannot find syscall: $eventid"); }
				}
			}
			if ($list_sf ne "") {
				if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -a entry,always $list_sf"); }
				`/sbin/auditctl -a entry,always $list_sf`;
			}
			if ($list_s ne "") {
				if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -a entry,always $list_s -F success=1"); }
				`/sbin/auditctl -a entry,always $list_s -F success=1`;
			}
			if ($list_f ne "") {
				if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -a exit,always $list_f -F success=0"); }
				`/sbin/auditctl -a exit,always $list_f -F success=0`;
			}
		}
		# if these events are not explicitly turned on, then block them out
		# since they can be quite noisy using watches
		if (not defined $EventsON{"lstat64"} && not defined $EventsON{"stat64"} && not defined $EventsON{"access"}) {
			if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -A entry,never -S lstat64 -S stat64 -S access"); }
			`/sbin/auditctl -A entry,never -S lstat64 -S stat64 -S access`;
		}
		if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -e 1"); }
		`/sbin/auditctl -e 1`;
	}
}





sub OpenOutput() {
	my $line = shift;
	($type,$destination,$opt,$opt2)=split(/[=:]/,$line);
	if($type eq "file" && not defined $OUTPUTFILE) {
		if($destination eq "stdout") {
			open($OUTPUTFILE,">-");
		} else {
			open($OUTPUTFILE,">>$destination");
			# hot file handle to stop unwanted buffering
			select((select($OUTPUTFILE), $|=1)[0]);
		}
		if(defined $OUTPUTFILE) {
			return(1);
		}
		return(0);
	}
	return(0);
}



sub resolve_path {
	my($path)=@_;
	my(@pathparts)=split(/\//,$path);
	my(@newpath)=();

	foreach $part (@pathparts) {
		if($part eq "..") {
			if(@newpath) {
				pop(@newpath);
			}
		} elsif($part eq ".") {
			# Do nothing
		} elsif($part eq "") {
			# Do nothing
		} else {
			# strip out double quotes
			$part =~ s/"//g; 
			push(@newpath,$part);
		}
	}
	$resolvedpath="";
	if($path =~ /^\//) {
		$resolvedpath = "/";
	}
	$resolvedpath .= join("/",@newpath);

	return($resolvedpath);
}

sub getuname {
	my($name)=@_;
	if($unamecache{"$name"} eq "-") {
		return(-1);
	} elsif($unamecache{"$name"}) {
		return($unamecache{"$name"});
	} else {
		$id=getpwnam($name);
		if($id) {
			$unamecache{"$name"}=$id;
			return($id);
		} else {
			$unamecache{"$name"}="-";
			return(-1);
		}
	}
}

sub getuid {
	my($id,$sleep)=@_;
	if($uidcache{"$id"} eq "-") {
		return(0);
	} elsif($uidcache{"$id"}) {
		return($uidcache{"$id"});
	} else {
		$name=getpwuid($id);
		if($sleep == 1 && !$name) {
			sleep(1);
			$name=getpwuid($id);
		}
		if($name) {
			$uidcache{"$id"}=$name;
			return($name);
		} else {
			$uidcache{"$id"}="-";
			return(0);
		}
	}
}

sub getgid {
	my($id)=@_;
	if($gidcache{"$id"} eq "-") {
		return(0);
	} elsif($gidcache{"$id"}) {
		return($gidcache{"$id"});
	} else {
		$name=getgrgid($id);
		if($name) {
			$gidcache{"$id"}=$name;
			return($name);
		} else {
			$gidcache{"$id"}="-";
			return(0);
		}
	}
}

sub Handler {
	local($sig)=@_;
	LogMsg("SIG$sig Signal Received");
	if($DEBUG) { LogMsg("SIG$sig Signal Received"); }
	if ($sig ne "PIPE") {
		$CONTINUE=0;
	}
}

sub Restart {
	local($sig)=@_;
	if($DEBUG) { LogMsg("SIG$sig Signal Received in restart routine"); }
	#$CONTINUE=0;

	# Flush our buffers
	CloseOutputs();
	sleep(1);

	%event=();
	%Filters=();

	LoadConfig();
	# Set up our audit configuration based on our objectives.
	SetAudit();
	# Good to go.
}


sub LogMsg {
	my($string)=@_;
	if(!$string) {
		return;
	}
	setlogsock('unix');
	$rc=openlog("SafedDispatcher",'','user');
	if($rc) {
		syslog('info',"[$$]$string");
	}
	closelog();
	print "DEBUG: $string\n";
}

sub ExtraWatch {
	my ($path,$flag) = @_;
	if ($DEBUG >= 2) { LogMsg("Handling watch for $path"); }
	$tempfile = "/tmp/safedwatch.txt";
	`/usr/bin/find "$path" -type d -printf "-i -w %p -k dir\n" -or -type f -printf "-i -w %p\n" >> $tempfile`;
	chmod 0600,$tempfile;
	if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -R $tempfile"); }
	`/sbin/auditctl -R $tempfile` if (-e $tempfile);
	#if (!$DEBUG) {unlink ($tempfile);}
	unlink ($tempfile);
}

sub HandleWatch {
	my(%watch) = %{$_[0]};
	#loop through the watch values
	$tempfile = "/tmp/safedwatch.txt";
	# make sure it is empty
	unlink ($tempfile);
	my $new=0;
	for ($wcount=0; $wcount < $WatchCount;$wcount++) {
		#first, check if we need to watch for any new values, if not, it makes things easy
		$new=1 if ($watch{$wcount}{"flag"} == NEWWATCH);
	}
	if (!$new) {
		for ($wcount=0; $wcount < $WatchCount;$wcount++) {
			$path = $watch{$wcount}{"path"};
			if ($DEBUG >= 2) { LogMsg("Handling watch for " . $watch{$wcount}{"path"}); }
			if ($watch{$wcount}{"flag"} == WATCH) {
				if ($DEBUG >= 2) { LogMsg("CMD: /usr/bin/find \"$path\" -type f -printf \"-i -w %p\n\" >> $tempfile"); }
				`/usr/bin/find "$path" -type f -printf "-i -w %p\n" >> $tempfile`;
			} else {
				if (-d $path) {
					if ($DEBUG >= 2) { LogMsg("CMD: /usr/bin/find \"$path\" -printf \"-i -W %p\n\" >> $tempfile"); }
					`/usr/bin/find "$path" -printf "-i -W %p\n" >> $tempfile`;
				} else {
					if ($DEBUG >= 2) { LogMsg("CMD: echo \"-i -W $path\" >> $tempfile"); }
					`echo "-i -W $path" >> $tempfile`;
				}
			}
		}
		chmod 0600,$tempfile;
		if ($DEBUG) { LogMsg("AUDITCTL: /sbin/auditctl -R $tempfile"); }
		`/sbin/auditctl -R $tempfile` if (-e $tempfile);
		#if (!$DEBUG) {unlink ($tempfile);}
		unlink ($tempfile);
	} else {
		# filterkey=dir for all dir of NEWWATCH dir; filterkey=safedignore for all watched dir or ignored dir part also of NEWWATCH; watched file part of NEWWATCH continue to be watched; ignored file part of NEWWATCH will be ignored
		# filterkey dir will be considered for further filtering but filterkey safedignore will be ignored
		for ($wcount=0; $wcount < $WatchCount;$wcount++) {
			$path = $watch{$wcount}{"path"};
			if ($DEBUG >= 2) { LogMsg("Handling watch for " . $watch{$wcount}{"path"}); }
			if ($watch{$wcount}{"flag"} == NEWWATCH) {
				`/usr/bin/find "$path" -type d -printf "-i -w %p -k dir\n" -or -type f -printf "-i -w %p\n" >> $tempfile`;
			} elsif ($watch{$wcount}{"flag"} == WATCH) {
				#Just in case the parent dir in part of NEWWATCH
				if (-d $path) {
					$audit=`auditctl -l | grep "path=$path, filterkey=dir"`;
					if ($audit ne '') {
						# NEWWATCH zone, will need to use safedignore on the directories
						`/usr/bin/find "$path" -type d -printf "-i -W %p\n-i -w %p -k safedignore\n" >> $tempfile`;
					}
				}
				`/usr/bin/find "$path" -type f -printf "-i -w %p\n" >> $tempfile`;
			} else {
				#IGNORE
				if (-d $path) {
					$audit=`auditctl -l | grep "path=$path, filterkey=dir"`;
					if ($audit ne '') {
						# if the dir being ignored is in a NEWWATCH zone, need to use safedignore
						`/usr/bin/find "$path" -printf "-i -W %p\n-i -w %p -k safedignore\n" >> $tempfile`;
					} else {
						# otherwise, just strip out the file watches
						`/usr/bin/find "$path" -type f -printf "-i -W %p\n" >> $tempfile`;
					}
				} else {
					# ignoring a file, file might not exist
					# check that the basedir is not being audited
					$basedir = dirname($path);
					$audit=`auditctl -l | grep "path=$basedir, filterkey=dir"`;
					if ($audit ne '') {
						# NEWWATCH zone, will need to use safedignore
						`echo "-i -W $path\n-i -w $path -k safedignore" >> $tempfile`;
					} else {
						# otherwise, just strip out the file watch
						`echo "-i -W $path" >> $tempfile`;
					}
				}
			}
			chmod 0600,$tempfile;
			if ($DEBUG) { LogMsg("AUDITCTL: sbin/auditctl -R $tempfile"); }
			`/sbin/auditctl -R $tempfile` if (-e $tempfile);
			#if (!$DEBUG) {unlink ($tempfile);}
			unlink ($tempfile);
		}
	}
}
