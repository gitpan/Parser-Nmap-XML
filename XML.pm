package Parser::Nmap::XML;

################################################################################
##			Parser::Nmap::XML				      ##
################################################################################

use strict;
use lib '../';
use XML::Twig;
use vars qw($S %H %OS_LIST %G);
use Exporter;
use vars qw($DEBUG);
our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw( ) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw( );

our $VERSION = '0.50';

sub new {
my ($class,$self) = shift;
$class = ref($class) || $class;
$$self{twig}  = new XML::Twig(
	start_tag_handlers => {nmaprun => \&_nmaprun_hdlr},
	TwigHandlers => {
		scaninfo => \&_scaninfo_hdlr,
		finished => \&_finished_hdlr,
		host => \&_host_hdlr,
		}
		);

$G{generic_os_scan} =1;
%OS_LIST = (solaris => [qw(solaris sparc sunos)],
            linux => [qw(linux mandrake redhat slackware)],
            unix => [qw(unix hp-ux hpux bsd immunix aix knoppix)],
            win  => [qw(win microsoft)],
	    mac => [qw(mac osx)],
	    switch => [qw(ethernet cisco netscout router switch)],
	    );
bless ($self,$class);
return $self;
}

################################################################################
##			PRE-PARSE METHODS				      ##
################################################################################
sub set_generic_os_list {
my $self = shift;my $list = shift;
%OS_LIST = %{$list};return \%OS_LIST;
}

sub get_generic_os_list {return \%OS_LIST;}
sub parse_filter_generic_os {$G{generic_os_scan} = $_[1];}
sub parse_filter_status {$G{only_active} = $_[1];}


################################################################################
##			PARSE METHODS					      ##
################################################################################
sub parse {%H =();$S = undef;shift->{twig}->parse(@_);}
sub parsefile {%H=();$S = undef;shift->{twig}->parsefile(@_);}
sub safe_parse {%H=();$S = undef;shift->{twig}->safe_parse(@_);}
sub safe_parsefile {%H=();$S = undef;shift->{twig}->safe_parsefile(@_);}
sub clean {%H = ();$S = undef;$_[0]->{twig}->purge;return $S;}

################################################################################
##			POST-PARSE METHODS				      ##
################################################################################

sub get_host_list {shift if(ref($_[0]) eq __PACKAGE__);my $state = shift;
if($state eq 'up' || $state eq 'down')
{return (grep {$H{$_}{state} eq $state}(keys %H))};
return (keys %H);
}
sub get_host {shift if(ref($_[0]) eq __PACKAGE__);return $H{$_[0]};}
sub del_host {shift if(ref($_[0]) eq __PACKAGE__);delete $H{$_[0]};}
sub get_host_objects {return values (%H);}

sub filter_by_generic_os {
my $self = shift;
my @keywords = @_;
my @os_matched_ips = undef;
for my $addr (keys %H)
{
	my $os = $H{$addr}{os}{generic_names};
	next unless(defined($os) && $os ne '');
	my $keyword = (grep { $os =~ m/$_/ } @keywords)[0];
	if(defined $keyword){push @os_matched_ips, $addr;}

}
return @os_matched_ips;

}

sub filter_by_status {
my $self= shift;
my $status = lc(shift);
$status = 'up' if($status ne 'up' || $status ne 'down');
return (grep {$H{$_}->{status} eq $status} (keys %H));
}


sub get_scaninfo {return $S;}


################################################################################
##			PRIVATE TWIG HANDLERS				      ##
################################################################################

sub _scaninfo_hdlr {
my ($twig,$scan) = @_;
my ($type,$proto,$num) = ($scan->att('type'),$scan->att('protocol'),$scan->att('numservices'));
if(defined($type)){$S->{type}{$type} = $proto;$S->{numservices}{$type} = $num;}
$twig->purge;}


sub _nmaprun_hdlr {#Last tag in an nmap output
my ($twig,$host) = @_;
$S->{start_time} = $host->att('start');
$S->{nmap_version} = $host->att('version');
$S->{args} = $host->att('args');
$S = Parser::Nmap::XML::ScanInfo->new($S);

$twig->purge;
}


sub _finished_hdlr {my ($twig,$host) = @_;$S->{finish_time} = $host->att('time');$twig->purge;}


sub _host_hdlr {
my($twig, $host)= @_; # handlers are always called with those 2 arguments
my ($addr,$tmp);
    if(not defined($host)){return undef;}
    my $tmp        = $host->first_child('address');         # get the element text
    if(not defined $tmp){return undef;}
    my $addr = $tmp->att('addr');
    if(!defined($addr) || $addr eq ''){return undef;}
    $H{$addr}{addr} = $addr;
    $H{$addr}{addrtype} = $tmp->att('addrtype');
    $tmp = $host->first_child('hostnames');
    @{$H{$addr}{hostnames}} = _hostnames_hdlr($tmp,$addr) if(defined ($tmp = $host->first_child('hostnames')));
    $H{$addr}{status} = $host->first_child('status')->att('state');
    if($H{$addr}{status} eq 'down')
    {$twig->purge;
	if($G{only_active})
	{delete $H{$addr};}
    	else { $H{$addr} = Parser::Nmap::XML::Host->new($H{$addr});}
    	return;}

    $H{$addr}{ports} = _port_hdlr($host,$addr);
    $H{$addr}{os} = _os_hdlr($host,$addr);
    $H{$addr}{uptime} = _uptime_hdlr($host,$addr);
    $H{$addr} = Parser::Nmap::XML::Host->new($H{$addr});
                  # print the info
    $twig->purge;                                      # purges the twig

}

sub _port_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
$tmp = $host->first_child('ports');
unless(defined $tmp){return undef;}
@list= $tmp->children('port');
for my $p (@list){
my $proto = $p->att('protocol');
my $portid = $p->att('portid');
if(defined($proto && $portid)){$H{$addr}{ports}{$proto}{$portid} =
				_service_hdlr($host,$addr,$p);}

}

return $H{$addr}{ports};
}



sub _service_hdlr {
my ($host,$addr,$p) = @_;
my $tmp;
my $s = $p->first_child('service[@name]');
$tmp->{service_name} = 'unknown';

if(defined $s){
$tmp->{service_name} = $s->att('name');
$tmp->{service_proto} = $s->att('proto') if($s->att('proto'));
$tmp->{service_rpcnum} = $s->att('rpcnum') if($tmp->{service_proto} eq 'rpc');
}

return $tmp;

}

sub _os_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
if(defined(my $os_list = $host->first_child('os'))){
    $tmp = $os_list->first_child("portused[\@state='open']");
    $H{$addr}{os}{portused} = $tmp->att('portid') if(defined $tmp);
    for my $o ($os_list->children('osmatch')){
    push @list, $o->att('name');
    }
    @{$H{$addr}{os}{names}} = @list;

    $H{$addr}{os}{generic_names} = _match_os(@list) if($G{generic_os_scan});
    }

    return $H{$addr}{os};

}


sub _uptime_hdlr {
my ($host,$addr) = (shift,shift);
my $uptime = $host->first_child('uptime');
my $hash;
if(defined $uptime){
	$hash->{seconds} = $uptime->att('seconds');
	$hash->{lastboot} = $uptime->att('lastboot');
}
return $hash;
}


sub _hostnames_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my $hostnames = shift;
my $addr = shift;
my @names;
for my $n ($hostnames->children('hostname')) {push @names, $n->att('name');}
return @names if(wantarray);
return \@names;

}


sub _match_os {

shift if(ref($_[0]) eq __PACKAGE__);
my $os_string = lc(join '', @_);
$os_string =~ s/\s|\n//g;
my @matches;
unless(keys %OS_LIST){return undef;}
for my $os_generic (keys %OS_LIST){
	my @keywords = @{$OS_LIST{$os_generic}};
	for my $keyword (@keywords){
		if($os_string =~ /$keyword/){
			push @matches, $os_generic;}
	}


}
if(scalar @matches){return (join ',', sort keys %{ {map {$_,1} @matches} } );}
return 'other';

}


################################################################################
##			Parser::Nmap::XML::ScanInfo			      ##
################################################################################

package Parser::Nmap::XML::ScanInfo;

sub new {
my $class = shift;
$class = ref($class) || $class;
my $self =  shift || {};
bless ($self,$class);
return $self;
}

sub num_of_services {
if($_[1] ne ''){return $_[0]->{numservices}{$_[1]};}
else {my $total = 0;for (values %{$_[0]->{numservices}}){$total +=$_;}
return $total;}
}
sub finish_time {return $_[0]->{finish_time};}
sub nmap_version {return $_[0]->{nmap_version};}
sub args {return $_[0]->{args};}
sub start_time {return $_[0]->{start_time};}
sub scan_types {(wantarray) ? 	return (keys %{$_[0]->{type}}) :
				return scalar(keys %{$_[0]->{type}});}
sub proto_of_scan_type {return $_[0]->{type}{$_[1]};}


################################################################################
##			Parser::Nmap::XML::Host				      ##
################################################################################

package Parser::Nmap::XML::Host;


sub new {
my ($class,$self) = (shift);
$class = ref($class) || $class;
$self = shift || {};
bless ($self,$class);
return $self;
}

sub status {return $_[0]->{status};}
sub addr {return $_[0]->{addr};}
sub addrtype {return $_[0]->{addrtype};}
sub hostnames {($_[1]) ? 	return @{$_[0]->{hostnames}}[ $_[1] - 1] :
				return @{$_[0]->{hostnames}};}
sub tcp_ports {(wantarray) ? 	return (keys %{$_[0]->{ports}{tcp}}) :
				return $_[0]->{ports}{tcp};}
sub udp_ports {(wantarray) ? 	return (keys %{$_[0]->{ports}{udp}}) :
				return $_[0]->{ports}{udp};}
sub tcp_service_name {return $_[0]->{ports}{tcp}{$_[1]}{service_name};}
sub udp_service_name {return $_[0]->{ports}{udp}{$_[1]}{service_name};}
sub os_matches {($_[1]) ? 	return @{$_[0]->{os}{names}}[ $_[1] - 1 ] :
				return (@{$_[0]->{os}{names}});}
sub os_port_used {return $_[0]->{os}{portused};}
sub os_generic {(wantarray) ? 	return (split ',', $_[0]->{os}{generic_names}) :
				return $_[0]->{os}{generic_names};}
sub uptime_seconds {return $_[0]->{uptime}{seconds};}
sub uptime_lastboot {return $_[0]->{uptime}{lastboot};}

1;

__END__

=pod

=head1 NAME

Parser::Nmap::XML - frontend to parse the Nmap scan data from the XML output (-oX).

=head1 SYNOPSIS

  use Parser::Nmap::XML;

 	#PARSING
  my $p = new Parser::Nmap::XML;
  $p->parse($fh); #filehandle or nmap xml output string
  #or $p->parsefile('nmap_output.xml');

 	#GETTING SCAN INFORMATION
  print "Scan Information:\n";
  $si = $p->get_scaninfo();
  #Now I can get scan information by calling methods
  print
  'Number of services scanned: '.$si->num_of_services()."\n",
  'Start Time: '.$si->start_time()."\n",
  'Scan Types: ',(join ' ',$si->scan_types())."\n";

 	#GETTING HOST INFORMATION
   print "Hosts scanned:\n";
   for my $ip ($p->get_host_list()){
   $host_obj = Parser::Nmap::XML->get_host($ip);
   print
  'Hostname: '.($host_obj->hostnames())[0],"\n",
  'Address: '.$host_obj->addr()."\n",
  'OS matches: '.(join ',', $host_obj->os_matches())."\n",
  'Last Reboot: '.($host_obj->uptime_lastboot,"\n";
  	#... you get the idea...
   }

  print "\n\nUnix Flavor Machines:\n";
  for ($p->filter_by_generic_os('linux','solaris','unix')){print;}

  print "\n\nAnd for those who like Windows:\n";
  for ($p->filter_by_generic_os('win')){print;}

  $p->clean(); #frees memory


=head1 DESCRIPTION

This is an XML parser for nmap XML reports. This uses the XML::Twig library
which is fast and more memory efficient than using the XML::SAX::PurePerl that
comes with Nmap::Scanner::Scanner. This module, in the authors opinion, is
easier to use for basic information gathering of hosts.

=head3 Easy Steps

- Using this module is very simple. (hopefully). You use
$obj->parse() or $obj->parsefile(), to parse the nmap xml
information. This information is parsed and constructed
internally.

- Use the $si = $obj->get_scaninfo() to obtain the
Parser::Nmap::XML::ScanInfo object. Then you can call any of the
ScanInfo methods on this object to retrieve the information. See
L<Parser::Nmap::XML::ScanInfo> below.

- Use the $host_obj = $obj->get_host($addr) to obtain the
Parser::Nmap::XML::Host object of the current address. Using this object
you can call any methods in the Host object to retrieve the information
taht nmap obtained from this scan.

- You can use any of the other methods to filter or obtain
different lists.

 get_host_list() #returns all ip addresses that were scanned
 filter_by_generic_os($os) #returns all ip addresses that have generic_os = $os
 			   #See get_os_list() and set_os_list()
 #etc. (see other methods)

- After you are done with everything, you should do a $obj->clean()
to free up the memory used by maintaining the scan and hosts information
from the scan.
 A much more efficient way to do is, once you are done using a host object,
 delete it from the main tree.

 	#Getting all IP addresses parsed
 for my $host ($obj->get_host_list())
 	{#Getting the host object for that address
	my $h = $obj->get_host($host);
	#Calling methods on that object
	print "Addr: $host  OS: ".(join ',',$h->os_matches())."\n";
	$obj->del_host($host); #frees memory
	}

 Of course a much better way would be:
 for ($obj->get_host_objects())
 {
 print "Addr: ".$_->addr()." OS: ".$_->os_matches()."\n";
 delete $_;
 }

=head1 METHODS

=head2 Pre-Parsing Methods

=over 4

=item B<new()>

Creates a new Parser::Nmap::XML object with default handlers and default
generic os list.


=item B<set_generic_os_list($hashref)>

Decides what is the generic OS name of the given system.

Takes in a hash refernce that referes to pairs of generic os names to their
keyword list. Shown here is the default. Calling this method will overwrite the
whole list, not append to it. Use C<get_generic_os_list()> first to get the current
listing.

  $obj->set_generic_os_list({
  	solaris => [qw(solaris sparc sunos)],
        linux => [qw(linux mandrake redhat slackware)],
        unix => [qw(unix hp-ux hpux bsd immunix aix knoppix)],
        win  => [qw(win microsoft)],
	mac => [qw(mac osx)],
	switch => [qw(ethernet cisco netscout router switch)],
	    });

example: generic_os_name = solaris if the os string being matched
matches (solaris, sparc or sunos) keywords

=item B<get_generic_os_list()>

Returns a hashre containing the current generic os names (keys) and
an arrayref pointing to the list of corresponding keywords (values).
See C<set_generic_os_list()> for an example.

=item B<parse_filter_generic_os($bool)>

If set to true, (the default), it will match the OS guessed by nmap with a
generic name that is given in the OS list. See L<set_generic_os_list()>. If
false, it will disable this matching (a bit of speed up in parsing).

=item B<parse_filter_status($bool)>

If set to true, it will ignore hosts that nmap found to be in state 'down'.
If set to perl-wise false, it will parse all the hosts. This is the default.
Note that if you do not place this filter, it will parse and store (in memory)
hosts that do not have much information. So calling a Parser::Nmap::XML::Host
method on one of these hosts that were 'down', will return undef.

=back 4


=head2 Parse Methods

=over 4

=item B<parse($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::parse().

This method is inherited from XML::Parser.  The "SOURCE" parameter should
either be a string containing the whole XML document, or it should be
an open "IO::Handle". Constructor options to "XML::Parser::Expat" given as
keyword-value pairs may follow the"SOURCE" parameter. These override, for this
call, any options or attributes passed through from the XML::Parser instance.

A die call is thrown if a parse error occurs. Otherwise it will return
the twig built by the parse. Use "safe_parse" if you want the
parsing to return even when an error occurs.

=item B<parsefile($filename [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::parsefile().

This method is inherited from XML::Parser. Open
"$filename" for reading, then call "parse" with the open
handle. The file is closed no matter how "parse" returns.

A die call is thrown if a parse error occurs. Otherwise it willreturn
the twig built by the parse. Use "safe_parsefile" if you want
the parsing to return even when an error occurs.

=item B<safe_parse($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::safe_parse().

This method is similar to "parse" except that it wraps the parsing
in an "eval" block. It returns the twig on success and 0 on failure
(the twig object also contains the parsed twig). $@ contains the
error message on failure.

Note that the parsing still stops as soon as an error is detected,
there is no way to keep going after an error.


=item B<safe_parsefile($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::safe_parsefile().

This method is similar to "parsefile" except that it wraps the
parsing in an "eval" block. It returns the twig on success and 0 on
failure (the twig object also contains the parsed twig) . $@ con-
tains the error message on failure

Note that the parsing still stops as soon as an error is detected,
there is no way to keep going after an error.

=item B<clean()>

Frees up memory by cleaning the current tree hashes and purging the current
information in the XML::Twig object.

=back 4


=head2 Post-Parse Methods

=over 4

=item B<get_host_list([$status])>

Returns all the ip addresses that were run in the nmap scan.
$status is optional and can be either 'up' or 'down'. If $status is
given, then only IP addresses that have that corresponding state will
be returned. Example: setting $status = 'up', then will return all IP
addresses that were found to be up. (network talk for active)

=item B<get_host_tree($ip_addr)>

Returns the complete tree of the corresponding IP address.

=item B<del_host_tree($ip_addr)>

Deletes the corresponding host tree from the main forest. (Frees up
memory of unwanted host structures).

=item B<get_host_objects()>

Returns all the host objects of all the IP addresses that nmap had run against.
See L<Parser::Nmap::XML::Host>.

=item B<filter_by_generic_os(@generic_os_names)>

This returns all the IP addresses that have match any of the keywords in
@generic_os_names that is set in their generic_names field. See os_list()
for example on generic_os_name. This makes it easier to sift through the
lists of IP if you are trying to split up IP addresses
depending on platform (window and unix machines for example).

=item B<filter_by_status($status)>

This returns an array of hosts addresses that are in the $status state.
$status can be either 'up' or 'down'. Default is 'up'.

=item B<get_scaninfo_tree()>

Returns the the current Parser::Nmap::XML::ScanInfo.
Methods can be called on this object to retrieve information
about the parsed scan. See L<Parser::Nmap::XML::ScanInfo> below.

=back 4


=head2 Parser::Nmap::XML::ScanInfo

The scaninfo object. This package contains methods to easily access
all the parameters and values of the Nmap scan information ran by the
currently parsed xml file or filehandle.

 $si = $obj->get_scaninfo();
 print 	'Nmap Version: '.$si->nmap_version()."\n",
 	'Num of Scan Types: '.(join ',', $si->scan_types() )."\n",
 	'Total time: '.($si->finish_time() - $si->start_time()).' seconds';
 	#... you get the idea...

=over 4


=item B<num_of_services([$scan_type])>;

If given a corresponding scan type, it returns the number of services
that was scan by nmap for that scan type. If $scan_type is omitted,
then num_of_services() returns the total number of services scan by all
scan_types.

=item B<start_time()>

Returns the start time of the nmap scan.

=item B<finish_time()>

Returns the finish time of the nmap scan.

=item B<nmap_version()>

Returns the version of nmap that ran.

=item B<args()>

Returns the command line parameters that were run with nmap

=item B<scan_types()>

In list context, returns an array containing the names of the scan types
that were selected. In scalar context, returns the total number of scan types
that were selected.

=item B<proto_of_scan_type($scan_type)>

Returns the protocol of the specific scan type.

=back 4


=head2 Parser::Nmap::XML::Host

The host object. This package contains methods to easily access the information
of a host that was scanned.

 $host_obj = Parser::Nmap::XML->get_host($ip_addr);
  #Now I can get information about this host whose ip = $ip_addr
  print
 'Hostname: '.$host_obj->hostnames(1),"\n",
 'Address: '.$host_obj->addr()."\n",
 'OS matches: '.(join ',', $host_obj->os_matches())."\n",
 'Last Reboot: '.($host_obj->uptime_lastboot,"\n";
 #... you get the idea...

If you would like for me to add more advanced information (such as
TCP Sequences), let me know.

=over 4


=item B<status()>

Returns the status of the host system. Either 'up' or 'down'

=item B<addr()>

Returns the IP address of the system

=item B<addrtype()>

Returns the address type of the IP address returned
by addr(). Ex. 'ipv4'

=item B<hostnames($number)>

If $number is omitted (or false), returns an array containing all of
the host names. If $number is given, then returns the host name in that
particular slot. (order). The slot order starts at 1.

 $host_obj->hostnames(0); #returns an array containing the hostnames found
 $host_obj->hostnames();  #same thing
 $host_obj->hostnames(1); #returns the 1st hostname found
 $host_obj->hostnames(4); #returns the 4th. (you the point)

=item B<tcp_ports()>

In a list context, returns an array containing
the open tcp ports on the system. In a scalar
context, a hash reference of the tree branch is returned.

=item B<udp_ports()>

In a list context, returns an array containing
the open udp ports on the system. In a scalar
context, a hash reference of the tree branch is returned.

=item B<tcp_service_name($port)>

Returns the name of the service running on the
given tcp $port. (if any)

=item B<udp_service_name($port)>

Returns the name of the service running on the
given udp $port. (if any)

=item B<os_matches([$number])>

If $number is omitted, returns an array of possible matching os names.
If $number is given, then returns that slot entry of possible os names.
The slot order starts at 1.

 $host_obj->os_matches(0); #returns an array containing the os names found
 $host_obj->os_matches();  #same thing
 $host_obj->os_matches(1); #returns the 1st os name found
 $host_obj->os_matches(5); #returns the 5th. (you the point)

=item B<os_port_used()>

Returns the port number that was used in determining
the OS of the system.

=item B<os_generic()>

Returns the generic_name that was matched to the given host.
(see set_os_list()).

=item B<uptime_seconds()>

Returns the number of seconds the host has been up (since boot).

=item B<uptime_lastboot()>

Returns the time and date the given host was last rebooted.

=back 4

=head1 AUTHOR

Anthony G Persaud <ironstar@iastate.edu>

=head1 SEE ALSO

L<nmap(1)>, L<XML::Twig(3)>

  http://www.insecure.org/nmap/
  http://www.xmltwig.com

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html

=cut