#!/usr/bin/perl


use strict;
use blib;
use Test::More tests => 46;
use constant TEST_FILE =>'test.xml';
use vars qw($host $p $FH $scriptpath $scaninfo @test %test $test);
use_ok('Parser::Nmap::XML');
$scriptpath = $0;$scriptpath =~ s%[^/]+$%%;
$FH = $scriptpath.TEST_FILE;
if(! -e $FH){$FH='./test.xml';}

$p = new Parser::Nmap::XML;
$scaninfo = new Parser::Nmap::XML::ScanInfo;
$host = new Parser::Nmap::XML::Host;

nmap_parser_test();
nmap_parser_std_test();
nmap_parser_host_test();
nmap_parser_scaninfo_test();
nmap_parser_end_test();


sub nmap_parser_test {
isa_ok( $p , 'Parser::Nmap::XML');
isa_ok( $scaninfo,'Parser::Nmap::XML::ScanInfo');
isa_ok( $host,'Parser::Nmap::XML::Host');
ok($p->parsefile($FH),'Parsing FH filehandle from nmap data');}

sub nmap_parser_end_test {
ok(!$p->clean(),'Testing clean() to clean memory');
ok(!$p->get_scaninfo(),'Testing clean() against scaninfo');
is(scalar $p->get_host_list(),0,'Testing clean() against host list');

}

sub nmap_parser_std_test {

ok(!$p->only_inactive(), 'Setting filters for only inactive hosts');
ok($p->only_active(), 'Setting filters for only active hosts');



%test = (solaris => [qw(solaris sparc sunos)],
            linux => [qw(linux mandrake redhat slackware)],
            unix => [qw(unix hp-ux hpux bsd immunix aix knoppix)],
            win  => [qw(win microsoft)],
	    mac => [qw(mac osx)],
	    switch => [qw(ethernet cisco netscout router switch)],
	    );
is_deeply($p->get_generic_os_list(),\%test, 'Testing default get_generic_os_list');
%test = (solaris => [qw(solaris sparc sunos)],linux => [qw(linux mandrake redhat slackware)]);
is_deeply($p->set_generic_os_list(\%test),\%test, 'Testing set_generic_os_list');
is_deeply($p->get_generic_os_list(),\%test, 'Testing get_generic_os_list for premanence of structure');
eq_set([$p->get_host_list()],['127.0.0.2','127.0.0.1','127.0.0.3'], ,'Testing get_host_list for correct hosts from file');
eq_set([$p->get_host_list('up')],['127.0.0.2','127.0.0.1'], ,'Testing get_host_list for correct hosts with status = up');
eq_set([$p->get_host_list('down')],['127.0.0.3'], ,'Testing get_host_list for correct hosts for with status = down');
eq_set([$p->get_host_list()],['127.0.0.2','127.0.0.1'], ,'Testing get_host_list for correct hosts from file');
eq_set([$p->filter_by_generic_os('solaris')],['127.0.0.2'],'Testing generic_os filter');
eq_set([$p->filter_by_generic_os('solaris','linux')],['127.0.0.2','127.0.0.1'], 'Testing multi generic_os filter');
eq_set([$p->filter_by_status('up')],['127.0.0.2','127.0.0.1'],'Testing status filter - up');
eq_set([$p->filter_by_status('down')],['127.0.0.3'],'Testing status filter - down');
eq_set([$p->filter_by_status()],['127.0.0.2','127.0.0.1'],'Testing status filter - default');
@test = sort {$a->addr() cmp $b->addr()} $p->get_host_objects();
is(scalar @test, 3,'Testing for number of host objects');
is($test[0]->addr(), '127.0.0.1','Testing for host object 1');
is($test[1]->addr(), '127.0.0.2','Testing for host object 2');
is($test[2]->addr(), '127.0.0.3','Testing for host object 3');
ok($p->del_host('127.0.0.2'),'Testing del_host');
ok(!$p->get_host('127.0.0.2'),'Testing for permanent deletion from call');
eq_set([$p->get_host_list('up')],['127.0.0.1'],'Testing for permanent deletion from list');

}

sub nmap_parser_scaninfo_test {
$scaninfo = $p->get_scaninfo();
is(ref($scaninfo), 'Parser::Nmap::XML::ScanInfo','Getting ScanInfo Object from get_scaninfo()');
is($scaninfo->num_of_services(), (1023+1023), 'Testing total number of services');
is($scaninfo->num_of_services('connect'), 1023, 'Testing number of services for CONNECT');
is($scaninfo->num_of_services('udp'),1023, 'Testing number of services for UDP');
is($scaninfo->start_time(),1057088883,'Testing scaninfo start time');
is($scaninfo->finish_time(),1057088900,'Testing scaninfo finish time');
is($scaninfo->nmap_version(),'3.27','Testing nmap version');
is($scaninfo->args(),'nmap -v -v -v -oX test.xml -O -sTUR -p 1-1023 localhost','Testing nmap arguments');
is(scalar $scaninfo->scan_types() ,2, 'Testing number of scan types');
eq_set( [$scaninfo->scan_types()], ['connect','udp'], 'Testing for correct scan types');
is($scaninfo->proto_of_scan_type('connect'), 'tcp','Testing "connect" protocol = tcp');
is($scaninfo->proto_of_scan_type('udp'), 'udp','Testing "udp" protocol = udp');
}


sub nmap_parser_host_test {
is(ref($host = $p->get_host('127.0.0.1')),'Parser::Nmap::XML::Host','Getting Host Object from get_host()');
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), '127.0.0.1', 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->hostnames(), 'localhost.localdomain','Testing for correct hostname');
is(scalar @{[$host->tcp_ports()]} , 6, 'Testing for tcp_ports()');
is(scalar @{[$host->udp_ports()]} , 2, 'Testing for udp_ports()');
is($host->tcp_service_name('22'), 'ssh','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_name('25'), 'smtp','Testing tcp_service_name(25) = smtp');
is($host->udp_service_name('111'), 'rpcbind', 'Testing udp_service_name(111) = rpcbind');
is(scalar @{[$host->os_matches()]} , 1,'Testing os_matches()');
is($host->os_matches().'', 'Linux Kernel 2.4.0 - 2.5.20','Testing for correct OS');
is($host->os_generic(),'linux','Testing os_generic() = linux');
is($host->os_port_used(), '22', 'Testing os_port_used() = 22');
is($host->uptime_seconds() , 1973, 'Testing uptime_seconds() : ');
is($host->uptime_lastboot() ,'Tue Jul  1 14:15:27 2003', 'Testing uptime_lastboot() : ');

}
