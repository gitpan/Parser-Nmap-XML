use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Parser::Nmap::XML',
    'VERSION_FROM'	=> 'XML.pm', # finds $VERSION
    'PREREQ_PM'		=> {'XML::Twig' => 3.0}, # e.g., Module::Name => 1.1
    'ABSTRACT'		=> 'Parse Nmap xml-output files using perl',
    'AUTHOR'	       => 'Anthony G Persaud <ironstar@iastate.edu>'
	);


