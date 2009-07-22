
use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  DISTNAME  => 'Catalyst-Authentication-Credential-RPX',
  NAME      => 'Catalyst::Authentication::Credential::RPX',
  AUTHOR    => 'Kent\ Fredric\ \<kentnl\@cpan\.org\>',
  ABSTRACT  => 'Use\ Janarains\ RPX\ service\ for\ Credentials',
  VERSION   => '0.0920310',
  EXE_FILES => [ qw() ],
  (eval { ExtUtils::MakeMaker->VERSION(6.31) } ? (LICENSE => 'bsd') : ()),
  PREREQ_PM    => {
    "Test::More" => '0',
    "MooseX::Types::Moose" => '0',
    "MooseX::Has::Sugar" => '0.0300',
    "Test::MockObject" => '0',
    "namespace::autoclean" => '0',
    "Test::Exception" => '0',
    "Find::Lib" => '0',
    "Net::API::RPX" => '0.01',
    "Test::use::ok" => '0.02',
    "Moose" => '0',
  },
);
