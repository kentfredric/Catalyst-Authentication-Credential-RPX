
use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
  module_name   => 'Catalyst::Authentication::Credential::RPX',
  license       => 'bsd',
  dist_abstract => "Use\ JanRain\'s\ RPX\ service\ for\ Credentials",
  dist_name     => "Catalyst\-Authentication\-Credential\-RPX",
  dist_author   => [
"Kent\ Fredric\ \<kentnl\@cpan\.org\>",
  ],
  requires      => {
    "Test::More" => '0',
    "Test::MockObject" => '0',
    "MooseX::Has::Sugar" => '0.0300',
    "MooseX::Types::Moose" => '0',
    "Test::Exception" => '0',
    "namespace::autoclean" => '0',
    "Net::API::RPX" => '0.01',
    "Moose" => '0',
  },
  script_files => [ qw() ],
);

$build->create_build_script;
