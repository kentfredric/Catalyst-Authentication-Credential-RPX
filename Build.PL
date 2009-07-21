
use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
  module_name   => 'Catalyst::Authentication::Credential::RPX',
  license       => 'bsd',
  dist_abstract => "Use\ Janarains\ RPX\ service\ for\ Credentials",
  dist_name     => "Catalyst\-Authentication\-Credential\-RPX",
  dist_author   => [
"Kent\ Fredric\ \<kentnl\@cpan\.org\>",
  ],
  requires      => {
    "Test::More" => '0',
    "Test::MockObject" => '0',
    "Test::Exception" => '0',
    "Find::Lib" => '0',
    "Net::API::RPX" => '0.01',
    "Test::use::ok" => '0.02',
  },
  script_files => [ qw() ],
);

$build->create_build_script;
