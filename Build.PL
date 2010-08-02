
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  'build_requires' => {
    'File::Find' => '0',
    'File::Temp' => '0',
    'FindBin' => '0',
    'Module::Build' => '0.3601',
    'Test::Exception' => '0',
    'Test::MockObject' => '0',
    'Test::More' => '0.88'
  },
  'configure_requires' => {
    'Module::Build' => '0.3601'
  },
  'dist_abstract' => 'Use JanRain\'s RPX service for Credentials',
  'dist_author' => [
    'Kent Fredric <kentnl@cpan.org>'
  ],
  'dist_name' => 'Catalyst-Authentication-Credential-RPX',
  'dist_version' => '0.10038414',
  'license' => 'bsd',
  'module_name' => 'Catalyst::Authentication::Credential::RPX',
  'recommends' => {},
  'recursive_test_files' => 1,
  'requires' => {
    'Moose' => '0',
    'MooseX::Has::Sugar' => '0.0300',
    'MooseX::Types::Moose' => '0',
    'Net::API::RPX' => '0.01',
    'Test::Exception' => '0',
    'Test::MockObject' => '0',
    'Test::More' => '0',
    'namespace::autoclean' => '0'
  },
  'script_files' => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
