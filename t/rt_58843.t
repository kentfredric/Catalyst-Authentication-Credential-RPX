
use strict;
use warnings;

use Test::MockObject;
use Test::More tests => 10;
use Test::Exception;

sub RPX() {
  'Catalyst::Authentication::Credential::RPX';
}

sub APIRPX() {
  'Net::API::RPX';
}

# Order is important

use FindBin;
use lib "$FindBin::Bin/mock";

BEGIN {
  use_ok( APIRPX() );
}

BEGIN {
  use_ok( RPX() );
}

my $config = {
  api_key     => 'SomeApiKey',
  base_url    => 'http://example.com',
  token_field => 'token',
};
my $realm = Test::MockObject->new();
$realm->mock( find_user => sub { $_[1] } );

my %data = map {
  my $i   = $_;
  my $req = Test::MockObject->new();
  $req->mock(
    params => sub {
      {
        field => 'value',
        token => $i,
      };
    }
  );
  eval "package" . " TestApp::" . $_ . "; use Moose; sub req { \$req }; sub debug { 1 }; sub log { 1 };";
  $i => ( ( "TestApp::" . $_ )->new() );

} qw( A B );

{    # Success

  my ( $m, $user );

  lives_ok { $m = RPX->new( $config, 'TestApp::A', $realm ) } "Create Credential ( XSUCCESS )";
  can_ok( $m, qw( new authenticate ) );

  lives_ok { $user = $m->authenticate( 'TestApp::A', $realm ); } "Authenticate Credential ( XSUCCESS )";
  is_deeply( $user, $Net::API::RPX::RESPONSES->{'A'}, "Credentials Match Expectations" );
}

{    # Fail
  my ( $m, $user );
  lives_ok { $m = RPX->new( $config, 'TestApp::B', $realm, ) } "Create Credential ( XFAIL )";
  can_ok( $m, qw( new authenticate  ) );
  lives_ok { $user = $m->authenticate( 'TestApp::B', $realm, ); } "Authenticate Credential ( XFAIL )";
  is_deeply( $user, undef, "Authentication fails properly" );
}
