
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

use ok RPX;
use Find::Lib './mock';
use ok APIRPX;

my $config = {
  api_key     => 'SomeApiKey',
  base_url    => 'http://example.com',
  token_field => 'token',
};

{    # Success

  my $req = Test::MockObject->new();
  $req->mock( params => sub { { field => 'value', token => 'A', } } );

  my $c = Test::MockObject->new();
  $c->mock(
    req   => sub { $req },
    debug => sub { 1 },
    log   => sub { 1 },
  );
  my $realm = Test::MockObject->new();
  $realm->mock( find_user => sub { $_[1] } );

  my ( $m, $user );
  lives_ok { $m = RPX->new( $config, $c, $realm, ) } "Create Credential ( XSUCCESS )";
  can_ok( $m, qw( new authenticate authenticate_rpx ) );

  lives_ok { $user = $m->authenticate( $c, $realm, ); } "Authenticate Credential ( XSUCCESS )";
  is_deeply( $user, $Net::API::RPX::RESPONSES->{'A'}, "Credentials Match Expectations" );
}

{    # Fail

  my $req = Test::MockObject->new();
  $req->mock( params => sub { { field => 'value', token => 'B', } } );

  my $c = Test::MockObject->new();
  $c->mock(
    req   => sub { $req },
    debug => sub { 1 },
    log   => sub { 1 },
  );
  my $realm = Test::MockObject->new();
  $realm->mock( find_user => sub { $_[1] } );

  my ( $m, $user );
  lives_ok { $m = RPX->new( $config, $c, $realm, ) } "Create Credential ( XFAIL )";
  can_ok( $m, qw( new authenticate authenticate_rpx ) );

  lives_ok { $user = $m->authenticate( $c, $realm, ); } "Authenticate Credential ( XFAIL )"; 
  is_deeply( $user, $Net::API::RPX::RESPONSES->{'B'} , "Failure Message is sent");
}
