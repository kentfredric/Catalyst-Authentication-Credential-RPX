package Catalyst::Authentication::Credential::RPX;

# ABSTRACT: Use Janarains RPX service for Credentials

use strict;
use warnings;
use Moose;
use MooseX::Types::Moose qw( :all );
use MooseX::Has::Sugar;
use namespace::autoclean;
use Net::API::RPX;

has '_config'        => ( isa => HashRef, rw, required, );
has '_app'           => ( isa => Object,  rw, required, );
has '_realm'         => ( isa => Object,  rw, required, );
has 'api_key'        => ( isa => Str,     rw, required, );
has 'base_url'       => ( isa => Str,     rw, predicate => 'has_base_url', );
has 'ua'             => ( isa => Str,     rw, predicate => 'has_ua', );
has 'token_field'    => ( isa => Str,     rw, default => 'token' );
has 'last_auth_info' => ( isa => HashRef, rw, predicate => 'has_last_auth_info', clearer => 'clear_last_auth_info' );

has '_api_driver' => (
  lazy_build, ro,
  isa      => Object,
  init_arg => undef,
  handles  => [qw( map unmap mappings )],
);

sub BUILDARGS {
  my $class = shift;
  if ( @_ == 3 ) {
    my %args = (
      _config => $_[0],
      _app    => $_[1],
      _realm  => $_[2],
    );
    for ( keys %{ $args{'_config'} } ) {
      $args{$_} = $args{'_config'}->{$_};
    }
    return $class->SUPER::BUILDARGS(%args);
  }
  return $class->SUPER::BUILDARGS(@_);
}

sub _build__api_driver {
  my $self = shift;
  my $conf = { api_key => $self->api_key };
  if ( $self->has_base_url ) {
    $conf->{'base_url'} = $self->base_url;
  }
  if ( $self->has_ua ) {
    $conf->{'ua'} = $self->ua;
  }
  return Net::API::RPX->new($conf);
}

sub authenticate {
  my ( $self, $c, $realm, $authinfo ) = @_;
  my $token_field = $self->token_field;
  my $token;

  unless ( exists $c->req->params->{$token_field} ) {
    return undef;
  }

  $token = $c->req->params->{$token_field};

  my $result = $self->auth_info({ token => $token });

  if ( exists $result->{'err'} ){ 
      return undef;
  }
  
  return $result; 

}
sub auth_info { 
    my $self = shift; 
    return $self->_api_driver->auth_info( @_ );
}
around 'auth_info' => sub {
  my $orig = shift;
  my $self = shift;
  $self->clear_last_auth_info if $self->has_last_auth_info;
  my $result = $self->$orig(@_);
  $self->last_auth_info($result);
  return $result;
};

1;

