package Catalyst::Authentication::Credential::RPX;
our $VERSION = '0.0920221';


# ABSTRACT: Use Janarains RPX service for Credentials

use strict;
use warnings;
use Moose;
use MooseX::Types::Moose qw( :all );
use MooseX::Has::Sugar;
use namespace::autoclean;
use Net::API::RPX;



has '_config'     => ( isa => HashRef, rw, required, );
has '_app'        => ( isa => Object,  rw, required, );
has '_realm'      => ( isa => Object,  rw, required, );
has 'api_key'     => ( isa => Str,     ro, required, );
has 'base_url'    => ( isa => Str,     ro, predicate => 'has_base_url', );
has 'ua'          => ( isa => Str,     ro, predicate => 'has_ua', );
has 'token_field' => ( isa => Str,     ro, default => 'token' );

has 'last_auth_info' => (
  rw,
  isa       => HashRef,
  init_arg  => undef,
  predicate => 'has_last_auth_info',
  clearer   => 'clear_last_auth_info',
);

has '_api_driver' => (
  lazy_build, ro,
  isa      => Object,
  init_arg => undef,
  handles  => [qw( auth_info map unmap mappings )],
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

  my $result = $self->authenticate_rpx( { token => $token } );

  if ( exists $result->{'err'} ) {
    return undef;
  }

  return $result;

}

sub authenticate_rpx {
  my $self = shift;
  $self->clear_last_auth_info if $self->has_last_auth_info;
  my $result = $self->_api_driver->auth_info(@_);
  $self->last_auth_info($result);
  return $result;
}

1;


__END__

=pod

=head1 NAME

Catalyst::Authentication::Credential::RPX - Use Janarains RPX service for Credentials

=head1 VERSION

version 0.0920221

=head1 SYNOPSIS

    use Catalyst qw/ Authentication /;

    package MyApp::Controller::Auth; 

    sub login : Local { 
        my ( $self , $c ) = @_; 
        $c->authenticate();
    }

=head1 CONFIGURATION

    __PACKAGE__->config->{'Plugin::Authenticate'} = {
      default_realm => 'RPX_Service',
      realms        => {
        RPX_Service => {
          credential => {
            class => 'RPX',

            # Package Options
            api_key => 'ASDF...',

            # optional fields
            base_url    => 'http://foo.bar.org',
            ua          => 'Firefox',
            token_field => 'token',
          }
        }
      }
    };

=head1 ATTRIBUTES

=over 4

=item * C<api_key>  | C< ro required Str >

The API Key for connecting to the RPX server.

=item * C<base_url>  | C< ro Str predicate=has_base_url >

The URL The RPX server interconnects with.

=item * C<ua> | C< ro Str predicate=has_ua >

The User-Agent String.

=item * C<token_field> | C< ro Str default='token' >

The token to look for in request params 

=item * C<last_auth_info> | C< rw HashRef predicate=has_last_auth_info  clearer=clear_last_auth_info >

The results of the last call to C<< ->auth_info >>

=back

=head1 AUTHOR

  Kent Fredric <kentnl@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2009 by 'Cloudtone Studios'.

This is free software, licensed under:

  The (three-clause) BSD License

=cut


