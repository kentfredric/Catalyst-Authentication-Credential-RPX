
BEGIN {
  unless ($ENV{AUTHOR_TESTING}) {
    require Test::More;
    Test::More::plan(skip_all => 'these tests are for testing by the author');
  }
}

use strict;
use warnings;
use Test::More;

eval "use Test::Perl::Critic( -profile => 'perlcriticrc' );";
plan skip_all => "Test::Perl::Critic required for testing Against Policy" if $@;
all_critic_ok();
