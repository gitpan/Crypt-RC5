#---------------------------------------------------------------------------#
# Crypt::RC5
#       Date Written:   23-Nov-2001 10:47:02 AM
#       Last Modified:  23-Nov-2001 10:47:04 AM
#       Author:    Kurt Kincaid
#       Copyright (c) 2001, Kurt Kincaid
#           All Rights Reserved
#
# NOTICE:  RC5 is a fast block cipher designed by Ronald Rivest
#          for RSA Data Security (now RSA Security) in 1994. It is a
#          parameterized algorithm with a variable block size, a variable
#          key size, and a variable number of rounds. This particular
#          implementation is 32 bit. As such, it is suggested that a minimum
#          of 12 rounds be performed.
#---------------------------------------------------------------------------#

package Crypt::RC5;

use Exporter;
use warnings;
use strict;
no strict 'refs';

our ( $VERSION, $processed, $key, $rounds, $text, $class, $block, $decrypt, $A, $B, $T, $last, $m, $n, $x, $self );
our ( @L, @S, @EXPORT_OK, @ISA );

@ISA       = qw(Exporter);
@EXPORT_OK = qw($VERSION RC5);
$VERSION   = '1.0';

sub new {
    ( $class, $key, $rounds )  = @_;
    my $self = bless {}, $class;
    my @temp = unpack( "C*", $key );
    my $newKey;
    foreach my $temp ( @temp ) {
        $temp = sprintf( "%lx", $temp );
        if ( length($temp) < 2 ) {
            $temp = "0" . $temp;
        }
        $newKey .= $temp;
    }
    print $newKey, "\n";
    @L = unpack "V*", pack "H*x3", $newKey;
    return $self;
}

sub encrypt {
    ( $self, $text ) = @_;
    return RC5( $text );
}

sub decrypt {
    ( $self, $text ) = @_;
    return RC5( $text, 1 );
}

sub RC5 {
    undef $processed;
    if ( ref $_[0] ) {
        my $self = shift;
    }
    ( $text, $decrypt ) = @_;
    @S = ( $T = 0xb7e15163, map { $T = M( $T + 0x9e3779b9 ) } 0 .. 2 * $rounds );
    for ( 0 .. 3 * ( @S > @L ? @S : @L ) - 1 ) {
        $A = Y( @S, 3 );
        $B = Y( @L, M( $A + $B ) );
    }
    while ( $text =~ /(.{8})/g ) {
        $last = $';
        Process( $1, $decrypt );
    }
    if ( length( $text ) % 8 ) {
        Process( $last, $decrypt );
    }
    return $processed;
}

sub M { ( $m = pop ) + ( $m < 0 || -( $m > ~0 ) ) * 2**32 }

sub L {
    ( $x = pop ) << ( $n = 31 & pop ) | 2**$n - 1 & $x >> 32 - $n;
}

sub Y { $_[ $_ % @_ ] = L( pop, M( $_[ $_ % @_ ] ) + M( $A + $B ) ) }

sub Process {
    ( $block, $decrypt ) = @_;
    ( $A, $B ) = unpack "V2", $block . "\0" x 3;
    $_ = '$A = M( $A+$S[0] );$B = M( $B+$S[1] )';
    $decrypt || eval;
    for ( 1 .. @S - 2 ) {
        $decrypt ? $B = $A ^ L( 32 - ( $A & 31 ), M( $B- $S[ @S - $_ ] ) ) : ( $A = M( $S[ $_ + 1 ] + L( $B, $A ^ $B ) ) );
        $A ^= $B ^= $A ^= $B;
    }
    $decrypt && ( y/+/-/, eval );
    $processed .= pack "V2", $A, $B;
}

1;
__END__

=head1 NAME

Crypt::RC5 - Perl implementation of the RC5 encryption algorithm.

=head1 SYNOPSIS

  use Crypt::RC5;

  $ref = Crypt::RC5->new( $key, $rounds );
  $ciphertext = $ref->encrypt( $plaintext );

  $ref2 = Crypt::RC5->new( $key, $rounds );
  $plaintext2 = $ref2->decrypt( $ciphertext );

=head1 DESCRIPTION

RC5 is a fast block cipher designed by Ronald Rivest for RSA Data Security (now RSA Security) in 1994. It is a parameterized algorithm with a variable block size, a variable key size, and a variable number of rounds. This particular implementation is 32 bit. As such, it is suggested that a minimum of 12 rounds be performed.

Core logic based on "RC5 in 6 lines of perl" at http://www.cypherspace.org

=head1 AUTHOR

Kurt Kincaid (sifukurt@yahoo.com)

Ronald Rivest for RSA Security, Inc.

=head1 SEE ALSO

L<perl>, L<http://www.cypherspace.org>, L<http://www.rsasecurity.com>

=cut
