#!/usr/bin/perl

#
# Copyright (C) 2016 Joel C. Maslak
# All Rights Reserved - See License
#

use lib 'lib';
use JCM::Boilerplate 'script';

use FWCreate::IPTables;
use FWCreate::Mikrotik;

use List::Util qw/any/;
use Regexp::Common;

MAIN: {
    my $type = $ARGV[0] // 'iptables';

    if ( $type !~ m/^(iptables|mikrotik)$/ ) {
        die("Outputs supported are iptables or mikrotik, not $type");
    }

    my $state = {
        done       => 0,
        line       => 0,
        file       => '__NONE__',
        line_start => 0,
        var        => {},
        list       => {
            iface => {},
            net   => {},
            port  => {},
        },
        in     => [],
        mangle => [],
        nat    => [],
        out    => [],
    };

    if ( exists( $ARGV[1] ) ) {
        read_file( $state, $ARGV[1] );
    } else {
        read_file( $state, undef );
    }

    my $output;
    if ( $type eq 'iptables' ) {
        $output = FWCreate::IPTables->new( rules => $state );
    } elsif ( $type eq 'mikrotik' ) {
        $output = FWCreate::Mikrotik->new( rules => $state );
    } else {
        die("Invalid type: $type");
    }

    $output->output();
}

sub read_file ( $state, $file = undef ) {
    my $fh;
    if ( !defined($file) ) {
        $file = "__STDIN__";
        $fh   = *STDIN;
    } else {
        open $fh, '<', $file or die("could not open $file: $!");
    }

    my $oldline = $state->{line};
    my $oldfile = $state->{file};

    $state->{line} = 0;
    $state->{file} = $file;

    my $command = '';
    while ( my $line = <$fh> ) {
        chomp $line;
        $state->{line}++;

        # Remove comments
        $line =~ s/#.*$//ms;

        # Trim strim, merge whitespace
        # Note that leading whitespace is significant
        $line =~ s/\s+/ /msg;
        $line =~ s/\s+$//ms;

        # We also treat commas like space (syntactic sugar)
        $line =~ s/;/ /msg;

        # Skip blank lines
        if ( $line eq '' ) { next; }

        # Lines that start with a space are continuations
        if ( $line =~ m/^\s/ ) {
            $line =~ s/^\s+//ms;
            $command .= ' ' . $line;
        } else {
            process_line( $state, $command );
            $state->{line_start} = $state->{line};
            $line =~ s/^\s+//ms;
            $command = $line;
        }
    }
    process_line( $state, $command );

    $state->{line} = $oldline;
    $state->{file} = $oldfile;
}

sub process_line ( $state, $cmd ) {
    if ( !defined($cmd) ) { return; }
    if ( $cmd eq '' )     { return; }
    if ( $state->{end} )  { return; }    # We are in __END__ block

    my (@parts) = split /\s+/, $cmd;
    given ( $parts[0] ) {
        when ('in') { cmd_in( $state, @parts ) }
        when ('include') { cmd_include( $state, @parts ) }
        when ('list') { cmd_list( $state, @parts ) }
        when ('mangle') { cmd_mangle( $state, @parts ) }
        when ('nat') { cmd_nat( $state, @parts ) }
        when ('out') { cmd_out( $state, @parts ) }
        when ('var') { cmd_var( $state, @parts ) }
        when ('__END__') { $state->{end} = 1; }
        default {
            die_line( $state, "Unknown command '" . $parts[0] . "'" );
        }
    }
}

sub cmd_include ( $state, @cmd ) {
    shift @cmd;
    if ( scalar(@cmd) > 1 ) {
        die_line( $state,
            "include requires only a filename without white space" );
    }

    read_file( $state, $cmd[0] );
}

sub cmd_list ( $state, @cmd ) {
    shift @cmd;
    if ( scalar(@cmd) < 2 ) {
        die_line( $state,
            "list requires a list type, name, and at least one value" );
    }

    $cmd[0] = lc( $cmd[0] );

    # Do variable substitutions
    for ( my $i = 2; $i < scalar(@cmd); $i++ ) {
        $cmd[$i] = expand_variables( $state, $cmd[$i] );
    }

    given ( $cmd[0] ) {
        when ('iface') { cmd_list_iface( $state, @cmd ) }
        when ('net') { cmd_list_net( $state, @cmd ) }
        when ('port') { cmd_list_port( $state, @cmd ) }
        default { die_line( $state, "Unknown list type '" . $cmd[0] . "'" ) }
    }

}

sub cmd_list_iface ( $state, @cmd ) {
    shift @cmd;

    my $name = lc( shift @cmd );
    $state->{list}{iface}{$name} = [@cmd];

    ### parsed list / iface: $name
    ###  values: @cmd
}

sub cmd_list_net ( $state, @cmd ) {
    shift @cmd;

    my $name = lc( shift @cmd );
    $state->{list}{net}{$name} = [@cmd];

    ### parsed list / net: $name
    ###  values: @cmd
}

sub cmd_list_port ( $state, @cmd ) {
    shift @cmd;

    my $name = lc( shift @cmd );
    $state->{list}{port}{$name} = [@cmd];

    ### parsed list / port: $name
    ###  values: @cmd
}

sub cmd_mangle ( $state, @cmd ) {
    shift @cmd;

    # FORMAT:
    #               <type>         <other required>
    my %elements = (
        if_in   => [ 'iface',     [] ],
        if_out  => [ 'iface',     [] ],
        sport   => [ 'port',      ['proto'] ],
        dport   => [ 'port',      ['proto'] ],
        proto   => [ 'proto:tcp', [] ],
        src     => [ 'ip',        [] ],
        dst     => [ 'ip',        [] ],
        max_mss => [ 'int16',     ['proto'] ],
    );

    my %mangle;

    while ( scalar(@cmd) ) {
        my $type = lc shift(@cmd);
        if ( !defined( $elements{$type} ) ) {
            die_line( $state,
                "attribute '$type' not valid for mangle commands" );
        }

        if ( !scalar(@cmd) ) {
            die_line( $state, "attribute '$type' requires a value" );
        }
        my $val = expand_variables( $state, shift(@cmd) );
        validate_value( $state, $elements{$type}->[0], $val );
        $mangle{$type} = $val;
    }

    foreach my $key ( keys %mangle ) {
        if ( !defined( $mangle{max_mss} ) ) {
            die_line( $state, "mangle command must define max_mss attribute" );
        }
        if (   ( scalar( $elements{$key}->[1]->@* ) != 0 )
            && ( any { !exists( $mangle{$_} ) } $elements{$key}->[1]->@* ) )
        {
            die_line( $state,
                    "mangle attribute '$key' requires attributes '"
                  . join( "', '", $elements{$key}->[1]->@* )
                  . "' to be set" );
        }
    }

    push $state->{mangle}->@*, \%mangle;
}

sub cmd_nat ( $state, @cmd ) {
    shift @cmd;

    # FORMAT:
    #               <type>         <other required>
    my %elements = (
        if_in  => [ 'iface',          ['dnat'] ],
        if_out => [ 'iface',          ['snat'] ],
        sport  => [ 'port',           ['proto'] ],
        dport  => [ 'port',           ['proto'] ],
        proto  => [ 'proto',          [] ],
        src    => [ 'ip',             [] ],
        dst    => [ 'ip',             [] ],
        snat   => [ 'natip:opt_port', ['snat'] ],
        dnat   => [ 'natip:opt_port', ['dnat'] ],
    );

    my %nat;

    while ( scalar(@cmd) ) {
        my $type = lc shift(@cmd);
        if ( !defined( $elements{$type} ) ) {
            die_line( $state, "attribute '$type' not valid for nat commands" );
        }

        if ( !scalar(@cmd) ) {
            die_line( $state, "attribute '$type' requires a value" );
        }
        my $val = expand_variables( $state, shift(@cmd) );
        validate_value( $state, $elements{$type}->[0], $val );
        $nat{$type} = $val;
    }

    foreach my $key ( keys %nat ) {
        if ( !( defined( $nat{snat} ) || defined( $nat{dnat} ) ) ) {
            die_line( $state, "nat command must define either snat or dnat ",
                "attribute" );
        }
        if ( defined( $nat{snat} ) && defined( $nat{dnat} ) ) {
            die_line( $state,
                "nat snat and dnat are incompatible with each other" );
        }
        if (   ( scalar( $elements{$key}->[1]->@* ) != 0 )
            && ( any { !exists( $nat{$_} ) } $elements{$key}->[1]->@* ) )
        {
            die_line( $state,
                    "nat attribute '$key' requires attributes '"
                  . join( "', '", $elements{$key}->[1]->@* )
                  . "' to be set" );
        }
    }

    if ( ( !defined( $nat{proto} ) ) || ( $nat{proto} !~ m/^(tcp|udp)$/ ) ) {
        foreach my $ele ( keys %elements ) {
            if ( !defined( $nat{$ele} ) ) { next; }
            if ( $elements{$ele}->[0] eq 'port' ) {
                die_line(
                    $state,
                    "Cannot specify a '$ele' unless you also ",
                    "specify proto udp or proto tcp"
                );
            } elsif ( $elements{$ele}->[0] eq 'natip:opt_port' ) {
                if ( $nat{$ele} =~ /:/ ) {
                    die_line(
                        $state,
                        "Cannot specify a '$ele' port number ",
                        "unless you also specify proto udp or proto tcp"
                    );
                }
            }
        }
    }

    push $state->{nat}->@*, \%nat;
}

sub cmd_in ( $state, @cmd ) {
    cmd_in_out( 'in', $state, @cmd );
}

sub cmd_out ( $state, @cmd ) {
    cmd_in_out( 'out', $state, @cmd );
}

sub cmd_in_out ( $ctype, $state, @cmd ) {
    if ( $ctype !~ m/^(in|out)$/ ) {
        confess "not a valid command type: $ctype";
    }
    shift @cmd;

    # FORMAT:
    #               <type>         <other required>
    my %elements = (
        if_in  => [ 'iface',  [] ],
        if_out => [ 'iface',  [] ],
        sport  => [ 'port',   ['proto'] ],
        dport  => [ 'port',   ['proto'] ],
        proto  => [ 'proto',  [] ],
        src    => [ 'ip',     [] ],
        dst    => [ 'ip',     [] ],
        action => [ 'action', [] ],
    );

    my %inout;

    while ( scalar(@cmd) ) {
        my $type = lc shift(@cmd);
        if ( !defined( $elements{$type} ) ) {
            die_line( $state,
                "attribute '$type' not valid for $ctype commands" );
        }

        if ( !scalar(@cmd) ) {
            die_line( $state, "attribute '$type' requires a value" );
        }
        my $val = expand_variables( $state, shift(@cmd) );
        validate_value( $state, $elements{$type}->[0], $val );
        $inout{$type} = $val;
    }

    foreach my $key ( keys %inout ) {
        if ( !defined( $inout{action} ) ) {
            die_line( $state, "$ctype command must define an action" );
        }
        if (   ( scalar( $elements{$key}->[1]->@* ) != 0 )
            && ( any { !exists( $inout{$_} ) } $elements{$key}->[1]->@* ) )
        {
            die_line( $state,
                    "ip attribute '$key' requires attributes '"
                  . join( "', '", $elements{$key}->[1]->@* )
                  . "' to be set" );
        }
    }

    if ( ( !exists( $inout{proto} ) ) || ( $inout{proto} !~ m/^(tcp|udp)$/ ) ) {
        foreach my $ele ( keys %elements ) {
            if ( !defined( $inout{$ele} ) ) { next; }
            if ( $elements{$ele}->[0] eq 'port' ) {
                die_line(
                    $state,
                    "Cannot specify a '$ele' unless you also ",
                    "specify proto udp or proto tcp"
                );
            }
        }
    }

    if ( exists( $inout{if_in} ) && $ctype ne 'in' ) {
        die_line( $state, "Cannot specify if_in in $ctype command" );
    }
    if ( exists( $inout{if_out} ) && $ctype ne 'out' ) {
        die_line( $state, "Cannot specify if_out in $ctype command" );
    }

    push $state->{$ctype}->@*, \%inout;
}

sub cmd_var ( $state, @cmd ) {
    shift @cmd;
    if ( scalar(@cmd) < 2 ) {
        die_line( $state, "var requires a variable name and value" );
    }
    if ( scalar(@cmd) > 2 ) {
        die_line( $state, "value must only have one part" );
    }

    my $var = lc( $cmd[0] );
    my $val = $cmd[1];

    $state->{var}{$var} = $val;
    ### parsed var: "$var = $val"
}

sub expand_variables ( $state, $val ) {
    if ( $val !~ m/\$/ ) { return $val }

    while ( $val =~ m/\$/ ) {
        my ($var) = $val =~ m/\$([A-Za-z0-9_]+)/;
        if ( !defined($var) ) {
            die_line( $state,
                "variable name must consist of alphanumerics only" );
        }

        $var = lc($var);
        if ( !defined( $state->{var}{$var} ) ) {
            die_line( $state, "variable $var not defined" );
        }

        my $sub = $state->{var}{$var};
        $val =~ s/\$([A-Za-z0-9_]+)/$sub/;
    }
    return $val;
}

sub validate_value ( $state, $type, $val ) {

    $type = lc($type);
    given ($type) {
        when ('action') {
            if ( $val !~ m/^(pass|drop|droplog|reject|rejectlog|needtunnel)$/ ) {
                die_line( $state, "$val is not a valid action" );
            }
        }
        when ('iface') {
            if ( $val =~ m/^<(.*)>$/ ) {
                my $tname = $val =~ m/^<(.*)>$/;
                if ( !defined( $state->{list}{iface} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } elsif ( $val !~ m/^[a-z]([a-z_\d]*)((\.\d+)?)$/i ) {
                die_line( $state, "$val is not a valid interface" );
            }
        }
        when ('int16') {
            if ( $val !~ m/^\d+$/ ) {
                die_line( $state,
                    "$val is not an integer between 0 and 65535" );
            }
        }
        when ('ip') {
            if ( $val =~ m/^<(.*)>$/ ) {
                my $tname = $val =~ m/^<(.*)>$/;
                if ( !defined( $state->{list}{net} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } elsif ( $val =~ m/^!<(.*)>$/ ) {
                my $tname = $val =~ m/^!<(.*)>$/;
                if ( !defined( $state->{list}{net} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } elsif ( $val !~ m/^$RE{net}{IPv4}(?:(?:\/\d+)?)$/ ) {
                die_line( $state, "$val is not a valid ip address" );
            }
        }
        when ('iplist') {
            if ( $val =~ m/^<(.*)>$/ ) {
                my $tname = $val =~ m/^<(.*)>$/;
                if ( !defined( $state->{list}{net} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } else {
                die_line( $state, "$val is not a valid ip list name" );
            }
        }
        when ('natip') {
            if ( $val =~ m/^<(.*)>$/ ) {
                my $tname = $val =~ m/^<(.*)>$/;
                if ( !defined( $state->{list}{net} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } elsif ( $val eq 'masquerade' ) {
                # We are okay
            } elsif ( $val eq 'none' ) {
                # We are okay
            } elsif ( $val !~ m/^$RE{net}{IPv4}$/ ) {
                die_line( $state, "$val is not a valid ip address" );
            }
        }
        when ('natip:opt_port') {
            my ( $ip, $port ) = split /:/, $val;
            validate_value( $state, 'natip', $ip );
            if ( defined($port) ) { validate_value( $state, 'port', $port ) }
        }
        when ('port') {
            if ( $val =~ m/^<(.*)>$/ ) {
                my $tname = $val =~ m/^<(.*)>$/;
                if ( !defined( $state->{list}{port} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } elsif ( $val !~ m/^\d+$/ ) {
                die_line( $state, "$val is not a valid port" );
            }
        }
        when ('proto') {
            if ( $val !~ m/^(icmp|tcp|udp|(\d+))$/i ) {
                die_line( $state, "$val is not a valid protocol" );
            }
        }
        when ('proto:tcp') {
            if ( $val !~ m/^(tcp)$/i ) {
                die_line( $state, "$val not allowed, must be tcp" );
            }
        }

        default { confess("unknown type") }
    }
}

sub die_line ( $state, @msg ) {
    my $file = $state->{file};
    say STDERR ( "Input file [ $file ] line "
          . $state->{line_start} . ": "
          . join( " ", @msg ) );
    exit 1;
}

1;

