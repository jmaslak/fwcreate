#!/usr/bin/perl

#
# Copyright (C) 2016 Joel C. Maslak
# All Rights Reserved - See License
#

use JCM::Boilerplate 'script';

use List::Util qw/any/;
use Regexp::Common;

MAIN: {
    my $state = {
        done       => 0,
        line       => 0,
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

    my $command = '';
    while ( my $line = <stdin> ) {
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

    output_iptables($state);
}

sub process_line ( $state, $cmd ) {
    if ( !defined($cmd) ) { return; }
    if ( $cmd eq '' )     { return; }
    if ( $state->{end} )  { return; }    # We are in __END__ block

    my (@parts) = split /\s+/, $cmd;
    given ( $parts[0] ) {
        when ('in') { cmd_in( $state, @parts ) }
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
            if ( $val !~ m/^(pass|drop|reject)$/ ) {
                die_line( $state, "$val is not a valid action" );
            }
        }
        when ('iface') {
            if ( $val =~ m/^<(.*)>$/ ) {
                my $tname = $val =~ m/^<(.*)>$/;
                if ( !defined( $state->{list}{iface} ) ) {
                    die_line( $state, "$val is not a proper table name" );
                }
            } elsif ( $val !~ m/^[a-z]([a-z\d]*)((\.\d+)?)$/i ) {
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
            } elsif ( $val !~ m/^$RE{net}{IPv4}$/ ) {
                die_line( $state, "$val is not a valid ip address" );
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
            if ( $val !~ m/^(icmp|tcp|udp)$/i ) {
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
    say STDERR (
        "Input file line " . $state->{line_start} . ": " . join( " ", @msg ) );
    exit 1;
}

sub output_iptables ( $state ) {
    $state->{iptables} = {
        fwbuild_in      => [],
        fwbuild_out     => [],
        fwbuild_mss     => [],
        fwbuild_snat_in => [],
        fwbuild_snat_pr => [],
        fwbuild_dnat    => [],
    };

    say "#!/bin/bash";
    say "# Programmatically generated! DO NOT EDIT BY HAND!";
    say "";
    say 'IPSET=$(which ipset)';
    say 'if [ $IPSET == "" ] ; then';
    say '    echo "Could not find ipset...bailing" >&2';
    say '    exit 1';
    say 'fi';

    output_iptables_lists($state);

    for my $ctype ( 'mangle', 'nat', 'in', 'out' ) {
        output_iptables_rules( $state, $ctype );
    }

    # the _in table is the same as the _pr table, just with any MASQ
    # rules changed to ACCEPT rules.
    #
    # The "map" is to copy the value, so we don't modifiy it.
    foreach my $s ( map { $_ } $state->{iptables}{fwbuild_snat_pr}->@* ) {
        $s =~ s/-j MASQUERADE/-j ACCEPT/g;
        push $state->{iptables}{fwbuild_snat_in}->@*, $s;
    }

    # Do the actual output here
    say 'iptables-restore <<_IPTABLES_RESTORE_';
    output_iptables_print($state);
    say "_IPTABLES_RESTORE_";
}

sub output_iptables_lists($state) {

    output_iptables_lists_net($state);
    output_iptables_lists_port($state);

}

sub output_iptables_lists_net($state) {
    foreach my $nm ( keys $state->{list}{net}->%* ) {
        output_iptables_list_net( $state, $nm );
    }
}

sub output_iptables_list_net ( $state, $nm ) {
    my $key = $nm;
    my $set = "NET_$nm";

    say "ipset create $set hash:net -exist";
    say "ipset flush $set";

    my $list = $state->{list}{net}{$nm};
    foreach my $net ( $list->@* ) {
        say "ipset add $set $net";
    }
}

sub output_iptables_lists_port($state) {
    foreach my $nm ( keys $state->{list}{port}->%* ) {
        output_iptables_list_port( $state, $nm );
    }
}

sub output_iptables_list_port ( $state, $nm ) {
    my $key = $nm;
    my $set = "PORT_$nm";

    say "ipset create $set bitmap:port range 0-65535 -exist";
    say "ipset flush $set";

    my $list = $state->{list}{port}{$nm};
    foreach my $net ( $list->@* ) {
        say "ipset add $set $net";
    }
}

sub output_iptables_rules ( $state, $ctype ) {
    foreach my $ele ( $state->{$ctype}->@* ) {
        output_iptables_rule_gen( $state, $ctype, $ele );
    }
}

sub output_iptables_rule_gen ( $state, $ctype, $element ) {
    my $chain;
    if ( $ctype eq 'in' ) {
        $chain = 'fwbuild_in';
    } elsif ( $ctype eq 'out' ) {
        $chain = 'fwbuild_out';
    } elsif ( $ctype eq 'mangle' ) {
        # Only do max_mss right now
        $chain = 'fwbuild_mss';
    } elsif ( $ctype eq 'nat' ) {
        if ( exists( $element->{snat} ) ) {
            $chain = 'fwbuild_snat_pr';
        } elsif ( exists( $element->{dnat} ) ) {
            $chain = 'fwbuild_dnat';
        } else {
            die("Unknown nat type on rule");    # XXX should have more info
        }
    } else {
        die("Unknown command type: $ctype");
    }

    my $rule = '';

    # Keys are sort-val (4 chars) followed by the field name
    my %keytype = (
        '000_if_in'   => 'iface',
        '001_if_out'  => 'iface',
        '002_proto'   => 'proto',
        '003_src'     => 'ip',
        '004_sport'   => 'port',
        '005_dst'     => 'ip',
        '006_dport'   => 'port',
        '007_dnat'    => 'natip:opt_port',
        '008_snat'    => 'natip:opt_port',
        '009_max_mss' => 'int16',
        '010_action'  => '',
    );

    my (%working) =
      $element->%*;    # We remove keys from here when we process them
                       # This lets us validate we saw
                       # everything.

    my ( @in_interfaces, @out_interfaces );
    foreach my $sorted ( sort keys %keytype ) {
        my $key = $sorted;
        $key =~ s/^\d\d\d_//;

        if ( !exists( $element->{$key} ) ) { next; }    # Not defined

        delete $working{$key};

        # Variable substitution
        foreach my $var ( keys $state->{var}->%* ) {
            my $val = $state->{var}{$var};
            $element->{$key} =~ s/\$$var/$val/g;
        }

        # Handle parameters
        if ( $key eq 'if_in' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                push @in_interfaces, $state->{list}{iface}{$set}->@*;
            } else {
                $rule .= ' -i ' . $element->{$key};
            }
        } elsif ( $key eq 'if_out' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                push @out_interfaces, $state->{list}{iface}{$set}->@*;
            } else {
                $rule .= ' -o ' . $element->{$key};
            }
        } elsif ( $keytype{$sorted} eq 'port' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                my $dir = $key eq 'sport' ? 'src' : 'dst';
                $rule .= " -m set --match-set PORT_$set $dir";
            } else {
                my $type = $key eq 'sport' ? 'sport' : 'dport';
                $rule .= " --$type " . $element->{$key} . " ";
            }
        } elsif ( $keytype{$sorted} eq 'ip' ) {
            my $ele = $element->{$key};

            my $neg = $ele =~ m/^!/;
            $ele =~ s/^!//;
            my $opt = $neg ? '! ' : '';

            if ( $ele =~ m/^<.*>$/ ) {
                my ($set) = $ele =~ m/^<(.*)>$/;
                my $dir = $key;
                $rule .= " -m set $opt --match-set NET_$set $dir";
            } else {
                my $dir = $key;
                $rule .= " $opt --$dir $ele";
            }
        } elsif ( $key eq 'max_mss' ) {
            $rule .= " -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "
              . $element->{$key};
        } elsif ( $key eq 'snat' ) {
            if ( $element->{$key} eq 'none' ) {
                $rule .= " -j ACCEPT";
            } elsif ( $element->{$key} eq 'masquerade' ) {
                $rule .= " -j MASQUERADE";
            } else {
                $rule .= " -j SNAT --to-source " . $element->{$key};
            }
        } elsif ( $key eq 'dnat' ) {
            if ( $element->{$key} eq 'none' ) {
                $rule .= " -j ACCEPT";
            } else {
                $rule .= " -j DNAT --to-destination " . $element->{$key};
            }
        } elsif ( $key eq 'proto' ) {
            $rule .= " --proto " . $element->{$key};
            if ( $element->{$key} =~ m/^(tcp|udp)$/ ) {
                $rule .= " -m " . $element->{$key};
            }
        } elsif ( $key eq 'action' ) {
            if ( $element->{$key} eq 'pass' ) {
                $rule .= ' -j RETURN';    # A return is considered an okay
                                          # response
            } elsif ( $element->{$key} eq 'drop' ) {
                $rule .= ' -j DROP';
            } elsif ( $element->{$key} eq 'reject' ) {
                $rule .= ' -j fwbuild_reject';
            } else {
                die( "Unhandled action: " . $element->{$key} );
            }
        }
    }

    if ( keys %working > 0 ) {
        die( "Unhandled keys: ", join( ',', keys %working ) );
    }

    $rule =~ s/^\s+//g;
    $rule =~ s/\s+$//g;
    $rule =~ s/\s+/ /g;

    # We know @out_interfaces and @in_interfaces can't both be
    # simultaniously defined.
    if (@out_interfaces) {
        foreach my $if (@out_interfaces) {
            my $newrule = "-o $if $rule";
            push $state->{iptables}{$chain}->@*, $newrule;
        }
    } elsif (@in_interfaces) {
        foreach my $if (@in_interfaces) {
            my $newrule = "-i $if $rule";
            push $state->{iptables}{$chain}->@*, $newrule;
        }
    } else {
        push $state->{iptables}{$chain}->@*, $rule;    # Add rule to chain
    }
}

sub output_iptables_print ( $state, $fh = \*stdout ) {
    my %tabletype = (
        fwbuild_in      => 'filter',
        fwbuild_out     => 'filter',
        fwbuild_mss     => 'mangle',
        fwbuild_snat_in => 'nat',
        fwbuild_snat_pr => 'nat',
        fwbuild_dnat    => 'nat',
    );

    # Do Mangle tables
    say $fh "*mangle";
    say $fh ":PREROUTING ACCEPT [0:0]";
    say $fh ":POSTROUTING ACCEPT [0:0]";
    say $fh ":INPUT ACCEPT [0:0]";
    say $fh ":FORWARD ACCEPT [0:0]";
    say $fh ":OUTPUT ACCEPT [0:0]";
    say $fh "-N fwbuild_mss";
    say $fh "-A PREROUTING  -j fwbuild_mss";
    say $fh "-A POSTROUTING -j fwbuild_mss";
    say $fh "-A OUTPUT      -j fwbuild_mss";

    foreach my $chain ( grep { $tabletype{$_} eq 'mangle' } keys %tabletype ) {
        output_iptables_chain_print( $state, $chain, $fh );
    }

    say $fh "COMMIT";

    # Do NAT tables
    say $fh "*nat";
    say $fh ":PREROUTING ACCEPT [0:0]";
    say $fh ":POSTROUTING ACCEPT [0:0]";
    say $fh ":INPUT ACCEPT [0:0]";
    say $fh ":OUTPUT ACCEPT [0:0]";
    say $fh "-N fwbuild_snat_in";
    say $fh "-N fwbuild_snat_pr";
    say $fh "-N fwbuild_dnat";
    say $fh "-A PREROUTING  -j fwbuild_dnat";
    say $fh "-A OUTPUT      -j fwbuild_dnat";
    say $fh "-A POSTROUTING -j fwbuild_snat_pr";
    say $fh "-A INPUT       -j fwbuild_snat_in";

    foreach my $chain ( grep { $tabletype{$_} eq 'nat' } keys %tabletype ) {
        output_iptables_chain_print( $state, $chain, $fh );
    }

    say $fh "COMMIT";

    # Do Filter tables
    say $fh "*filter";
    say $fh ":INPUT DROP [0:0]";
    say $fh ":FORWARD DROP [0:0]";
    say $fh ":OUTPUT DROP [0:0]";
    say $fh "-N fwbuild_in";
    say $fh "-N fwbuild_out";
    say $fh "-N fwbuild_reject";
    say $fh "-A INPUT -j fwbuild_in";
    say $fh "-A INPUT -j ACCEPT";
    say $fh "-A FORWARD -j fwbuild_in";
    say $fh "-A FORWARD -j fwbuild_out";
    say $fh "-A FORWARD -j ACCEPT";
    say $fh "-A OUTPUT -j fwbuild_out";
    say $fh "-A OUTPUT -j ACCEPT";

    say $fh
      "-A fwbuild_reject -p udp -j REJECT --reject-with icmp-port-unreachable";
    say $fh "-A fwbuild_reject -p tcp -j REJECT --reject-with tcp-reset";
    say $fh "-A fwbuild_reject -j REJECT --reject-with icmp-proto-unreachable";

    say $fh
"-A fwbuild_in -m conntrack --ctstate INVALID,RELATED,ESTABLISHED -j ACCEPT";
    say $fh
"-A fwbuild_out -m conntrack --ctstate INVALID,RELATED,ESTABLISHED -j ACCEPT";

    foreach my $chain ( grep { $tabletype{$_} eq 'filter' } keys %tabletype ) {
        output_iptables_chain_print( $state, $chain, $fh );
    }

    say $fh "-A fwbuild_in  -j LOG";
    say $fh "-A fwbuild_in  -j DROP";
    say $fh "-A fwbuild_out -j LOG";
    say $fh "-A fwbuild_out -j DROP";

    say $fh "COMMIT";
}

sub output_iptables_chain_print ( $state, $chain, $fh ) {
    my (@rules) = $state->{iptables}{$chain}->@*;
    foreach my $rule (@rules) {
        say $fh "-A $chain $rule";
    }
}

1;

