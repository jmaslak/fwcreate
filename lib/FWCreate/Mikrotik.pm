#!/usr/bin/perl

#
# Copyright (C) 2016 Joel C. Maslak
# All Rights Reserved - See License
#

package FWCreate::Mikrotik v0.01.00;

use JCM::Boilerplate 'class';

my $MAXPORTS = 15;    # Max ports in a Mikrotik rule port list

has rules => (
    is       => 'rw',
    isa      => 'HashRef',
    required => 1,
);

has family => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has in => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has out => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has dscp => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has mark => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has mss => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has snat => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has dnat => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

sub output ( $self, $fh = \*STDOUT ) {

    if ( $self->family !~ m/^ipv[46]$/s ) {
        die( "Unsupported address family: " . $self->family . "\n" );
    }

    say $fh "# Programmatically generated! DO NOT EDIT BY HAND!";
    say $fh "# Mikrotik Router Configuration Script";
    say $fh "";

    $self->output_lists($fh);

    for my $ctype ( 'mangle', 'nat', 'in', 'out', 'dscp', 'mark' ) {
        if ( ( $self->family ne 'ipv6' ) || ( $ctype ne 'nat' ) ) {
            $self->output_rules($ctype);
        }
    }

    # Do the actual output here
    $self->output_print($fh);

    my $fam = $self->family;
    if ($fam eq 'ipv4') { $fam = 'ip'; }

    if ($fam ne 'ipv6') {
        say $fh "/$fam firewall nat remove [ find chain=postrouting ]";
        say $fh "/$fam firewall nat remove [ find chain=srcnat ]";
        say $fh "/$fam firewall nat add chain=srcnat action=jump jump-target=fwbuild_snat";
        say $fh "/$fam firewall nat remove [ find chain=input ]";
        say $fh "/$fam firewall nat remove [ find chain=dstnat ]";
        say $fh "/$fam firewall nat add chain=dstnat action=jump jump-target=fwbuild_dnat";
    }

    say $fh "/$fam firewall filter remove ", "[ /$fam firewall filter find chain=input ]";
    say $fh "/$fam firewall filter add chain=input action=jump jump-target=fwbuild_in";
    say $fh "/$fam firewall filter add chain=input action=accept";
    say $fh "/$fam firewall filter remove ", "[ /$fam firewall filter find chain=forward ]";
    say $fh "/$fam firewall filter add chain=forward action=jump ", "jump-target=fwbuild_in";
    say $fh "/$fam firewall filter add chain=forward action=jump ", "jump-target=fwbuild_out";
    say $fh "/$fam firewall filter add chain=forward action=accept";
    say $fh "/$fam firewall filter remove ", "[ /$fam firewall filter find chain=output ]";
    say $fh "/$fam firewall filter add chain=output action=jump ", "jump-target=fwbuild_out";
    say $fh "/$fam firewall filter add chain=output action=accept";

    say $fh "/$fam firewall mangle remove ", "[ /$fam firewall mangle find chain=postrouting ]";
    say $fh "/$fam firewall mangle add chain=postrouting action=jump ", "jump-target=fwbuild_mark";
    say $fh "/$fam firewall mangle add chain=postrouting action=jump ", "jump-target=fwbuild_dscp";
    say $fh "/$fam firewall mangle add chain=postrouting action=jump ", " jump-target=fwbuild_mss";
    say $fh "/$fam firewall mangle remove ", "[ /$fam firewall mangle find chain=output ]";
    say $fh "/$fam firewall mangle add chain=output action=jump ", "jump-target=fwbuild_mss";
}

sub output_lists ( $self, $fh ) {

    $self->output_lists_interface($fh);
    $self->output_lists_net($fh);
    $self->output_lists_port($fh);

}

sub output_lists_interface ( $self, $fh ) {
    foreach my $nm ( sort keys $self->rules->{list}{iface}->%* ) {
        $self->output_list_interface( $nm, $fh );
    }
}

sub output_list_interface ( $self, $nm, $fh ) {
    my $key = $nm;
    my $set = "IF_$nm";

    say $fh ":if ( [ /interface list find name=$set ] = \"\" ) do={";
    say $fh "  /interface list add name=$set";
    say $fh "}";

    say $fh "/interface list member remove [ find list=$set ]";

    my $list = $self->rules->{list}{iface}->{$key};
    foreach my $iface ( $list->@* ) {
        say $fh "/interface list member add list=$set interface=$iface";
    }
}

sub output_lists_net ( $self, $fh ) {
    foreach my $nm ( sort keys $self->rules->{list}{net}->%* ) {
        $self->output_list_net( $nm, $fh );
    }
}

sub output_list_net ( $self, $nm, $fh ) {
    my $key = $nm;
    my $set = "NET_$nm";

    my $fam = $self->family;
    if ($fam eq 'ipv4') { $fam = 'ip'; }

    say $fh "/$fam firewall address-list remove ", "[ /$fam firewall address-list find list=$set ]";

    my $list = $self->rules->{list}{net}->{$key};
    foreach my $net ( $list->@* ) {
        say $fh "/$fam firewall address-list add list=$set address=$net";
    }
}

sub output_lists_port ( $self, $fh ) {
    # We don't do anything - Mikrotik doesn't have port lists like ipset
}

sub output_rules ( $self, $ctype ) {
    foreach my $ele ( $self->rules->{$ctype}->@* ) {
        $self->output_rule_gen( $ctype, $ele );
    }
}

sub output_rule_gen ( $self, $ctype, $element ) {
    state $warned_needtunnel = undef;

    my $chain;
    if ( $ctype eq 'in' ) {
        $chain = $self->in;
    } elsif ( $ctype eq 'out' ) {
        $chain = $self->out;
    } elsif ( $ctype eq 'mangle' ) {
        # Only do max_mss right now
        $chain = $self->mss;
    } elsif ( $ctype eq 'nat' ) {
        if ( exists( $element->{snat} ) ) {
            $chain = $self->snat;
        } elsif ( exists( $element->{dnat} ) ) {
            $chain = $self->dnat;
        } else {
            die("Unknown nat type on rule");    # XXX should have more info
        }
    } elsif ( $ctype eq 'mark' ) {
        $chain = $self->mark;
    } elsif ( $ctype eq 'dscp' ) {
        $chain = $self->dscp;
    } else {
        die("Unknown command type: $ctype");
    }

    my $rule = '';

    # Keys are sort-val (4 chars) followed by the field name
    my %keytype = (
        '000_if_in'    => 'iface',
        '001_if_out'   => 'iface',
        '002_proto'    => 'proto',
        '003_src'      => 'ip',
        '004_sport'    => 'port',
        '005_dst'      => 'ip',
        '006_dport'    => 'port',
        '007_dnat'     => 'natip:opt_port',
        '008_snat'     => 'natip:opt_port',
        '009_max_mss'  => 'int16',
        '010_dscp'     => 'dscp',
        '011_action'   => '',
        '012_set_dscp' => '',
        '013_set_mark' => '',
    );

    my (%working) = $element->%*;    # We remove keys from here when we process them
                                     # This lets us validate we saw
                                     # everything.

    my ( @src_ports, @dst_ports );
    foreach my $sorted ( sort keys %keytype ) {
        my $key = $sorted;
        $key =~ s/^\d\d\d_//;

        if ( !exists( $element->{$key} ) ) { next; }    # Not defined

        delete $working{$key};

        # Variable substitution
        foreach my $var ( keys $self->rules->{var}->%* ) {
            my $val = $self->rules->{var}{$var};
            $element->{$key} =~ s/\$$var/$val/g;
        }

        # Handle parameters
        if ( $key eq 'if_in' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                $rule .= ' in-interface-list=IF_' . $set;
            } else {
                $rule .= ' in-interface=' . $element->{$key};
            }
        } elsif ( $key eq 'if_out' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                $rule .= ' out-interface-list=IF_' . $set;
            } else {
                $rule .= ' out-interface=' . $element->{$key};
            }
        } elsif ( $keytype{$sorted} eq 'port' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                # It is a port list
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                my $setlist = $self->rules->{list}{port}{$set};

                if ( @$setlist == 0 ) {
                    next;    # We don't add a rule
                } elsif ( @$setlist <= $MAXPORTS ) {
                    # Microtik lets us have a list <= $MAXPORTS long
                    my $type = $key eq 'sport' ? 'src-port' : 'dst-port';
                    $rule .= " $type=" . join( ',', @$setlist ) . " ";
                } elsif ( $key eq 'sport' ) {
                    # We have > $MAXPORTS
                    push @src_ports, $self->rules->{list}{port}{$set}->@*;
                } elsif ( $key eq 'dport' ) {
                    # We have > $MAXPORTS
                    push @dst_ports, $self->rules->{list}{port}{$set}->@*;
                } else {
                    # Something is really wrong here...
                    die("Unknown port type: $key");
                }

            } else {
                # It's not a port list
                my $type = $key eq 'sport' ? 'src-port' : 'dst-port';
                $rule .= " $type=" . $element->{$key} . " ";
            }
        } elsif ( $key eq 'dscp' ) {
            $rule .= ' dscp=' . $element->{$key};
        } elsif ( $key eq 'set_dscp' ) {
            $rule .= ' action=change-dscp passthrough=no new-dscp=' . $element->{$key};
        } elsif ( $key eq 'set_mark' ) {
            $rule .= ' action=mark-packet passthrough=no new-packet-mark=' . $element->{$key};
        } elsif ( $keytype{$sorted} eq 'ip' ) {
            my $ele = $element->{$key};

            my $neg = $ele =~ m/^!/;
            $ele =~ s/^!//;
            my $opt   = $neg          ? '!'           : '';
            my $field = $key eq 'src' ? 'src-address' : 'dst-address';

            if ( $ele =~ m/^<.*>$/ ) {
                my ($set) = $ele =~ m/^<(.*)>$/;
                $field .= '-list';
                $rule  .= " $field=${opt}NET_$set";
            } else {
                $rule .= " $field=${opt}$ele";
            }
        } elsif ( $key eq 'max_mss' ) {
            my $biggermss = $element->{$key} + 1;
            if ( $biggermss > 65535 ) {
                die("MSS specified as too big ($biggermss)");
            }

            my $mss = $element->{$key};
            $rule .= " tcp-mss=$biggermss-65535 new-mss=$mss tcp-flags=syn";
            $rule .= " action=change-mss";
        } elsif ( $key eq 'snat' ) {
            if ( $element->{$key} eq 'none' ) {
                $rule .= " action=accept";    # Is this right?
            } elsif ( $element->{$key} eq 'masquerade' ) {
                $rule .= " action=masquerade";
            } else {
                my ( $addr, $port ) = split /:/, $element->{$key};
                $rule .= " action=src-nat to-address=$addr";
                if ( defined($port) ) {
                    $rule .= " to-port=$port";
                }
            }
        } elsif ( $key eq 'dnat' ) {
            if ( $element->{$key} eq 'none' ) {
                $rule .= " action=accept";
            } else {
                my ( $addr, $port ) = $element->{$key} =~ m/^([\d\.]+)(?::(\d+))?$/;
                $rule .= " action=dst-nat to-address=$addr";
                if ( defined($port) ) {
                    $rule .= " to-port=$port";
                }
            }
        } elsif ( $key eq 'proto' ) {
            $rule .= " protocol=" . $element->{$key};
        } elsif ( $key eq 'action' ) {
            if ( $element->{$key} eq 'pass' ) {
                $rule .= ' action=accept';    # A return is considered an okay
                                              # response
            } elsif ( $element->{$key} eq 'drop' ) {
                $rule .= ' action=drop';
            } elsif ( $element->{$key} eq 'droplog' ) {
                $rule .= ' log=yes action=drop';
            } elsif ( $element->{$key} eq 'reject' ) {
                $rule .= ' action=jump jump-target=fwbuild_reject';
            } elsif ( $element->{$key} eq 'rejectlog' ) {
                $rule .= ' log=yes action=jump jump-target=fwbuild_reject';
            } elsif ( $element->{$key} eq 'needtunnel' ) {
                if ( $ctype eq 'nat' ) { die "NAT cannot have needtunnel" }
                if ($warned_needtunnel) {
                    next;                     # We already warned.
                }

                $warned_needtunnel = 1;
                warn( "Not configuring needttunnel rules - not applicable to ", "Mikrotik\n" );
                next;
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

    if ( @src_ports || @dst_ports ) {

        my @rules;
        $rules[0] = $rule;

        @rules = expand_list( \@rules, " src-port=",      \@src_ports );
        @rules = expand_list( \@rules, " dst-port=",      \@dst_ports );

        push $chain->@*, @rules;
    } else {
        # No lists defined
        push $chain->@*, $rule;    # Add rule to chain
    }
}

sub get_pending_rules ( $self, $chainname ) {
    my $chain = $chainname;
    $chain =~ s/^fwbuild_//;

    my $pending;
    if ( $chain eq 'in' ) {
        $pending = $self->in;
    } elsif ( $chain eq 'out' ) {
        $pending = $self->out;
    } elsif ( $chain eq 'mss' ) {
        $pending = $self->mss;
    } elsif ( $chain eq 'snat' ) {
        $pending = $self->snat;
    } elsif ( $chain eq 'dnat' ) {
        $pending = $self->dnat;
    } elsif ( $chain eq 'dscp' ) {
        $pending = $self->dscp;
    } elsif ( $chain eq 'mark' ) {
        $pending = $self->mark;
    } else {
        die("Unknown rule type: $chain");
    }

    return $pending;
}

sub output_print ( $self, $fh = \*STDOUT ) {
    my %tabletype = (
        fwbuild_in   => 'filter',
        fwbuild_out  => 'filter',
        fwbuild_mss  => 'mangle',
        fwbuild_snat => 'nat',
        fwbuild_dnat => 'nat',
        fwbuild_dscp => 'mangle',
        fwbuild_mark => 'mangle',
    );

    # Do Mangle tables
    foreach my $chain ( grep { $tabletype{$_} eq 'mangle' } sort keys %tabletype ) {
        $self->output_chain_print( 'mangle', $chain, $fh );
    }

    # Do NAT tables
    foreach my $chain ( grep { $tabletype{$_} eq 'nat' } sort keys %tabletype ) {
        if ($self->family ne 'ipv6') {
            $self->output_chain_print( 'nat', $chain, $fh );
        }
    }

    my $fam = $self->family;
    if ($fam eq 'ipv4') { $fam = 'ip'; }

    # Do Filter tables
    my $filter = "/$fam firewall filter";
    my $ch     = "chain=fwbuild_reject";
    my $reject = "log=yes action=reject";

    # Set up reject rules
    say $fh "$filter remove [ $filter find $ch ]";
    say $fh "$filter add $ch protocol=udp $reject reject-with=icmp-port-unreachable";
    say $fh "$filter add $ch protocol=tcp $reject reject-with=tcp-reset";

    if ($fam eq 'ip') {
        say $fh "$filter add $ch $reject reject-with=icmp-protocol-unreachable";
    } else {
        say $fh "$filter add $ch $reject reject-with=icmp-admin-prohibited";
    }

    # Set up rules
    foreach my $chain ( grep { $tabletype{$_} eq 'filter' } sort keys %tabletype ) {
        $self->output_chain_print( 'filter', $chain, $fh );
    }

    # Default deny
    # Set up existing conn allow rules
    foreach my $v ( "fwbuild_in", "fwbuild_out" ) {
        say $fh "$filter add chain=$v log=yes action=drop";
    }
}

# Type = mangle or filter
sub output_chain_print ( $self, $type, $chain, $fh ) {
    if ( !defined($chain) ) { confess 'Assert failed: $chain is undef' }

    my $fam = $self->family;
    if ($fam eq 'ipv4') { $fam = 'ip'; }

    # Remove old rules
    say $fh "/$fam firewall $type remove ", "[ /$fam firewall $type find chain=$chain ]";

    # Set up existing conn allow rules
    if ( ( $type eq 'filter' ) && ( $chain =~ m/^fwbuild_(in|out)$/ ) ) {
        say $fh
"/$fam firewall $type add chain=$chain connection-state=established,related action=accept";
    }

    my (@rules) = $self->get_pending_rules($chain)->@*;
    foreach my $rule (@rules) {
        say $fh "/$fam firewall $type add chain=$chain $rule";
    }
}

# Adds string to a list and returns a list with that string
# added to each element
sub expand_list ( $src_list, $prefix, $value_list ) {
    if ( @$value_list == 0 ) { return @$src_list }

    my @output;
    foreach my $src (@$src_list) {
        foreach my $value (@$value_list) {
            push @output, "$src$prefix$value";
        }
    }
    return @output;
}

__PACKAGE__->meta->make_immutable;

1;

