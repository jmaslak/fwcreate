#!/usr/bin/perl

#
# Copyright (C) 2016 Joel C. Maslak
# All Rights Reserved - See License
#

package FWCreate::IPTables v0.01.00;

use JCM::Boilerplate 'class';

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

has mss => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has snat_in => (
    is       => 'rw',
    isa      => 'ArrayRef',
    required => 1,
    default  => sub { [] },
    init_arg => undef,
);

has snat_pr => (
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

sub output($self) {

    if ($self->family ne 'ipv4') {
        die("Unsupported address family: " . $self->family . "\n");
    }

    say "#!/bin/bash";
    say "# Programmatically generated! DO NOT EDIT BY HAND!";
    say "";
    say 'IPSET=$(which ipset)';
    say 'if [ $IPSET == "" ] ; then';
    say '    echo "Could not find ipset...bailing" >&2';
    say '    exit 1';
    say 'fi';

    $self->output_lists();

    for my $ctype ( 'mangle', 'nat', 'in', 'out' ) {
        $self->output_rules($ctype);
    }

    # the _in table is the same as the _pr table, just with any MASQ
    # rules changed to ACCEPT rules.
    #
    # The "map" is to copy the value, so we don't modifiy it.
    foreach my $s ( map { $_ } $self->snat_pr->@* ) {
        $s =~ s/-j MASQUERADE/-j ACCEPT/g;
        push $self->snat_in->@*, $s;
    }

    # Do the actual output here
    say 'iptables -Z'; # Zero statistics
    say 'iptables-restore <<_IPTABLES_RESTORE_';
    $self->output_print();
    say "_IPTABLES_RESTORE_";
}

sub output_lists($self) {

    $self->output_lists_net();
    $self->output_lists_port();

}

sub output_lists_net($self) {
    foreach my $nm ( sort keys $self->rules->{list}{net}->%* ) {
        $self->output_list_net($nm);
    }
}

sub output_list_net ( $self, $nm ) {
    my $key = $nm;
    my $set = "NET_$nm";

    say "ipset create $set hash:net -exist";
    say "ipset flush $set";

    my $list = $self->rules->{list}{net}->{$key};
    foreach my $net ( $list->@* ) {
        say "ipset add $set $net";
    }
}

sub output_lists_port($self) {
    foreach my $nm ( sort keys $self->rules->{list}{port}->%* ) {
        $self->output_list_port($nm);
    }
}

sub output_list_port ( $self, $nm ) {
    my $key = $nm;
    my $set = "PORT_$nm";

    say "ipset create $set bitmap:port range 0-65535 -exist";
    say "ipset flush $set";

    my $list = $self->rules->{list}{port}->{$key};
    foreach my $net ( $list->@* ) {
        say "ipset add $set $net";
    }
}

sub output_rules ( $self, $ctype ) {
    foreach my $ele ( $self->rules->{$ctype}->@* ) {
        $self->output_rule_gen( $ctype, $ele );
    }
}

sub output_rule_gen ( $self, $ctype, $element ) {
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
            $chain = $self->snat_pr;
        } elsif ( exists( $element->{dnat} ) ) {
            $chain = $self->dnat;
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
        foreach my $var ( keys $self->rules->{var}->%* ) {
            my $val = $self->rules->{var}{$var};
            $element->{$key} =~ s/\$$var/$val/g;
        }

        # Handle parameters
        if ( $key eq 'if_in' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                push @in_interfaces, $self->rules->{list}{iface}{$set}->@*;
            } else {
                $rule .= ' -i ' . $element->{$key};
            }
        } elsif ( $key eq 'if_out' ) {
            if ( $element->{$key} =~ m/^<.*>$/ ) {
                my ($set) = $element->{$key} =~ m/^<(.*)>$/;
                push @out_interfaces, $self->rules->{list}{iface}{$set}->@*;
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
            } elsif ( $element->{$key} eq 'droplog' ) {
                $rule .= ' -j fwbuild_drop_log';
            } elsif ( $element->{$key} eq 'reject' ) {
                $rule .= ' -j fwbuild_reject';
            } elsif ( $element->{$key} eq 'rejectlog' ) {
                $rule .= ' -j fwbuild_reject_log';
            } elsif ( $element->{$key} eq 'needtunnel' ) {
                if ( $ctype eq 'nat' ) { die "NAT cannot have needtunnel" }
                $rule .=
" -m policy --pol none --dir $ctype -j REJECT --reject-with icmp-admin-prohibited";
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
            push $chain->@*, $newrule;
        }
    } elsif (@in_interfaces) {
        foreach my $if (@in_interfaces) {
            my $newrule = "-i $if $rule";
            push $chain->@*, $newrule;
        }
    } else {
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
    } elsif ( $chain eq 'snat_in' ) {
        $pending = $self->snat_in;
    } elsif ( $chain eq 'snat_pr' ) {
        $pending = $self->snat_pr;
    } elsif ( $chain eq 'dnat' ) {
        $pending = $self->dnat;
    } else {
        die("Unknown rule type: $chain");
    }

    return $pending;
}

sub output_print ( $self, $fh = \*STDOUT ) {
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

    foreach
      my $chain ( grep { $tabletype{$_} eq 'mangle' } sort keys %tabletype )
    {
        $self->output_chain_print( $chain, $fh );
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

    foreach my $chain ( grep { $tabletype{$_} eq 'nat' } sort keys %tabletype )
    {
        $self->output_chain_print( $chain, $fh );
    }

    say $fh "COMMIT";

    # Do Filter tables
    say $fh "*filter";
    say $fh ":INPUT DROP [0:0]";
    say $fh ":FORWARD DROP [0:0]";
    say $fh ":OUTPUT DROP [0:0]";
    say $fh "-N fwbuild_in";
    say $fh "-N fwbuild_out";
    say $fh "-N fwbuild_drop_log";
    say $fh "-N fwbuild_reject";
    say $fh "-N fwbuild_reject_log";
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

    say $fh "-A fwbuild_reject_log -j NFLOG --nflog-prefix \"REJECT \"";
    say $fh "-A fwbuild_reject_log -j fwbuild_reject_log";

    say $fh "-A fwbuild_drop_log -j NFLOG --nflog-prefix \"DROP \"";
    say $fh "-A fwbuild_drop_log -j DROP";

    say $fh
"-A fwbuild_in -m conntrack --ctstate INVALID,RELATED,ESTABLISHED -j ACCEPT";
    say $fh
"-A fwbuild_out -m conntrack --ctstate INVALID,RELATED,ESTABLISHED -j ACCEPT";

    foreach
      my $chain ( grep { $tabletype{$_} eq 'filter' } sort keys %tabletype )
    {
        $self->output_chain_print( $chain, $fh );
    }

    say $fh "-A fwbuild_in  -j NFLOG --nflog-prefix \"DROP\"";
    say $fh "-A fwbuild_in  -j DROP";
    say $fh "-A fwbuild_out -j NFLOG --nflog-prefix \"DROP\"";
    say $fh "-A fwbuild_out -j DROP";

    say $fh "COMMIT";
}

sub output_chain_print ( $self, $chain, $fh ) {
    if ( !defined($chain) ) { confess 'Assert failed: $chain is undef' }
    my (@rules) = $self->get_pending_rules($chain)->@*;
    foreach my $rule (@rules) {
        say $fh "-A $chain $rule";
    }
}

__PACKAGE__->meta->make_immutable;

1;

