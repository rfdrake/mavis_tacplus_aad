#!/usr/bin/env perl

# mavis_tacplus_aad.pl
# (C)2001-2014 Robert Drake <rfdrake@gmail.com>
# All rights reserved.
#
# TACACS+ backend for libmavis_external.so
# Authenticates/authorizes against OAuth2.
#
#
# NOTES:
#
# This uses the OAuth2 Password Grant mechanism for verifying the username and password.  This means that it can't support 2 factor authentication.
# See https://oauth.net/2/grant-types/password/ for more information.
#
# This has only been tested with Microsoft Azure AD.  Other Oauth servers will probably require some tweaking.
# Changing passwords probably won't be implemented unless we find a way that is both portal and secure.
#


=pod

Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.pl

#######

Environment variables:

OAUTH_ENDPOINT
        URL for the oauth token provider
        Examples: "https://login.microsoftonline.com/<application_id>/oauth2/v2.0/token"

OAUTH_DOMAIN
        Domain that will be appended to usernames, if the remote user doesn't supply an @fqdn.  Most of the time users will login with username: test, password: test, for example.  The OAuth server is expecting test@<domain>.
        Example: example.com

OAUTH_CLIENT_ID
        The Client identifier for the application
        Example: <uuid>

OAUTH_CLIENT_SECRET
        The passphrase used by the client to authenticate with the OAuth provider

AD_GROUP_PREFIX
        An AD group starting with this prefix will be used for tacacs group membership.
        Default: tacacs

REQUIRE_AD_GROUP_PREFIX
        If set, user needs to be in one of the AD_GROUP_PREFIX groups.  If this is used you will need to grant Group.Read.All permission to the Application so that the group list can be downloaded.
        Default: unset

FLAG_FALLTHROUGH
        If Oauth search fails, try next module (if any).
        Default: unset

FLAG_USE_MEMBEROF
        Use the memberof attribute for determining group membership.
        Default: unset

OAUTH_OPENID_CONFIG_URL
OAUTH_KEYSERVER
OAUTH_KEY
OAUTH_GROUP_ID


########

Sample configuration:

        id = spawnd {
                listen = {
                        port = 49
                }
                spawn = {
                        instances min = 1
                        instances max = 10
                }
                background = no
        }

        id = tac_plus {
                access log = /var/log/tacacs/%Y/%m/%d/access.log
                accounting log = /var/log/tacacs/%Y/%m/%d/acct.log

                mavis module = external {
                        setenv OAUTH_ENDPOINT = "https://login.microsoftonline.com/06ab1719-d1f8-4cae-87fa-824768230090/oauth2/v2.0/token"
                        setenv OAUTH_CLIENT_ID = "c45aecee-71fa-4c6e-96c5-7397df677112"
                        setenv OAUTH_CLIENT_SECRET = "secretkey"
                        setenv OAUTH_DOMAIN = "example.com"
                        exec = /usr/local/lib/mavis/mavis_tacplus_aad.pl
                }

                user backend = mavis    # query backend for users
                login backend = mavis   # authenticate login via backend
                pap backend = mavis             # authenticate PAP via backend

                host = world {
                        address = ::/0
                        prompt = "Welcome\n"
                        key = cisco
                }

                host = helpdesklab {
                                address = 192.168.34.16/28
                }

# A user will be in the "admin" group if he's member of the
# corresponding "tacacsadmin" ADS group. See $tacacsGroupPrefix
# and $require_tacacsGroupPrefix in the code.

                group = admin {
                        default service = permit
                        service = shell {
                                default command = permit
                                default attribute = permit
                                set priv-lvl = 15
                        }
                }

# A user will be in the "helpdesk" group if he's member of the
# corresponding "tacacshelpdesk" ADS group:

                group = helpdesk {
                        default service = permit
                        service = shell {
                                default command = permit
                                default attribute = permit
                                set priv-lvl = 1
                        }
                        enable = deny
                        member = admin@helpdesklab
                }
        }

=cut

use lib '/usr/local/lib/mavis/';

use strict;
use warnings;
use Mavis;
use HTTP::Tiny;
use Syntax::Keyword::Try;
use JSON;
use Crypt::JWT qw (decode_jwt);
use v5.16;


my $http = HTTP::Tiny->new( verify_SSL => 1 );
my $opts = {};


# force fflush after every print
$| = 1;

sub setup_env {
        my ($env) = @_;
        $opts = {
                'OAUTH_ENDPOINT'              => $env->{'OAUTH_ENDPOINT'},
                'OAUTH_GROUP_ENDPOINT'        => $env->{'OAUTH_GROUP_ENDPOINT'} || 'https://graph.microsoft.com/v1.0/groups',
                'OAUTH_CLIENT_ID'             => $env->{'OAUTH_CLIENT_ID'},
                'OAUTH_SECRET'                => $env->{'OAUTH_SECRET'},
                'OAUTH_DOMAIN'                => $env->{'OAUTH_DOMAIN'},
                'OAUTH_OPENID_CONFIG_URL'     => $env->{'OAUTH_OPENID_CONFIG_URL'},
                'OAUTH_KEYSERVER'             => $env->{'OAUTH_KEYSERVER'},
                'OAUTH_KEY'                   => $env->{'OAUTH_KEY'},
                'OAUTH_GROUP_ID'              => $env->{'OAUTH_GROUP_ID'},
                'flag_fallthrough'            => $env->{'FLAG_FALLTHROUGH'},
                'flag_use_memberof'           => $env->{'FLAG_USE_MEMBEROF'},
                'tacacsGroupPrefix'           => $env->{'TACACS_GROUP_PREFIX'} || $env->{'TACACS_AD_GROUP_PREFIX'} ||  $env->{'AD_GROUP_PREFIX'} || 'tacacs',
                'require_tacacsGroupPrefix'   => $env->{'REQUIRE_TACACS_GROUP_PREFIX'} || $env->{'REQUIRE_TACACS_AD_GROUP_PREFIX'} || $env->{'REQUIRE_AD_GROUP_PREFIX'},
        };

        unless (defined $opts->{'flag_use_memberof'}) {
                foreach my $v ('TACACS_GROUP_PREFIX', 'REQUIRE_TACACS_GROUP_PREFIX',
                               'TACACS_AD_GROUP_PREFIX', 'REQUIRE_TACACS_AD_GROUP_PREFIX',
                               'AD_GROUP_PREFIX', 'REQUIRE_AD_GROUP_PREFIX'
                              ) {
                        printf STDERR "Warning: Environment variable $v will be ignored.\n" if exists $env->{$v};
                }
        }
        # remove this warning for now, since we only support microsoft
        #print STDERR "Default server type is \'$OAUTH_SERVER_TYPE\'. You *may* need to change that to 'generic' or 'microsoft'.\n" unless exists $env->{'OAUTH_SERVER_TYPE'};
        die "OAUTH_ENDPOINT not defined" unless defined $opts->{'OAUTH_ENDPOINT'};
        die "OAUTH_CLIENT_ID not defined" unless defined $opts->{'OAUTH_CLIENT_ID'};
        die "OAUTH_SECRET not defined" unless defined $opts->{'OAUTH_SECRET'};
}

# this caches the groups indefinately.  We need a way to make this only cache for XX time.
sub fetch_group_names {

    state $groups = undef;
    return $groups if (defined $groups);

    my $args = {
       'client_id' => $opts->{'OAUTH_CLIENT_ID'},
       'client_secret' => $opts->{'OAUTH_SECRET'},
       'grant_type' => 'client_credentials',
       'scope' => 'https://graph.microsoft.com/.default',
    };

    my $res = HTTP::Tiny->new->post_form($opts->{'OAUTH_ENDPOINT'}, $args);
    my $token = decode_json($res->{content});

    # error checking needed here too.
    $groups = decode_json($http->get($opts->{OAUTH_GROUP_ENDPOINT}, { headers => => { 'Authorization' =>  'Bearer ' . $token->{access_token} } } )->{content});
    return $groups;
}

# this caches the key indefinately.  We need a way to make this only cache for XX time.
sub parse_jwt {
        my ($token) = @_;
        state $keys = undef;
        my $uri = undef;

        try {
            if (defined $keys) {
                    return decode_jwt(token => $token, kid_keys => $keys);
            }

            # if OAUTH_KEYSERVER or OAUTH_OPENID_CONFIG_URL or OAUTH_KEY is defined then perform a lookup of these values, then cache them?
            # if none of these are defined then we will set ignore_signature and read the JWT response without validating it.  This may be enough for some people since the session is validated over HTTPS
            if ($opts->{OAUTH_KEY}) {
                    return decode_jwt(token => $token, key => $opts->{OAUTH_KEY});
            }

            # need error checking here.  If these fail to decode then we pass through to ignore_signature
            if ($opts->{OAUTH_OPENID_CONFIG_URL}) {
                    $uri = decode_json($http->get($opts->{OAUTH_OPENID_CONFIG_URL})->{'content'})->{'jwks_uri'};
            } if ($opts->{OAUTH_KEYSERVER}) {
                    $uri = $opts->{OAUTH_KEYSERVER};
            }
            if (defined $uri) {
                    $keys = decode_json($http->get($uri)->{'content'});
                    return decode_jwt(token => $token, kid_keys => $keys);
            }

            # if we get here then decode_jwt with no validation
            return decode_jwt(token => $token, ignore_signature => 1);
        } catch {
            $keys = undef;
            return { exception_error => $@ };
        }
}

sub send_auth_request {
    my ($user, $pass) = @_;

    if ($user !~ /\@/ && defined $opts->{'OAUTH_DOMAIN'}) {
        $user = "$user\@$opts->{'OAUTH_DOMAIN'}";
    }

    my $args = {
       'client_id' => $opts->{'OAUTH_CLIENT_ID'},
       'client_secret' => $opts->{'OAUTH_SECRET'},
       'grant_type' => 'password',
       'scope' => 'openid',
       'username' => $user,
       'password' => $pass,
    };

    my $res = HTTP::Tiny->new->post_form($opts->{'OAUTH_ENDPOINT'}, $args);
    $res->{decoded_content} = decode_json($res->{content});
    return $res;
}


sub parse_entry {
    my ($in) = @_;
    my $result = MAVIS_DEFERRED;
    my @V = ();


    foreach my $a (split (/\n/, $in)) {
            next unless $a =~ /^(\d+) (.*)$/;
            $V[$1] = $2;
    }

    # Validate input from tac_plus
    if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) {
            $result = MAVIS_DOWN;
            goto bye;
    }
    if (!defined $V[AV_A_USER]){
            $V[AV_A_USER_RESPONSE] = "User not set.";
            goto fatal;
    }
    if ($V[AV_A_USER] =~ /\(|\)|,|\||&/){
            $V[AV_A_USER_RESPONSE] = "Username not valid.";
            goto fatal;
    }
    if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH && !defined $V[AV_A_PASSWORD]){
            $V[AV_A_USER_RESPONSE] = "Password not set.";
            goto fatal;
    }
    if ($V[AV_A_TACTYPE] ne AV_V_TACTYPE_AUTH) {
            $V[AV_A_USER_RESPONSE] = "Unknown TACTYPE";
            goto fatal;
    }

    my $response = send_auth_request($V[AV_A_USER], $V[AV_A_PASSWORD]);
    if ($response->{status} == 404) {
        $V[AV_A_USER_RESPONSE] = "OAuth Endpoint is not accessible (404 Error).";
        goto fatal;
    } elsif (!$response->{decoded_content}) {
        $V[AV_A_USER_RESPONSE] = "Failed to decode response from OAuth Endpoint.";
        goto fatal;
    } elsif ($response->{decoded_content}->{error_codes}) {
        my $error_codes = $response->{decoded_content}->{error_codes};
        my $error = $response->{decoded_content}->{error};
        if ($error eq 'invalid_grant') {
            if ($error_codes->[0] == 50055) {       # password expired
                $V[AV_A_USER_RESPONSE] = "Password has expired.";
                goto fail;
            } elsif ($error_codes->[0] == 50034) {  # invalid user
                goto down;
            } elsif ($error_codes->[0] == 50126) {  # invalid password
                $V[AV_A_USER_RESPONSE] = "Permission denied.";
                goto fail;
            } else {
                $V[AV_A_USER_RESPONSE] = "Unhandled invalid_grant error.  Check API Permissions.";
            }
        } elsif ($error eq 'unauthorized_client') {
            $V[AV_A_USER_RESPONSE] = "Recieved Unauthorized Client error for OAuth Endpoint.  Please check OAUTH_CLIENT_ID.";
        } elsif ($error eq 'invalid_client') {
            $V[AV_A_USER_RESPONSE] = "Recieved Invalid Client error for OAuth Endpoint.  Please check OAUTH_CLIENT_SECRET.";
        } else {
            my $err = join(',',@$error_codes);
            $V[AV_A_USER_RESPONSE] = "Unhandled error from OAuth endpoint (error numbers: $err)";
        }
        goto fatal;
    }


    my $jwt = parse_jwt($response->{decoded_content}->{id_token});
    if ($jwt->{exception_error}) {
        my $err = $jwt->{exception_error};
        chomp($err);
        $err =~ s/ at \S+ line \d+\.$//;
        $err =~ s/exp claim check failed .*/token expired (check time)/;
        $V[AV_A_USER_RESPONSE] = "Parse failure for token: $err";
        goto fatal;
    }

    # check groups for hardcoded group IDs
    if ($opts->{'OAUTH_GROUP_ID'}) {
        my $match = 0;
        foreach my $group (@{$jwt->{'groups'}}) {
            if ($group eq $opts->{'OAUTH_GROUP_ID'}) {
                $match=1;
                # group match, exit foreach
                last;
            }
        }

        if (!$match) {
            goto fail;
            # goto fail here, no group matched
        }
    }

    # check groups with lookup
    if (defined $opts->{flag_use_memberof}) {
        my $prefix = $opts->{tacacsGroupPrefix};
        my $groups = fetch_group_names();
        foreach my $group (@{$groups->{value}}) {
            if ($group->{displayName} =~ /^$prefix/) {
                foreach my $ugroup (@{$jwt->{groups}}) {
                    if ($ugroup eq $group->{id}) {
                        if (exists $V[AV_A_TACMEMBER]) {
                            $V[AV_A_TACMEMBER] .= ',"' . $group->{displayName} . '"';
                        } else {
                            $V[AV_A_TACMEMBER] = '"' . $group->{displayName} . '"';
                        }
                    }
                }
            }
        }
        # uncoverable condition [changing the JWT token in the mock server is difficult]
        if (defined ($opts->{require_tacacsGroupPrefix}) && !defined($V[AV_A_TACMEMBER])){
            goto fail;
        }
    }

    # success?
    $V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD];
    $V[AV_A_RESULT] = AV_V_RESULT_OK;
    $result = MAVIS_FINAL;
    goto bye;


    fail:
            $V[AV_A_RESULT] = AV_V_RESULT_FAIL;
            $result = MAVIS_FINAL;
            goto bye;

    down:
            $V[AV_A_RESULT] = AV_V_RESULT_NOTFOUND;
            $result = MAVIS_DOWN;
            goto bye;

    fatal:
            $result = MAVIS_FINAL;
            $V[AV_A_RESULT] = AV_V_RESULT_ERROR;
            goto bye;

    bye:
            my ($out) = "";
            for (my $i = 0; $i <= $#V; $i++) {
                    $out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
            }
            $out .= sprintf ("=%d\n", $result);
            print $out;
}

sub main {
    # uncoverable subroutine
    setup_env(\%ENV);                               # uncoverable statement
    # set input record separator to "\n=\n"
    $/ = "\n=\n";                                   # uncoverable statement
    while (my $in = <>) {                           # uncoverable statement
        chomp $in;                                  # uncoverable statement
        parse_entry($in);                           # uncoverable statement
    }
}

# uncoverable branch true
__PACKAGE__->main() unless caller;


# vim: ts=4
