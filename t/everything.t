use strict;
use warnings;
use Test::Fake::HTTPD;
use Test::More;
use Test::Exception;
use Test::Output qw (stdout_is);
use Test::Deep;
use JSON;
use Crypt::JWT qw (encode_jwt);
use CGI ();

use lib '.';
use lib 't';
require 'bin/mavis_tacplus_aad.pl';

my $CLIENT_ID = 'be5d8079-7a89-45bb-bde5-60843a2196aa';
my $DIRECTORY_ID = '2d28b14b-5459-4dc2-9496-277e41313bce';

my $private_key = <<'EOF';
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,770D386B37AF7148CAB98B10739070A6

JdjiOCilvQoEKT5DyElIZx3eZPbIedAMPkddVpHgmFsC334kDA2pGJvytxRLLsyt
hAa0bc3q6ZffnuhYEbL/2xoe6M7lGcPOw6mokDyNmLwoIb2uQlXb9h3MQkmj5ZXa
TXpap+8+qNDabEuGdWmBX1NneEJkpDyjL1UM2Thk1n/5/a6DD+aJ9t5hd3mslHqj
WLbeRstlZGdNcH53eB68Bl5qA46atpHrgNYm+ji1hqWNd+Oed0q19mTeWrPaiqCh
agjROSKUiE5o9uzgVbi3QjJgj09FK2qU+6g+vlN+8Kt4wWiipHzK394CC3kyhQTo
8mLsEc1bO1oZti4FiCnINwd1XFntrW+FyABs/PkFEwJjVxJtQH9OerGGLASKVEJ6
SIcgiYXNABErXsVnkCkXTfPZ6jGzRS1LoqnsPa8QfNG2fZTPVtBuuWIUk1CoTC+C
5kzoutUduE1QCNsalcZTu4qTR2foW/+DRajM963FdjmIkgSRw7ciAJKzw9oNSYjU
XQQnnKSGnLruDIP+l0crXgkLXycUwTdtm9wtDvmsXlbyrantDgq+All4ePV9IIEz
Md14COWnpefBYV3VaWdiBhD8DgzIgO1wVnszH/ypv3VD9Z7AKym6tRkp6ybhq87Q
oSUAc1X5BWrRZ+iM70icWQSuFzNWDMGrREz+od7OJN/fBXlrT9KH5Tn5ZWocOXN5
VS9oYPbLPLQT3ZcgkcOvIB5+Dc2nTnQ0N2KcCw6J5/aVA02d9pgSuVZxgi3mzPaU
u1lBioJn7QU8V+QytHpmW7hkEacwKo4U+j128iUjfNPzcDVzOBdbY9H9pkl9sJ/U
qRqX8oJgHQMva69aVFDsUZZnMFcrWl/VO5gau+PNh6u7m4orydGMy8hJwlaQuGXT
GMiA+iH3Zj9RoTJ/wqsnvyxbefcAhwtk5AJgAUq2V56lPJEALaRN7E/crC8AS57f
YfVGQBIrfnRunLSxtFuyrnSf2QIabEMq26XkD92YesAqe9KVMVmpHL7LMp154ess
HeqobWi10fFgWInXeajbJxCi9sitJHul8KlgjFu5IPCHHWK9qnbEjVvjREbCksKV
jAVDtQPfcB4G0viM0pFL/6PLC+9fRhePmnnsoEgCGUTegAx1JICIEwwyobWNO59c
s3sfgw80xgKWHxvUKnbm1xe91hJbHUZOpE5U9x3rAM51CO9SmkEaOobmo+vBfkZW
xYLw/sa95UZVMmGP3pUKhJRq9nKq8SY3XS79I3t3gfT93feHp2OHttdXdqVRpcw3
6SHsl+ZnZOctIGyueu22MvsFbILlrH/Now3cBDSqd1QdohyBdgzAtCufx6J+rh2K
TgNusbUxgFcFJ7MTbujrD866S9GyMPzPXWqTGoBgfCb0+56nfKyNhhFMcVuJMak3
Roh4bBmY0XYYPDqVW25vV2DOCceqHJ0inBpvWjhd0Rk3MjY23bZwg7LChI8xpZuB
ffuXiXbdFvbhn+9LliXEmP18DV/KmJQDR1rQnbM/X7YT5HCj6RD0Q/wfQ9nbL9E3
F26T5YEYU/Rz1/IoxrvLDDAaI17SBeX4JLpm028LeczYIOln36ReKkiESWTalQn0
-----END RSA PRIVATE KEY-----
EOF

my $public_key= <<'EOF';
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5InRGvvqlGpF4M3TI23L
CbNpakFI1O1HGzNrcpHAU7Do64quegLTA6X6aBQABnHf3PANSGogJS7KeQPy1jlu
t1EPwPpzcFIQ2MGym7SRMwTcuGrkyQXwEdI1NrgFnRxsMj8F6zOaXchqXMhNUkJI
8kFeriY7ZHFMDrUNGrIzFyVboHowR3nytd77rxKN92RusLsawcdtWNyBX5MiDqdh
RUiqsGIwUkDarP1ENGGSljAZXsPharkAaogq5XcsOijntuIkkJW52yp1TKX3dlEV
sRil2c42+FsNyllTttGKZxn0eZ/b162x6YfeXSMA2w18xUFOYeQQWbT7YKxnK9Ye
cwIDAQAB
-----END PUBLIC KEY-----
EOF

my $group_data =<<'EOF';
{
  "value": [
    {
      "id": "a2810867-f89c-4fcc-b20d-eb3f3f22c651",
      "displayName": "tacacsAdmins"
    },
    {
      "id": "4210bfea-b139-4f66-be70-2fb14536daf0",
      "displayName": "test_group2"
    },
    {
      "id": "4210bfea-b139-4f66-be70-2fb14536dafb",
      "displayName": "tacacsNonAdmins"
    }
  ]
}
EOF


sub encode_pwgrant_token {

    my $payload = {
          'iss' => "http://localhost/$DIRECTORY_ID/v2.0",
          # audience is the recieved client-id
          'aud' => $CLIENT_ID,
          'ver' => '2.0',
          'groups' => [ 'a2810867-f89c-4fcc-b20d-eb3f3f22c651', '4210bfea-b139-4f66-be70-2fb14536dafb' ],
          # not sure what this is
          'uti' => 'XXXXXXXXXXX_12345',
          # tenant identifier - This is an ID for the server that issued the token
          'tid' => '6a2ecc21-73f8-4f5e-9773-95230722e18a',
          # subject is the ID of the user we're authenticating
          'sub' => 'e83ca022-1208-4adf-968e-a1b8fb29afb8'
    };

    return encode_jwt(
        payload => $payload,
        alg => 'RS256',
        extra_headers => { kid => 'a8e0d80a-ca1b-4358-9176-a7d481647016' },
        auto_iat => 1,
        relative_exp => 3900,
        relative_nbf => 0,
        key => \$private_key,
        keypass => '9db81031cc584fa4b5575a0373b956bb'
    );

}

my $pwgrant_token = encode_pwgrant_token();

# for some reason the httpd server sometimes blocks until timeout on some of
# my requests.  Not sure if it's a bug in it or HTTP::Tiny.  I'm reducing the
# timeout here to make it better.
my $httpd = Test::Fake::HTTPD->new(
    timeout => 2,
);

$httpd->run( sub {
    my $req = shift;

    my $uri = $req->uri;
    my $path = $uri->as_string;

	# $req->headers contain the headers
	# $req->content contains the message
	my $p = CGI->new( $req->content );

    return do {
        if ($path eq "/$DIRECTORY_ID/oauth2/v2.0/token") {
            # client credentials is just falling through to a JWT token for
            # now.  This doesn't test invalid tokens or invalid options passed
            # to fetch_group_names.  We're not even returning the proper token
            # type for the query.
            if ( $p->{'param'}->{'grant_type'}->[0] eq 'client_credentials' ) {
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ "{\"access_token\":\"$pwgrant_token\"}" ]
                ]
            # password expired needs to be checked first because we're going to use a special username to trigger the error
            } elsif ( $p->{'param'}->{'username'}->[0] eq 'test_expired') { # password expired
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ '{"error":"invalid_grant","error_description":"AADSTS50055: The password is expired.\r\nTrace ID: <trace id>\r\nCorrelation ID: <correlation id>\r\nTimestamp: 2019-12-19 22:05:16Z","error_codes":[50055],"timestamp":"2019-12-19 22:05:16Z","trace_id":"<trace id>","correlation_id":"<correlation id>","error_uri":"https://localhost/error?code=50055","suberror":"user_password_expired"}' ]
                ]
            } elsif ( $p->{'param'}->{'username'}->[0] ne 'test_user@example.com' ) { # username ne correct
                [
                    200,
                    ['Content-Type' => 'application/json'],
                    [ '{"error":"invalid_grant","error_description":"AADSTS50034: The user account {EmailHidden} does not exist in the directory. To sign into this application, the account must be added to the directory\r\nTimestamp: 2019-12-19 22:07:08Z","error_codes":[50034],"timestamp":"2019-12-19 22:07:08Z","trace_id":"<trace id>","correlation_id":"<correlation id>","error_uri":"https://localhost/error?code=50034"}' ],
                ]
            } elsif ( $p->{param}->{password}->[0] ne 'test!pw' ) { # password ne correct
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ '{"error":"invalid_grant","error_description":"AADSTS50126: Error validating credentials due to invalid username or password.\r\nTrace ID: <trace id>\r\nCorrelation ID: <correlation id>\r\nTimestamp: 2019-12-19 22:06:01Z","error_codes" :[50126],"timestamp":"2019-12-19 22:06:01Z","trace_id":"<trace id>","correlation_id":"<correlation id>","error_uri":"https://localhost/error?code=50126"}' ]
                ]
            } elsif ( $p->{param}->{client_id}->[0] ne 'be5d8079-7a89-45bb-bde5-60843a2196aa' ) { # clientid ne correct
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ '{"error":"unauthorized_client","error_description":"AADSTS700016: Application with identifier \'<bad client id here>\' was not found in the directory \'<directory id here>\'. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant. You may have sent your authentication request to the wrong tenant.\r\nTrace ID: <trace id>\r\nCorrelation ID: <correlation id>\r\nTimestamp: 2019-12-19 22:09:42Z","error_codes":[700016],"timestamp":"2019-12-19 22:09:42Z","trace_id":"<trace id>","correlation_id":"<correlation id>","error_uri":"https://localhost/error?code=700016"}' ]
                ]
            } elsif ( $p->{param}->{client_secret}->[0] ne 'supersecret1234' ) { # secret ne correct
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret is provided.\r\nTrace ID: <trace id>\r\nCorrelation ID: <correlation id>\r\nTimestamp: 2019-12-19 22:10:15Z","error_codes":[7000215],"timestamp":"2019-12-19 22:10:15Z","trace_id":"<trace id>","correlation_id":"<correlation id>","error_uri":"https://localhost/error?code=7000215"}' ]
                ]
            } else {
                # return valid data
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ "{\"id_token\":\"$pwgrant_token\"}" ]
                ]
            }
        } elsif ($path eq '/broken-endpoint') {
                # return invalid data
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ '{"id_token":"hello!"}' ]
                ]
        } elsif ($path eq '/expired-endpoint') {
                # return expired token
                [
                    200,
                    [ 'Content-Type' => 'application/json' ],
                    [ '{"id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImE4ZTBkODBhLWNhMWItNDM1OC05MTc2LWE3ZDQ4MTY0NzAxNiJ9.eyJpYXQiOiIxNTc4MjAwNjIxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdC8uLi4vdjIuMCIsInZlciI6IjIuMCIsImF1ZCI6ImNsaWVudF9pZCIsInRpZCI6IjZhMmVjYzIxLTczZjgtNGY1ZS05NzczLTk1MjMwNzIyZTE4YSIsImV4cCI6IjE1NzgyMDA2MjEiLCJzdWIiOiJlODNjYTAyMi0xMjA4LTRhZGYtOTY4ZS1hMWI4ZmIyOWFmYjgiLCJuYmYiOiIxNTc4MjAwNjIxIiwidXRpIjoiWFhYWFhYWFhYWFhfMTIzNDUifQ.ZYatsF-Ec8Xi3xhYbZscPtz-6CPhKZmqms2zPYrlMOxAK1xuxLKLMNFfuLXygmGONB3-ZBhc3iZUTqhft9jB0fSkCgWxkdMP_BuIrO_ZJ8xaFSumL26IT_9Cpn4kmydPLNS5dleileNJo9KoUHcciT0qq8p7RyS2ZbIzXYs0JNa1Kv45Y4TXJlfa60lQGsAj4Loi4UrsP7Q02KIbQyv8MS7rH383LCcGoOfrnOvE9ls2rRbxlQtaJCx2-klrLfjGvQ2yVaApo0o8MI-atREeTxVM8faFx5pKKyH4zBWscZSKhy6_Dh1C5a9v-BiTI1nvO7WipMdIDF6Rs6whK9ttPA"}' ]
                ]
        } elsif ($path eq '/openid-configuration' ) {
            [
                200,
                [ 'Content-Type' => 'application/json' ],
                # this needs to include httpd->endpoint but I don't know how we would do that.
                [ "{\"jwks_uri\":\"/common/discovery/keys\"}" ]
            ]
        } elsif ($path eq '/common/discovery/keys' ) {
            [
                200,
                [ 'Content-Type' => 'application/json' ],
                [ '{"keys":[{"kty":"RSA","e":"AQAB","kid":"a8e0d80a-ca1b-4358-9176-a7d481647016","n":"5InRGvvqlGpF4M3TI23LCbNpakFI1O1HGzNrcpHAU7Do64quegLTA6X6aBQABnHf3PANSGogJS7KeQPy1jlut1EPwPpzcFIQ2MGym7SRMwTcuGrkyQXwEdI1NrgFnRxsMj8F6zOaXchqXMhNUkJI8kFeriY7ZHFMDrUNGrIzFyVboHowR3nytd77rxKN92RusLsawcdtWNyBX5MiDqdhRUiqsGIwUkDarP1ENGGSljAZXsPharkAaogq5XcsOijntuIkkJW52yp1TKX3dlEVsRil2c42-FsNyllTttGKZxn0eZ_b162x6YfeXSMA2w18xUFOYeQQWbT7YKxnK9Yecw"}]}'
                ]
            ]
        } elsif ($path eq '/groups') {
            [
                200,
                [ 'Content-Type' => 'application/json' ],
                [ $group_data ]
            ]
        } else { # 404 catchall
            [
                404,
                [ 'Content-Type' => 'application/json' ],
                [ '{"error":"My Custom Page Not Found Message"}' ]
            ]
        }
    };
});

sub test_httpd {
    my ($url, $args, $expected) = @_;
    $args ||= {};
    $expected ||= {};

    my $opts = {
       'client_id' => $CLIENT_ID,
       'client_secret' => 'supersecret1234',
       'grant_type' => 'password',
       'scope' => 'openid',
       'username' => 'test_user@example.com',
       'password' => 'test!pw',
       %$args,
    };

    use HTTP::Tiny;
    my $res = HTTP::Tiny->new->post_form($url, $opts);
    $res->{decoded_content} = decode_json($res->{content});
    # check the results to see if the actual return value matches what is expected.
    cmp_deeply(\%$res, superhashof(\%$expected));
    return $res;
}

subtest 'test_oauth_mock' => sub {
    plan skip_all => 'Skipping oauth_mock tests' if (!$ENV{'OAUTH_MOCK_TESTS'});

    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token3", {}, { status => '404' } );
    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token", { 'username' => 'test_expired' }, { decoded_content => superhashof({ error => 'invalid_grant', error_codes => [ 50055 ] }) } );
    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token", { 'username' => 'invalid_user' },  { decoded_content => superhashof({ error => 'invalid_grant', error_codes => [ 50034 ] }) } );
    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token", { 'password' => 'invalid_password' }, { decoded_content => superhashof({ error => 'invalid_grant', error_codes => [ 50126 ] }) } );
    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token", { 'client_id' => 'test' }, { decoded_content => superhashof({ error => 'unauthorized_client', error_codes => [ 700016 ] }) } );
    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token", { 'client_secret' => 'test' }, { decoded_content => superhashof({ error => 'invalid_client', error_codes => [ 7000215 ] }) } );
    test_httpd( $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token");
    test_httpd( $httpd->endpoint . "/groups", {},  { headers => superhashof({ 'content-length' => '325' }) });
};


subtest 'improper_environment_variables' => sub {
    my $env = {};
    throws_ok(sub { setup_env($env) }, qr/OAUTH_ENDPOINT not defined/, 'OAUTH_ENDPOINT not defined');
    $env->{OAUTH_ENDPOINT}='test';
    throws_ok(sub { setup_env($env) }, qr/OAUTH_CLIENT_ID not defined/, 'OAUTH_CLIENT_ID not defined');
    $env->{OAUTH_CLIENT_ID}='test';
    throws_ok(sub { setup_env($env) }, qr/OAUTH_SECRET not defined/, 'OAUTH_SECRET not defined');
    $env->{OAUTH_SECRET}='test';
    lives_ok(sub { setup_env($env) }, 'all required variables set.');
};


# this test ENV will be used by several tests
my $test_env = {
   'OAUTH_ENDPOINT' => $httpd->endpoint . "/$DIRECTORY_ID/oauth2/v2.0/token",
   'OAUTH_CLIENT_ID' => $CLIENT_ID,
   'OAUTH_SECRET' => 'supersecret1234',
   'OAUTH_DOMAIN' => 'example.com',
   'OAUTH_KEYSERVER' => $httpd->endpoint . "/common/discovery/keys",
};

subtest 'validate_input_from_tacplus' => sub {
    setup_env($test_env);
    # apparently this is a valid condition
    stdout_is(sub { parse_entry("4 test_user\n8 test!pw\n49 AUTH\n=\n") },
        "4 test_user\n6 ACK\n8 test!pw\n36 test!pw\n49 AUTH\n=0\n",
        'No TACPLUS source line 0');
    stdout_is(sub { parse_entry("0 TACP\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
        "0 TACP\n4 test_user\n8 test!pw\n49 AUTH\n=16\n",
        'Non-TACPLUS source line');
    stdout_is(sub { parse_entry("0 TACPLUS\n8 test!pw\n49 AUTH\n=\n") },
        "0 TACPLUS\n6 ERR\n8 test!pw\n32 User not set.\n49 AUTH\n=0\n",
        'No user line');
    stdout_is(sub { parse_entry("0 TACPLUS\n4 test()\n8 test!pw\n49 AUTH\n=\n") },
        "0 TACPLUS\n4 test()\n6 ERR\n8 test!pw\n32 Username not valid.\n49 AUTH\n=0\n",
        'Invalid user line');
    stdout_is(sub { parse_entry("0 TACPLUS\n4 test\n49 AUTH\n=\n") },
        "0 TACPLUS\n4 test\n6 ERR\n32 Password not set.\n49 AUTH\n=0\n",
        'No password line');
    stdout_is(sub { parse_entry("0 TACPLUS\n4 test\n49 XAUTH\n=\n") },
        "0 TACPLUS\n4 test\n6 ERR\n32 Unknown TACTYPE\n49 XAUTH\n=0\n",
        'Unknown TACTYPE');
};

### Test Normal Authentication
{
setup_env($test_env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 ACK
8 test!pw
36 test!pw
49 AUTH
=0
',
'Test Normal Auth');
}


### Test Hardcoded Group Auth
{
my $env = {%$test_env};

$env->{'OAUTH_GROUP_ID'}='a2810867-f89c-4fcc-b20d-eb3f3f22c651';
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 ACK
8 test!pw
36 test!pw
49 AUTH
=0
',
'Test Hardcoded Group Authentication');
}


### Test Hardcoded Group Auth (group not found)
{
my $env = {%$test_env};

$env->{'OAUTH_GROUP_ID'}='xxx';
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 NAK
8 test!pw
49 AUTH
=0
',
'Test Hardcoded Group Authentication (group not found)');
}


### Test Group Authentication
{
my $env = {%$test_env};

$env->{'FLAG_USE_MEMBEROF'}=1;
$env->{'REQUIRE_TACACS_GROUP_PREFIX'}=1;
$env->{'OAUTH_GROUP_ENDPOINT'} = $httpd->endpoint . "/groups";

setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 ACK
8 test!pw
36 test!pw
47 "tacacsAdmins","tacacsNonAdmins"
49 AUTH
=0
',
'Test Group Authentication');
}


### Secret Incorrect
{
my $env = {%$test_env};
$env->{'OAUTH_SECRET'} = 'test';
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 ERR
8 test!pw
32 Recieved Invalid Client error for OAuth Endpoint.  Please check OAUTH_CLIENT_SECRET.
49 AUTH
=0
',
'Test Incorrect Client Secret');
}


### Client ID incorrect
{
my $env = {%$test_env};
$env->{'OAUTH_CLIENT_ID'} = 'test';
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 ERR
8 test!pw
32 Recieved Unauthorized Client error for OAuth Endpoint.  Please check OAUTH_CLIENT_ID.
49 AUTH
=0
',
'Test Incorrect Client ID');
}


### Incorrect Password
{
my $env = {%$test_env};
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_user\n8 test\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_user
6 NAK
8 test
32 Permission denied.
49 AUTH
=0
',
'Test Incorrect Password');
}


### Incorrect Username
{
my $env = {%$test_env};
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test
6 NFD
8 test!pw
49 AUTH
=16
',
'Test Incorrect Username');
}


### Expired User
{
my $env = {%$test_env};
$env->{'OAUTH_DOMAIN'}=undef;
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test_expired\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test_expired
6 NAK
8 test!pw
32 Password has expired.
49 AUTH
=0
',
'Test Expired User');
}


### Invalid Endpoint
{
my $env = {%$test_env};
$env->{'OAUTH_ENDPOINT'}=$httpd->endpoint . "/not/found";
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test
6 ERR
8 test!pw
32 OAuth Endpoint is not accessible (404 Error).
49 AUTH
=0
',
'Test Invalid Endpoint');
}


### Broken Endpoint
{
my $env = {%$test_env};
$env->{'OAUTH_ENDPOINT'}=$httpd->endpoint . "/broken-endpoint";
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test
6 ERR
8 test!pw
32 Parse failure for token: JWT: invalid token format
49 AUTH
=0
',
'Test Broken Endpoint');
}


### Expired Endpoint
{
my $env = {%$test_env};
$env->{'OAUTH_ENDPOINT'}=$httpd->endpoint . "/expired-endpoint";
setup_env($env);
stdout_is(sub { parse_entry("0 TACPLUS\n4 test\n8 test!pw\n49 AUTH\n=\n") },
'0 TACPLUS
4 test
6 ERR
8 test!pw
32 Parse failure for token: JWT: token expired (check time)
49 AUTH
=0
',
'Test Expired Endpoint');
}

### End
done_testing();
