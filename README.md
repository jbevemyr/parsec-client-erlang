# Parsec Erlang Client

This repository contains an Erlang based client for consuming the
API provided by the [Parsec service]
(https://github.com/parallaxsecond/parsec).

It communicates with the Parsec server over a Unix Domain Socket. The
socket is located using the [service
discovery](https://parallaxsecond.github.io/parsec-book/parsec_client/api_overview.html#service-discovery)
policy to find the Parsec endpoint. For example, if the socket is
located at `/tmp/parsec.sock` it can be specified using an
environment variable:

```
export PARSEC_SERVICE_ENDPOINT="unix:/tmp/parsec.sock"
```

Alternatively the endpoint can be specified when a session is
initiated:

```
S = parsec:init(#{service_endpoint => <<"/tmp/parsec.sock">>}).
```

The `parsec:init(Opts)` function also accepts auth settings that
will be used when interacting with the parsec service. By default
`uid` will be used and the current user `uid` will be read from
the environment.

```
-type opts() ::
        #{ service_endpoint => binary(),
           auth             => none | uid | token | jwt | direct,
           uid              => non_neg_integer(),
           token            => binary(),
           jwt              => binary(),
           direct           => binary()
         }.

-spec init(Opts::opts()) -> #parsec{} | {error, term()}.
```

## Example

Start a shell with the parsec client code

```
$ make all shell
Erlang/OTP 25 [erts-13.1.2] [source] [64-bit] [smp:16:16] [ds:16:16:10] [async-threads:1] [jit:ns]

Eshell V13.1.2  (abort with ^G)
```

Create a session object. It keeps track of the service endpoint,
available providers and their capabilities.
```
1> S = parsec:init(#{service_endpoint => <<"/tmp/parsec.sock">>}).
{parsec,<<"/tmp/parsec.sock">>,
        [#{description =>
               <<"TPM provider, interfacing with a library implementing the TCG TSS 2.0 Enhanced System API specif"...>>,
           id => 3,
           opcodes => [3,11,32,30,5,13,10,31,4,2,6,7],
           uuid => <<"1e4954a4-ff21-46d3-ab0c-661eeb667e1d">>,
           vendor => <<"Trusted Computing Group (TCG)">>,
           version_maj => 0,version_min => 1,version_rev => 0},
         #{description =>
               <<"Software provider that implements only administrative (i.e. no cryptographic) operations">>,
           id => 0,
           opcodes => [26,9,14,8,1],
           uuid => <<"47049873-2a43-4845-9d72-831eab668784">>,
           vendor => <<>>,version_maj => 1,version_min => 0,
           version_rev => 0}],
        3,
        <<232,3,0,0>>,
        785540712}
```

List available providers.

```
2> parsec:list_providers(S).
{ok,#{providers =>
          [#{description =>
                 <<"TPM provider, interfacing with a library implementing the TCG TSS 2.0 Enhanced System API specif"...>>,
             id => 3,uuid => <<"1e4954a4-ff21-46d3-ab0c-661eeb667e1d">>,
             vendor => <<"Trusted Computing Group (TCG)">>,
             version_maj => 0,version_min => 1,version_rev => 0},
           #{description =>
                 <<"Software provider that implements only administrative (i.e. no cryptographic) operations">>,
             id => 0,uuid => <<"47049873-2a43-4845-9d72-831eab668784">>,
             vendor => <<>>,version_maj => 1,version_min => 0,
             version_rev => 0}]}}
```

Create a 2048 bit RSA keypair named `test`.

```
3> parsec:create_rsa_key(S, <<"test">>, #{}).
{ok,#{}}
```

List available keys.

```
4> parsec:list_keys(S).
{ok,#{keys =>
          [#{attributes =>
                 #{key_bits => 2048,
                   key_policy =>
                       #{key_algorithm =>
                             #{variant =>
                                   {asymmetric_encryption,
                                       #{variant => {rsa_pkcs1v15_crypt,#{}}}}},
                         key_usage_flags =>
                             #{cache => false,copy => false,decrypt => true,
                               derive => false,encrypt => true,export => false,
                               sign_hash => false,sign_message => false,
                               verify_hash => false,verify_message => false}},
                   key_type => #{variant => {rsa_key_pair,#{}}}},
             name => <<"test">>,provider_id => 3}]}}
```

Encrypt some text using the newly created `test` key.

```
5> {ok, #{ciphertext := Ciphertext}} = parsec:asymmetric_encrypt(S, <<"test">>, <<"The quick brown fox jumps over the lazy dog.">>).
{ok,#{ciphertext =>
          <<161,48,172,200,80,49,176,86,197,86,251,44,162,150,241,
            213,89,73,107,8,171,252,91,3,117,101,...>>}}
```

Decrypt the resulting ciphertext.

```
6> parsec:asymmetric_decrypt(S, <<"test">>, Ciphertext).
{ok,#{plaintext =>
          <<"The quick brown fox jumps over the lazy dog.">>}}
```

Cleanup, remove the test key.

```
7> parsec:destroy_key(S, <<"test">>).
{ok,#{}}
```

List the available keys to ensure it has been deleted.

```
8> parsec:list_keys(S).
{ok,#{keys => []}}
```

The same operations can be executed using the `test/1` function in the
`parsec` module.

## Low level API

There is also a low level API that can be used to access all available
API functions in Parsec, the `send_request/3` function. For example,

```
10> parsec:send_request(S, 0, {list_providers, #{}}).
{ok,#{providers =>
          [#{description =>
                 <<"TPM provider, interfacing with a library implementing the TCG TSS 2.0 Enhanced System API specif"...>>,
             id => 3,uuid => <<"1e4954a4-ff21-46d3-ab0c-661eeb667e1d">>,
             vendor => <<"Trusted Computing Group (TCG)">>,
             version_maj => 0,version_min => 1,version_rev => 0},
           #{description =>
                 <<"Software provider that implements only administrative (i.e. no cryptographic) operations">>,
             id => 0,uuid => <<"47049873-2a43-4845-9d72-831eab668784">>,
             vendor => <<>>,version_maj => 1,version_min => 0,
             version_rev => 0}]}}
```

It is fairly straightforward to extend the code with additional
high level operations.
