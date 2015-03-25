# ed25519
Erlang port program for ed25519 sign and verify from libsodium.

This is a very simple implementation using a port program to access the libsodium functionality. Other, more integrated implementations with full functionality are available ([enacl](https://github.com/jlouis/enacl) or [salt](https://github.com/freza/salt)), but these require specialy built Erlang systems (with dirty schedulars.) I just needed the ed25519 sign and verify functions and very much rely on the Erlang distributions form [Erlang Solutions](https://www.erlang-solutions.com/downloads) which do not have dirty schedulars compiled in. Also, this was a good exercise in building a port program.

## Install
First of all, install libsodium as described [here](http://doc.libsodium.org/installation/README.html).
Get [rebar](https://github.com/rebar/rebar/wiki) (not rebar3). 
Run
```
$ rebar clean compile eunit doc
```
This was tested for Debian. Should work for Windows, maybe with some small tweaks.

## Usage
Start a Erlang shell
```
Erlang/OTP 17 [erts-6.3] [source] [64-bit] [smp:2:2] [async-threads:10] [kernel-poll:false]

Eshell V6.3  (abort with ^G)
1> application:start(ed25519).
ok
2> {ok, {Public_key, Secret_key}} = ed25519:ed25519_keypair().
{ok,{<<35,174,231,72,230,138,133,140,102,9,37,227,157,250,
       229,40,146,164,22,122,148,15,44,149,131,116,...>>,
     <<54,115,66,197,35,66,140,242,36,224,142,170,208,91,3,
       209,25,203,215,127,235,9,85,188,218,...>>}}
3> Message = "This is a message".                             
"This is a message"
4> {ok, Signature} = ed25519:ed25519_sign(Secret_key, Message).
{ok,<<191,69,86,82,239,193,140,199,116,84,161,47,7,135,
      95,26,139,77,227,83,190,34,97,233,148,222,147,...>>}
5> ed25519:ed25519_verify(Public_key, Message, Signature).
{ok,true}
6> ed25519:ed25519_verify(Public_key, "Forged message", Signature).
{ok,false}

```
See the docs (also the libsodium) for more functions and details. 

## Tests
The eunit tests use the test data from the [sign.input](http://ed25519.cr.yp.to/python/sign.input) from the original Ed25519 high-speed high-security signatures Alternate implementations [software](http://ed25519.cr.yp.to/software.html) page. All 1024 test vectors should run just fine.