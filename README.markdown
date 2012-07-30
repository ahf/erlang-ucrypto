Erlang µCrypto Library
======================

µCrypto is a thin Erlang wrapper for the OpenSSL library. The idea is to aim
towards upstreaming most of the features added to this library to the OTP
codebase.

The rationale for this module is the fact that Erlang's built-in `crypto`
modules lacks certain features that would be nice to have in your applications.

Code Examples
-------------

### RIPEMD160 Hash Function

```erl
1> c(ucrypto).
{ok,ucrypto}
2> ucrypto:ripemd160("Hello world!").
<<127,119,38,71,216,135,80,173,216,45,142,26,122,62,92,9,2,163,70,163>>
3> Context = ucrypto:ripemd160_init().
<<1,35,69,103,137,171,205,239,254,220,186,152,118,84,50,16,240,225,210,195,0,0,0,0,0,0,0,0,0,...>>
4> Context2 = ucrypto:ripemd160_update(Context, "Hello ").
<<1,35,69,103,137,171,205,239,254,220,186,152,118,84,50,16,240,225,210,195,48,0,0,0,0,0,0,0,72,...>>
5> Context3 = ucrypto:ripemd160_update(Context2, "world!").
<<1,35,69,103,137,171,205,239,254,220,186,152,118,84,50,16,240,225,210,195,96,0,0,0,0,0,0,0,72,...>>
6> ucrypto:ripemd160_final(Context3).
<<127,119,38,71,216,135,80,173,216,45,142,26,122,62,92,9,2,163,70,163>>
7> ucrypto:ripemd160("Hello world!") == ucrypto:ripemd160_final(Context3).
true
```

Authors
-------

[Alexander Færøy](mailto:ahf@0x90.dk) -- Main code.
