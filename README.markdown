Erlang µCrypto Library
======================

µCrypto is a thin Erlang wrapper for the OpenSSL library. The idea is to aim
towards upstreaming most of the features added to this library to the OTP
codebase.

The rationale for this module is the fact that Erlang's built-in `crypto`
modules lacks certain features that would be nice to have in your applications.

Code Examples
-------------

### RIPEMD 160

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

### Utilities

#### `hex2bin`

```erl
1> c(ucrypto).
{ok,ucrypto}
2> ucrypto:hex2bin("FFFFFF").
<<"ÿÿÿ">>
3> ucrypto:hex2bin("000f").  
<<0,15>>
4> ucrypto:hex2bin("000fff").
<<0,15,255>>
```

#### `bin2hex`

```erl
1> c(ucrypto).
{ok,ucrypto}
2> ucrypto:bin2hex(<<255,255,255>>).
"FFFFFF"
3> ucrypto:bin2hex(<<255,255,0>>).  
"FFFF00"
4> ucrypto:bin2hex(<<255,255,0,127,1>>).
"FFFF007F01"
5> ucrypto:hex2bin("FFFF007F01").
<<255,255,0,127,1>>
```

Contributing
------------

Contributions to µCrypto are welcome. Please go ahead and fork the project here
on Github and submit merge requests when you have something ready for review. I
will then give some feedback and once everything looks good, I will merge your
contributions into the mainline repository.

### Continuous Integration

We are currently using [Travis CI](http://www.travis-ci.org/) for continuous
integration. When submitting patches, please ensure that the entire project
builds and tests are passing.

Current Status: [![Build Status](https://secure.travis-ci.org/ahf/erlang-ucrypto.png)](http://travis-ci.org/ahf/erlang-ucrypto)

Authors
-------

[Alexander Færøy](mailto:ahf@0x90.dk) -- Main code.
