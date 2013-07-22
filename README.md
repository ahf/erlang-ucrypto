

# Erlang µCrypto Library #

Copyright (c) 2012, 2013 Alexander Færøy


__Authors:__ Alexander Færøy ([`ahf@0x90.dk`](mailto:ahf@0x90.dk)).

µCrypto is a thin Erlang wrapper for the OpenSSL library. Most of the features
in this library should be upstreamed and included the crypto module of the OTP
codebase.

The need for this module is the fact that Erlang's built-in crypto modules
lacks certain features that would be nice to have in one of our future
applications.


### <a name="Contributing">Contributing</a> ###

Contributions to µCrypto are welcome. Please go ahead and fork the project here
on Github and submit pull requests when you have something ready for review. I
will give feedback and once everything looks good, I will merge your
contributions into the mainline repository.


### <a name="Continuous_Integration">Continuous Integration</a> ###

We are currently using [Travis CI](http://www.travis-ci.org/) for continuous
integration. When submitting patches, please ensure that the entire project
compiles without errors and our tests are passing.

[![Build Status](https://secure.travis-ci.org/ahf/erlang-ucrypto.png)](http://travis-ci.org/ahf/erlang-ucrypto)


## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="https://github.com/ahf/erlang-ucrypto/blob/master/doc/ucrypto.md" class="module">ucrypto</a></td></tr>
<tr><td><a href="https://github.com/ahf/erlang-ucrypto/blob/master/doc/ucrypto_types.md" class="module">ucrypto_types</a></td></tr></table>

