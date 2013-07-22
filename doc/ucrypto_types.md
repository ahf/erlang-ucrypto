

# Module ucrypto_types #
* [Description](#description)
* [Data Types](#types)


uCrypto Types.
Copyright (c)  2013 Alexander Færøy

__Authors:__ Alexander Færøy ([`ahf@0x90.dk`](mailto:ahf@0x90.dk)).
<a name="description"></a>

## Description ##
   This module contains common types used in the uCrypto code.
<a name="types"></a>

## Data Types ##




### <a name="type-ec_curve">ec_curve()</a> ###



<pre><code>
ec_curve() = secp112r1 | secp112r2 | secp128r1 | secp128r2 | secp160k1 | secp160r1 | secp160r2 | secp192k1 | secp224k1 | secp224r1 | secp256k1 | secp384r1 | secp521r1
</code></pre>





### <a name="type-ec_hash_function">ec_hash_function()</a> ###



<pre><code>
ec_hash_function() = fun((iodata()) -&gt; binary())
</code></pre>





### <a name="type-ec_key">ec_key()</a> ###



<pre><code>
ec_key() = {ec_key, <a href="#type-ec_key_ref">ec_key_ref()</a>}
</code></pre>





### <a name="type-ec_key_ref">ec_key_ref()</a> ###


__abstract datatype__: `ec_key_ref()`




### <a name="type-ec_private_key">ec_private_key()</a> ###



<pre><code>
ec_private_key() = binary
</code></pre>





### <a name="type-ec_public_key">ec_public_key()</a> ###



<pre><code>
ec_public_key() = binary
</code></pre>





### <a name="type-ec_signature">ec_signature()</a> ###



<pre><code>
ec_signature() = binary
</code></pre>


