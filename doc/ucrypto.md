

# Module ucrypto #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)


uCrypto.
Copyright (c)  2012, 2013 Alexander Færøy

__Authors:__ Alexander Færøy ([`ahf@0x90.dk`](mailto:ahf@0x90.dk)).
<a name="description"></a>

## Description ##
   This module contains the public API for the uCrypto library.
<a name="types"></a>

## Data Types ##




### <a name="type-ec_curve">ec_curve()</a> ###



<pre><code>
ec_curve() = <a href="ucrypto_types.md#type-ec_curve">ucrypto_types:ec_curve()</a>
</code></pre>





### <a name="type-ec_hash_function">ec_hash_function()</a> ###



<pre><code>
ec_hash_function() = <a href="ucrypto_types.md#type-ec_hash_function">ucrypto_types:ec_hash_function()</a>
</code></pre>





### <a name="type-ec_key">ec_key()</a> ###



<pre><code>
ec_key() = <a href="ucrypto_types.md#type-ec_key">ucrypto_types:ec_key()</a>
</code></pre>





### <a name="type-ec_private_key">ec_private_key()</a> ###



<pre><code>
ec_private_key() = <a href="ucrypto_types.md#type-ec_private_key">ucrypto_types:ec_private_key()</a>
</code></pre>





### <a name="type-ec_public_key">ec_public_key()</a> ###



<pre><code>
ec_public_key() = <a href="ucrypto_types.md#type-ec_public_key">ucrypto_types:ec_public_key()</a>
</code></pre>





### <a name="type-ec_signature">ec_signature()</a> ###



<pre><code>
ec_signature() = <a href="ucrypto_types.md#type-ec_signature">ucrypto_types:ec_signature()</a>
</code></pre>


<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#bin2hex-1">bin2hex/1</a></td><td></td></tr><tr><td valign="top"><a href="#ec_curve_size-1">ec_curve_size/1</a></td><td></td></tr><tr><td valign="top"><a href="#ec_delete_key-1">ec_delete_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#ec_new_key-1">ec_new_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#ec_new_key-3">ec_new_key/3</a></td><td></td></tr><tr><td valign="top"><a href="#ec_new_private_key-2">ec_new_private_key/2</a></td><td></td></tr><tr><td valign="top"><a href="#ec_new_public_key-2">ec_new_public_key/2</a></td><td></td></tr><tr><td valign="top"><a href="#ec_private_key-1">ec_private_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#ec_public_key-1">ec_public_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#ec_set_private_key-2">ec_set_private_key/2</a></td><td></td></tr><tr><td valign="top"><a href="#ec_set_public_key-2">ec_set_public_key/2</a></td><td></td></tr><tr><td valign="top"><a href="#ec_sign-2">ec_sign/2</a></td><td></td></tr><tr><td valign="top"><a href="#ec_sign-3">ec_sign/3</a></td><td></td></tr><tr><td valign="top"><a href="#ec_sign_hash-3">ec_sign_hash/3</a></td><td></td></tr><tr><td valign="top"><a href="#ec_sign_hash-4">ec_sign_hash/4</a></td><td></td></tr><tr><td valign="top"><a href="#ec_verify-3">ec_verify/3</a></td><td></td></tr><tr><td valign="top"><a href="#ec_verify-4">ec_verify/4</a></td><td></td></tr><tr><td valign="top"><a href="#ec_verify_hash-4">ec_verify_hash/4</a></td><td></td></tr><tr><td valign="top"><a href="#ec_verify_hash-5">ec_verify_hash/5</a></td><td></td></tr><tr><td valign="top"><a href="#hex2bin-1">hex2bin/1</a></td><td></td></tr><tr><td valign="top"><a href="#ripemd160-1">ripemd160/1</a></td><td></td></tr><tr><td valign="top"><a href="#ripemd160_final-1">ripemd160_final/1</a></td><td></td></tr><tr><td valign="top"><a href="#ripemd160_init-0">ripemd160_init/0</a></td><td></td></tr><tr><td valign="top"><a href="#ripemd160_update-2">ripemd160_update/2</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="bin2hex-1"></a>

### bin2hex/1 ###


<pre><code>
bin2hex(Bin::binary()) -&gt; string()
</code></pre>

<br></br>



<a name="ec_curve_size-1"></a>

### ec_curve_size/1 ###


<pre><code>
ec_curve_size(X1::<a href="#type-ec_curve">ec_curve()</a>) -&gt; integer()
</code></pre>

<br></br>



<a name="ec_delete_key-1"></a>

### ec_delete_key/1 ###


<pre><code>
ec_delete_key(X1::<a href="#type-ec_key">ec_key()</a>) -&gt; ok
</code></pre>

<br></br>



<a name="ec_new_key-1"></a>

### ec_new_key/1 ###


<pre><code>
ec_new_key(Curve::<a href="#type-ec_curve">ec_curve()</a>) -&gt; <a href="#type-ec_key">ec_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_new_key-3"></a>

### ec_new_key/3 ###


<pre><code>
ec_new_key(Curve::<a href="#type-ec_curve">ec_curve()</a>, PrivateKey::<a href="#type-ec_private_key">ec_private_key()</a>, PublicKey::<a href="#type-ec_public_key">ec_public_key()</a>) -&gt; <a href="#type-ec_key">ec_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_new_private_key-2"></a>

### ec_new_private_key/2 ###


<pre><code>
ec_new_private_key(Curve::<a href="#type-ec_curve">ec_curve()</a>, PrivateKey::<a href="#type-ec_private_key">ec_private_key()</a>) -&gt; <a href="#type-ec_key">ec_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_new_public_key-2"></a>

### ec_new_public_key/2 ###


<pre><code>
ec_new_public_key(Curve::<a href="#type-ec_curve">ec_curve()</a>, PublicKey::<a href="#type-ec_public_key">ec_public_key()</a>) -&gt; <a href="#type-ec_key">ec_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_private_key-1"></a>

### ec_private_key/1 ###


<pre><code>
ec_private_key(X1::<a href="#type-ec_key">ec_key()</a>) -&gt; <a href="#type-ec_private_key">ec_private_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_public_key-1"></a>

### ec_public_key/1 ###


<pre><code>
ec_public_key(X1::<a href="#type-ec_key">ec_key()</a>) -&gt; <a href="#type-ec_public_key">ec_public_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_set_private_key-2"></a>

### ec_set_private_key/2 ###


<pre><code>
ec_set_private_key(X1::<a href="#type-ec_key">ec_key()</a>, PrivateKey::<a href="#type-ec_private_key">ec_private_key()</a>) -&gt; <a href="#type-ec_key">ec_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_set_public_key-2"></a>

### ec_set_public_key/2 ###


<pre><code>
ec_set_public_key(X1::<a href="#type-ec_key">ec_key()</a>, PublicKey::<a href="#type-ec_public_key">ec_public_key()</a>) -&gt; <a href="#type-ec_key">ec_key()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_sign-2"></a>

### ec_sign/2 ###


<pre><code>
ec_sign(Data::iodata(), X2::<a href="#type-ec_key">ec_key()</a>) -&gt; <a href="#type-ec_signature">ec_signature()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_sign-3"></a>

### ec_sign/3 ###


<pre><code>
ec_sign(Data::iodata(), Curve::<a href="#type-ec_curve">ec_curve()</a>, PrivateKey::<a href="#type-ec_private_key">ec_private_key()</a>) -&gt; <a href="#type-ec_signature">ec_signature()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_sign_hash-3"></a>

### ec_sign_hash/3 ###


<pre><code>
ec_sign_hash(Data::iodata(), Hash::<a href="#type-ec_hash_function">ec_hash_function()</a>, Key::<a href="#type-ec_key">ec_key()</a>) -&gt; <a href="#type-ec_signature">ec_signature()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_sign_hash-4"></a>

### ec_sign_hash/4 ###


<pre><code>
ec_sign_hash(Data::iodata(), Hash::<a href="#type-ec_hash_function">ec_hash_function()</a>, Curve::<a href="#type-ec_curve">ec_curve()</a>, PrivateKey::<a href="#type-ec_private_key">ec_private_key()</a>) -&gt; <a href="#type-ec_signature">ec_signature()</a> | {error, any()}
</code></pre>

<br></br>



<a name="ec_verify-3"></a>

### ec_verify/3 ###


<pre><code>
ec_verify(Data::iodata(), Signature::<a href="#type-ec_signature">ec_signature()</a>, X3::<a href="#type-ec_key">ec_key()</a>) -&gt; boolean() | {error, any()}
</code></pre>

<br></br>



<a name="ec_verify-4"></a>

### ec_verify/4 ###


<pre><code>
ec_verify(Data::iodata(), Signature::<a href="#type-ec_signature">ec_signature()</a>, Curve::<a href="#type-ec_curve">ec_curve()</a>, PublicKey::<a href="#type-ec_public_key">ec_public_key()</a>) -&gt; boolean() | {error, any()}
</code></pre>

<br></br>



<a name="ec_verify_hash-4"></a>

### ec_verify_hash/4 ###


<pre><code>
ec_verify_hash(Data::iodata(), Hash::<a href="#type-ec_hash_function">ec_hash_function()</a>, Signature::<a href="#type-ec_signature">ec_signature()</a>, Key::<a href="#type-ec_key">ec_key()</a>) -&gt; boolean() | {error, any()}
</code></pre>

<br></br>



<a name="ec_verify_hash-5"></a>

### ec_verify_hash/5 ###


<pre><code>
ec_verify_hash(Data::iodata(), Hash::<a href="#type-ec_hash_function">ec_hash_function()</a>, Signature::<a href="#type-ec_signature">ec_signature()</a>, Curve::<a href="#type-ec_curve">ec_curve()</a>, PublicKey::<a href="#type-ec_public_key">ec_public_key()</a>) -&gt; boolean() | {error, any()}
</code></pre>

<br></br>



<a name="hex2bin-1"></a>

### hex2bin/1 ###


<pre><code>
hex2bin(Rest::string()) -&gt; binary()
</code></pre>

<br></br>



<a name="ripemd160-1"></a>

### ripemd160/1 ###


<pre><code>
ripemd160(Data::iodata()) -&gt; binary()
</code></pre>

<br></br>



<a name="ripemd160_final-1"></a>

### ripemd160_final/1 ###


<pre><code>
ripemd160_final(Context::binary()) -&gt; binary()
</code></pre>

<br></br>



<a name="ripemd160_init-0"></a>

### ripemd160_init/0 ###


<pre><code>
ripemd160_init() -&gt; binary()
</code></pre>

<br></br>



<a name="ripemd160_update-2"></a>

### ripemd160_update/2 ###


<pre><code>
ripemd160_update(Context::binary(), Data::iodata()) -&gt; binary()
</code></pre>

<br></br>



