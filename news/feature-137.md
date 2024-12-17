Add `fingerprint-alg()` option to `tls()` blocks: SSL peers can be validated
using the `trusted-keys()` option that takes a list of trusted public key
fingerprints.  This was using the `sha1` algorithm, which is not considered
safe anymore.  This option can be used to customize the message digest
algorithm and accepts any known algorithms supported by OpenSSL. As of
OpenSSL 3.0.10, the followings are supported (OpenSSL 3.0.10):

Message Digest commands (see the `dgst' command for more details)
blake2b512        blake2s256        md4               md5
rmd160            sha1              sha224            sha256
sha3-224          sha3-256          sha3-384          sha3-512
sha384            sha512            sha512-224        sha512-256
shake128          shake256          sm3
