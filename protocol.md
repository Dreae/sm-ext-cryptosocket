## SM CryptoSocket Protocol

### Foreword
The protocol defined in this document was created by a cryptography enthusiast, not someone with any formal training
in cryptography, or cryptographic concepts. It was designed as a hobby, for securing communication between video
game servers, and should probably not be used for anything of signficant importance.

#### Prior Art
The protocol described is heavily inspired by both the [Olm Cryptographic Ratchet](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md),
and the [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/#overview), ableit significantly simplified from
both of those protocols to reduce complexity of use and implementation.


#### Notation
This document uses $`\parallel`$ to represent string concatenation. When $`\parallel`$ appears on the right hand side of an $`=`$ it means
that the inputs are concatenated. When $`\parallel`$ appears on the left hand side of an $`=`$ it means the output is split.

When this document uses $`\operatorname{HKFD}\left(salt,IKM,info,L\right)`$ it means to perform 
[HMAC-based key derivation function](https://tools.ietf.org/html/rfc5869) using SHA512-256 as the 
hashing algorithm with a salt $`salt`$ input key material $`IKM`$, context string $`info`$ and output length $`L`$.

## Algorithm
#### Initial setup
The setup takes two one-time [Curve25519](http://cr.yp.to/ecdh.html) inputs for Alice and Bob, $`E_A`$ and $`E_B`$, and a shared
session key $`S`$ is computed using [Elliptic-curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
on the one-time inputs. Two 256 bit chain keys are then generated using HKDF with $`info`$ `"\x01"` on the Curve25519 public
keys and $`S`$. One chain key $`C_R`$ is used for receiving messages, and the other $`C_M`$ is used when sending messages.
$$
\begin{aligned}
    S&=\operatorname{ECDH}\left(E_A,E_B\right)\\
    C_{R,0}\parallel\;C_{M,0}&=\operatorname{HKDF}\left(0,S\parallel\;E_A^{public}\parallel\;E_B^{public},\text{``\char`\\x01``},64\right)
\end{aligned}
$$

#### Advancing the chain keys
Advancing a chain key takes the previous chain key, $`C_{i,j-1}`$. The next chain key, $`C_{i,j}`$ is the HMAC-SHA512-256 of
`"\x02"` using the previous chain key as the key.
$$
\begin{aligned}
    C_{i,j}&=\operatorname{HMAC}\left(C_{i,j-1},\text{``\char`\\x02``}\right)
\end{aligned}
$$

#### Encrypting messages
Messages are encrypted using [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439) with a 256 bit encryption key and a 96 bit
nonce derived from the chain key $`C_{i,j}`$. After sending a message, the message chain key is advanced as defined above.
$$
\begin{aligned}
    KEY_{i,j}\parallel\;NONCE_{i,j}&=\operatorname{HKDF}\left(0,C_{i,j},\text{``SMCRYPTO\_KEYS``},44\right)
\end{aligned}
$$


## Protocol
#### Creating an outbound session
The setup starts with Alice establishing a TCP connection with Bob. Alice and Bob then compute a derived signing key $`DK`$ using
shared secret key $`K`$ and a random salt $`salt`$ with a lenght of 32 bytes, and a pair of ECDH keys $`E_A`$ and $`E_B`$. Alice
computes a message signature for $`salt_{alice}`$, $`E_A^{public}`$ and Key ID $`K_{id}`$ using derived signing key $`DK`$. Alice
then transmits her salt, ECDH public key, Key ID, and the message signature to Bob.
$$
\begin{aligned}
    DK&=\operatorname{PBKDF2\_BLAKE2b}\left(salt,K,10000,64\right)\\

    S&=\operatorname{HMAC}\left(salt\parallel\;E_A^{public}\parallel\;K_{id}\right)
\end{aligned}
$$
