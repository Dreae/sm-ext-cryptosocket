## SM CryptoSockets


#### Protocol Specification
SM CryptoSockets use a Key ID and Key combination to secure communication
between the extension and an external service. The Key is shared between
both parties, and is used for message authentication during the initial
handshake. Once the handshake is complete both parties maintain session
keys using a cryptographic ratchet for the duration of the connection.

For a more complete discussion of the protocol suitable for implementing
the protocol in your own libraries, see [protocol.md](protocol.md).