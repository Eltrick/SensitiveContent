# SensitiveContent
A custom[-ish] combined implementation of Diffie-Hellman, AES and/or RSA to facilitate manual encrypted exchanges.
## Requirements
- To build, install .NET 10 SDK.
- To run, install .NET 10 Desktop Runtime.

Available at [.NET 10.0](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)
## Expected common usage pipeline:
1. Run the program, which generates an RSA and Elliptic Curve Diffie-Hellman key pair in the printed location.
1.  1. If following the ECDH pipeline, send each other your public keys, and use them in conjunction with the private keys to derive AES keys for encryption
	1. If following the RSA pipeline, send a public key, the other person uses it to encrypt an AES key to be sent back.
1. Use the corresponding options to derive/unwrap keys. Now both parties have the same AES key to be used to encrypt messages and/or files.
1. Depending on whether encrypted exchanges need to be recoverable, store the private keys somewhere safe or delete them afterwards.