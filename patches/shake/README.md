# SP1 SHAKE adapter

This workspace-only compatibility crate exposes the public SHAKE API expected
by `ml-dsa 0.1` and delegates it to RustCrypto `sha3 0.11`.

The workspace patches `sha3 0.11` to SP1's official implementation. On the
Succinct zkVM target its SHAKE permutation uses the Keccak syscall; native and
other zkVM targets retain RustCrypto's portable implementation. FIPS 202 output
and ML-DSA protocol parameters are unchanged.
