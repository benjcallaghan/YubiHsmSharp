# YubiHsmSharp.PciPin

A library of cryptographic methods suitable for use with PIN transactions in a credit card environment.

## Design

Any cryptographic method supported by YubiHSM 2 should be performed by the HSM. Any cryptographic method not supported by YubiHSM 2 should be performed in-memory with BouncyCastle. Long-lived keys and multi-use keys should be stored in the HSM, even if their cryptographic usage is not supported by YubiHSM 2. Ephemeral keys (such as subkeys used in CMAC calcuationss) should not be stored in the HSM, as YubiHSM 2 has limited storage space.