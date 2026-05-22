# YubiHsmSharp.PciPin

An implementation of PCI-compatible PIN cryptography methods that store sensitive keys in a YubiHSM 2.

## Design

Any cryptographic method supported by YubiHSM 2 should be performed by the HSM. Any cryptographic method not supported by YubiHSM 2 should be performed in-memory with BouncyCastle. Long-lived keys and multi-use keys should be stored in the HSM, even if their cryptographic usage is not supported by YubiHSM 2. Ephemeral keys (such as subkeys used in CMAC calcuationss) should not be stored in the HSM, as YubiHSM 2 has limited storage space.

## Operations

* Creating a Zone Master Key (ZMK) from three key components: `KeyUtils.CombineComponents`
* Creating Key Check Values (KCV) from keys and key components: `KeyUtils.AesKeyCheckValue`
* Importing a Zone Master Key (ZMK) into the YubiHSM 2: `YubiSession.ImportZoneMasterKey`
* Importing a TR-31 Key Block protected by a stored ZMK: `YubiSession.ImportAesKey`
* Encrypting a PIN using a stored PIN Encryption Key (PEK): `YubiSession.EncryptPin`
* Decrypting a PIN using a stored PIN Encryption Key (PEK): `YubiSession.DecryptPin`

Once a ZMK or PEK is imported into the YubiHSM 2, the key is never extracted for local cryptography. All required operations that act on a stored key occur within the YubiHSM 2 device.

## Example

The following code takes user-provided key components and merges them into a Zone Master Key (ZMK). The ZMK is then imported into the YubiHSM 2. Then, a user-provided TR-31 Key Block is imported into the YubiHSM 2 using the stored ZMK. Finally, a PIN is encrypted and decrypted using the stored PIN Encryption Key (PEK) that was previously extracted from the Key Block.

```csharp
using YubiHsmSharp;
using YubiHsmSharp.PciPin;

ReadOnlySpan<byte> keyComponent1 = ReadFromUser();
Span<byte> keyCheckValue1 = stackalloc byte[3];
int written = KeyUtils.AesKeyCheckValue(keyComponent1, keyCheckValue1);
keyCheckValue1 = keyCheckValue1[..written];
AskUserIfCorrect(keyCheckValue1);

ReadOnlySpan<byte> keyComponent2 = ReadFromUser();
Span<byte> keyCheckValue2 = stackalloc byte[3];
written = KeyUtils.AesKeyCheckValue(keyComponent2, keyCheckValue2);
keyCheckValue2 = keyCheckValue2[..written];
AskUserIfCorrect(keyCheckValue2);

ReadOnlySpan<byte> keyComponent3 = ReadFromUser();
Span<byte> keyCheckValue3 = stackalloc byte[3];
written = KeyUtils.AesKeyCheckValue(keyComponent3, keyCheckValue2);
keyCheckValue3 = keyCheckValue3[..written];
AskUserIfCorrect(keyCheckValue3);

Span<byte> zoneMasterKey = stackalloc byte[keyComponent1.Length];
written = KeyUtils.CombineComponents(keyComponent1, keyComponent2, keyComponent3, zoneMasterKey);
zoneMasterKey = zoneMasterKey[..written];
Span<byte> zoneMasterKeyCheckValue = stackalloc byte[3];
written = KeyUtils.AesKeyCheckValue(zoneMasterKey, zoneMasterKeyCheckValue);
zoneMasterKeyCheckValue = zoneMasterKeyCheckValue[..written];
AskUserIfCorrect(zoneMasterKeyCheckValue);

using YubiSession session = CreateYubiSession(); // See YubiHsmSharp documentation for the detailed creation process.
ushort zoneMasterKeyId = session.ImportZoneMasterKey("My Zone Master Key"u8, Domains.From("1,2,3"u8), zoneMasterKey);

TR31KeyBlock pinEncryptionKeyBlock = ReadFromDynamicKeyExchange();
ushort pinEncryptionKeyId = session.ImportAesKey(pinEncryptionKeyBlock, zoneMasterKeyId, "My PIN Encryption Key"u8, Domains.From("1,2,3"u8));

string primaryAccountNumber = ReadFromUser();
string pin = ReadFromUser();
Format4PinBlock pinBlock = session.EncryptPin(pinEncryptionKeyId, pin, primaryAccountNumber);
string pinCopy = session.DecryptPin(pinEncryptionKeyId, pinBlock, primaryAccountNumber);
Debug.Assert(pin == pinCopy);
```