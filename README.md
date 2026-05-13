# YubiHsmSharp

A comprehensive, type-safe .NET wrapper for the YubiHSM 2 SDK (libyubihsm). Provides an idiomatic C# API for HSM operations including key management, cryptographic signing/verification, encryption, and secure object storage.

## Features

- **Full API Coverage**: All ~100+ libyubihsm functions wrapped with C# type safety
- **Object-Oriented Design**: Instance methods on `YhConnector` and `YhSession` with proper resource management
- **Exception-Based Error Handling**: Device errors mapped to typed exceptions instead of return codes
- **Comprehensive Type Safety**: Enums, structs, and capabilities system with helper methods
- **IDisposable Support**: Automatic resource cleanup via `using` statements
- **XML Documentation**: Full doc comments adapted from official YubiHSM documentation

## Installation

Requires:
- .NET 10.0 or later
- libyubihsm native library (installed and available in system PATH)

## Quick Start

### Basic Connection and Key Operations

```csharp
using YubiHsmSharp;

// Create and connect to device
using var connector = YhConnector.Create("yhusb://");
connector.Connect(timeout: 5000);

// Create an authenticated session
using var session = connector.CreateSessionDerived(
    authKeyId: 1, 
    password: "password");

// Generate an HMAC key
var keyId = session.GenerateHmacKey(
    keyId: 0xFFFF,  // 0xFFFF = auto-generate
    label: "my-hmac-key",
    domains: 1,
    capabilities: YhCapabilities.From(
        YhCapability.SignHmac,
        YhCapability.VerifyHmac),
    algorithm: YhAlgorithm.HmacSha256);

// Sign data
var data = new byte[] { 1, 2, 3, 4, 5 };
var signature = session.SignHmac(keyId, data);

// Verify signature
bool isValid = session.VerifyHmac(keyId, signature, data);
Console.WriteLine($"Signature valid: {isValid}");

// Session and connector cleanup automatic via IDisposable
```

### Working with Asymmetric Keys

```csharp
// Generate RSA key
var keyId = session.GenerateAsymmetricKey(
    keyId: 0xFFFF,
    label: "rsa-2048-key",
    domains: 1,
    capabilities: YhCapabilities.From(
        YhCapability.SignPkcs,
        YhCapability.SignPss,
        YhCapability.GetObject),
    algorithm: YhAlgorithm.Rsa2048);

// Sign data (PKCS#1 v1.5)
var signature = session.SignPkcs(keyId, hashedData);

// Sign with PSS padding
var pssSig = session.SignPss(keyId, hashedData, saltLength: 32);

// Get public key
session.GetPublicKey(keyId, out var publicKey, out var algo);
```

### Device Information

```csharp
// Get device info (no authentication required)
var deviceInfo = connector.GetDeviceInfo();
Console.WriteLine($"Serial: {deviceInfo.SerialNumber}");
Console.WriteLine($"Firmware: {deviceInfo.FirmwareVersion}");
Console.WriteLine($"FIPS Mode: {deviceInfo.FipsMode}");

// List all objects on device
var objects = connector.ListObjects();
foreach (var obj in objects)
{
    Console.WriteLine($"[{obj.Type}:0x{obj.Id:X4}] {obj.Label}");
}

// Get storage information
session.GetStorageInfo(out var total, out var free, out var used);
Console.WriteLine($"Storage: {free}/{total} slots free");
```

### Exception Handling

```csharp
try
{
    var signature = session.SignHmac(invalidKeyId, data);
}
catch (YubiHsmDeviceException ex)
{
    Console.WriteLine($"Device error: {ex.ErrorCode} - {ex.Message}");
}
catch (YubiHsmException ex)
{
    Console.WriteLine($"Library error: {ex.Message}");
}
```

## API Architecture

### Core Classes

- **`YhConnector`**: Manages device connection lifecycle
  - `Create()` - Factory method to create a connector
  - `Connect()` / `Disconnect()` - Manage transport
  - `GetDeviceInfo()` - Retrieve device properties
  - `ListObjects()` - Enumerate all objects
  - `CreateSessionDerived()` / `CreateSessionSymmetric()` / `CreateSessionAsymmetric()` - Create authenticated sessions

- **`YhSession`**: Authenticated session for crypto operations
  - **Key Management**: `GenerateHmacKey()`, `GenerateAsymmetricKey()`, `GenerateSymmetricKey()`, `Import*()`, `DeleteObject()`
  - **HMAC**: `SignHmac()`, `VerifyHmac()`
  - **RSA**: `SignPkcs()`, `SignPss()`, `DecryptPkcs()`, `DecryptOaep()`, `GetPublicKey()`
  - **EC**: `SignEcdsa()`, `SignEddsa()`, `EcdhDerivation()`
  - **AES**: `EncryptAes()`, `DecryptAes()`
  - **Key Wrapping**: `ExportWrappedKey()`, `ImportWrappedKey()`
  - **Device Ops**: `GetStorageInfo()`, `ResetDevice()`, `GetRandomBytes()`, `GetOption()`, `SetOption()`

### Type System

- **Enums**: `YhObjectType`, `YhAlgorithm`, `YhCommand`, `YhOption`, `YhCapability`, `YhReturnCode`
- **Structs**: `YhObjectInfo` (object metadata), `YhDeviceInfo` (device properties), `YhCapabilities` (permission bitmask)
- **Exceptions**: `YubiHsmException` (base), `YubiHsmDeviceException` (device-specific errors)

### Capabilities System

Capabilities control what operations a key or authentication session can perform:

```csharp
// Create capabilities with specific flags
var caps = YhCapabilities.From(
    YhCapability.SignHmac,
    YhCapability.VerifyHmac,
    YhCapability.GetObject);

// Check capabilities
if (caps.CanSignHmac && caps.CanVerifyHmac)
{
    // Safe to use for signing and verification
}

// Convert to/from string arrays (for configuration files, etc.)
var capStrings = caps.ToStringArray();  // ["sign-hmac", "verify-hmac", "get-object"]
var parsed = YhCapabilities.FromStringArray("sign-hmac", "verify-hmac");
```

## P/Invoke Layer

All native P/Invoke declarations are internal in `NativeMethods.cs`. The public API uses managed wrappers that:
- Convert yh_rc return codes to exceptions
- Marshal native data structures to managed types
- Manage memory lifetimes and cleanup
- Provide idiomatic C# parameter names and types

## Supported Operations

### Key Operations
- ✅ Generate HMAC keys
- ✅ Generate RSA keys (2048, 3072, 4096 bit)
- ✅ Generate EC keys (P-256, P-384, P-521, secp256k1, Brainpool, Ed25519, Ed448, X25519, X448)
- ✅ Generate AES/symmetric keys
- ✅ Import asymmetric, symmetric, and opaque objects
- ✅ Export/import wrapped objects (key encryption)
- ✅ Delete objects

### Cryptographic Operations
- ✅ HMAC: sign and verify
- ✅ RSA: sign (PKCS#1 v1.5, PSS), decrypt (PKCS#1, OAEP), get public key
- ✅ EC: ECDSA and EdDSA signing, ECDH key derivation
- ✅ AES: encrypt and decrypt
- ✅ Get pseudo-random bytes from device

### Device Management
- ✅ Get device information (serial, firmware, capabilities)
- ✅ List objects on device
- ✅ Get object metadata
- ✅ Get storage information
- ✅ Set/get device options
- ✅ Reset device
- ✅ Session management (create, close, query)

## Testing

The wrapper includes a comprehensive test suite structure. Tests are written but require a physical YubiHSM 2 device to run:

```bash
cd YubiHsmSharp.Tests
dotnet test
```

## Documentation

Full XML documentation is provided with the library:
- Generated DocFX documentation available in `docs/`
- All public types and methods include doc comments
- References to official YubiHSM documentation where applicable

See: https://docs.yubico.com/hardware/yubihsm-2/

## License

Apache License 2.0 - See LICENSE file for details

## References

- [YubiHSM 2 Documentation](https://docs.yubico.com/hardware/yubihsm-2/)
- [libyubihsm Source](https://github.com/Yubico/yubihsm-shell)
- [YubiHSM Shell Examples](https://github.com/Yubico/yubihsm-shell/tree/main/examples)
