# YubiHsmSharp API Reference

This document provides a comprehensive reference for the YubiHsmSharp .NET wrapper API.

## Table of Contents

1. [Core Classes](#core-classes)
2. [Enumerations](#enumerations)
3. [Structures](#structures)
4. [Exception Types](#exception-types)
5. [Capability System](#capability-system)
6. [Usage Patterns](#usage-patterns)

## Core Classes

### YhConnector

Manages the connection to the YubiHSM device.

#### Static Methods

```csharp
/// <summary>
/// Creates a new YhConnector instance.
/// </summary>
/// <param name="url">Device URL (default: "yhusb://")</param>
/// <returns>A new connector instance</returns>
public static YhConnector Create(string url = "yhusb://")
```

#### Instance Properties

```csharp
/// <summary>
/// Gets whether the connector is currently connected to the device.
/// </summary>
public bool IsConnected { get; }
```

#### Instance Methods

```csharp
/// <summary>
/// Connects to the YubiHSM device.
/// </summary>
/// <param name="timeoutMs">Connection timeout in milliseconds (0 = no timeout)</param>
public void Connect(int timeoutMs = 0)

/// <summary>
/// Disconnects from the YubiHSM device.
/// </summary>
public void Disconnect()

/// <summary>
/// Retrieves device information without authentication.
/// </summary>
/// <returns>Device information structure</returns>
public YhDeviceInfo GetDeviceInfo()

/// <summary>
/// Lists all objects currently stored on the device.
/// </summary>
/// <returns>Array of object information structures</returns>
public YhObjectInfo[] ListObjects()

/// <summary>
/// Creates an authenticated session using password-derived keys.
/// </summary>
/// <param name="authKeyId">ID of the authentication key</param>
/// <param name="password">Password to derive session keys from</param>
/// <param name="sessionId">Session ID to use (0 = auto-assign)</param>
/// <returns>An authenticated session</returns>
public YhSession CreateSessionDerived(ushort authKeyId, string password, byte sessionId = 0)

/// <summary>
/// Creates an authenticated session using symmetric keys.
/// </summary>
/// <param name="authKeyId">ID of the authentication key</param>
/// <param name="encryptionKey">Session encryption key (16 or 24 bytes)</param>
/// <param name="macKey">Session MAC key (16 or 24 bytes)</param>
/// <param name="sessionId">Session ID to use (0 = auto-assign)</param>
/// <returns>An authenticated session</returns>
public YhSession CreateSessionSymmetric(ushort authKeyId, byte[] encryptionKey, byte[] macKey, byte sessionId = 0)

/// <summary>
/// Begins asymmetric session creation (requires completion with FinishCreateSessionAsymmetric).
/// </summary>
/// <param name="authKeyId">ID of the authentication key</param>
/// <param name="context">Output context for handshake</param>
/// <param name="cardCrypto">Output card cryptographic data</param>
public void BeginCreateSessionAsymmetric(ushort authKeyId, out byte[] context, out byte[] cardCrypto)

/// <summary>
/// Completes asymmetric session creation.
/// </summary>
/// <param name="context">Context from BeginCreateSessionAsymmetric</param>
/// <param name="sessionEncKey">Session encryption key from asymmetric key agreement</param>
/// <param name="sessionMacKey">Session MAC key from asymmetric key agreement</param>
/// <param name="cardCrypto">Card cryptographic data from BeginCreateSessionAsymmetric</param>
/// <param name="sessionId">Session ID to use (0 = auto-assign)</param>
/// <returns>An authenticated session</returns>
public YhSession FinishCreateSessionAsymmetric(
    byte[] context, byte[] sessionEncKey, byte[] sessionMacKey, byte[] cardCrypto, byte sessionId = 0)
```

---

### YhSession

Represents an authenticated session for cryptographic operations.

#### Instance Properties

```csharp
/// <summary>
/// Gets the session ID.
/// </summary>
public byte SessionId { get; }

/// <summary>
/// Gets whether this session is still valid.
/// </summary>
public bool IsValid { get; }
```

#### Key Generation Methods

```csharp
/// <summary>
/// Generates a new HMAC key on the device.
/// </summary>
/// <param name="keyId">Desired key ID (0xFFFF = auto-generate)</param>
/// <param name="label">Human-readable key label</param>
/// <param name="domains">Domain bitmask</param>
/// <param name="capabilities">Operation capabilities</param>
/// <param name="algorithm">HMAC algorithm (e.g., HmacSha256)</param>
/// <returns>The assigned key ID</returns>
public ushort GenerateHmacKey(
    ushort keyId, string label, ushort domains, YhCapabilities capabilities, YhAlgorithm algorithm)

/// <summary>
/// Generates a new asymmetric (RSA/EC) key pair on the device.
/// </summary>
public ushort GenerateAsymmetricKey(
    ushort keyId, string label, ushort domains, YhCapabilities capabilities, YhAlgorithm algorithm)

/// <summary>
/// Generates a new symmetric (AES) key on the device.
/// </summary>
public ushort GenerateSymmetricKey(
    ushort keyId, string label, ushort domains, YhCapabilities capabilities, YhAlgorithm algorithm)

/// <summary>
/// Imports an asymmetric key pair into the device.
/// </summary>
public ushort ImportAsymmetricKey(
    ushort keyId, string label, ushort domains, YhCapabilities capabilities, 
    YhAlgorithm algorithm, byte[] keyMaterial)

/// <summary>
/// Imports a symmetric key into the device.
/// </summary>
public ushort ImportSymmetricKey(
    ushort keyId, string label, ushort domains, YhCapabilities capabilities, 
    YhAlgorithm algorithm, byte[] keyMaterial)

/// <summary>
/// Imports an opaque object into the device.
/// </summary>
public ushort ImportOpaque(
    ushort objectId, string label, ushort domains, YhCapabilities capabilities, 
    YhAlgorithm algorithm, byte[] data)
```

#### HMAC Operations

```csharp
/// <summary>
/// Signs data using HMAC.
/// </summary>
/// <param name="keyId">HMAC key ID</param>
/// <param name="data">Data to sign</param>
/// <returns>HMAC signature (up to 64 bytes)</returns>
public byte[] SignHmac(ushort keyId, byte[] data)

/// <summary>
/// Verifies an HMAC signature.
/// </summary>
/// <param name="keyId">HMAC key ID</param>
/// <param name="signature">Signature to verify</param>
/// <param name="data">Original data</param>
/// <returns>True if signature is valid</returns>
public bool VerifyHmac(ushort keyId, byte[] signature, byte[] data)
```

#### RSA Operations

```csharp
/// <summary>
/// Signs data using RSA PKCS#1 v1.5.
/// </summary>
/// <param name="keyId">RSA private key ID</param>
/// <param name="data">Hash to sign (typically SHA-256)</param>
/// <returns>Signature (up to 512 bytes)</returns>
public byte[] SignPkcs(ushort keyId, byte[] data)

/// <summary>
/// Signs data using RSA PSS padding.
/// </summary>
/// <param name="keyId">RSA private key ID</param>
/// <param name="data">Hash to sign</param>
/// <param name="saltLength">PSS salt length (typically 32)</param>
/// <returns>Signature (up to 512 bytes)</returns>
public byte[] SignPss(ushort keyId, byte[] data, int saltLength = 32)

/// <summary>
/// Retrieves the public key from an RSA key pair.
/// </summary>
/// <param name="keyId">RSA key ID</param>
/// <param name="publicKey">Output public key data</param>
/// <param name="algorithm">Output RSA algorithm type</param>
public void GetPublicKey(ushort keyId, out byte[] publicKey, out YhAlgorithm algorithm)

/// <summary>
/// Decrypts data using RSA PKCS#1 v1.5.
/// </summary>
/// <param name="keyId">RSA private key ID</param>
/// <param name="ciphertext">Ciphertext to decrypt</param>
/// <returns>Plaintext (up to 2048 bytes)</returns>
public byte[] DecryptPkcs(ushort keyId, byte[] ciphertext)

/// <summary>
/// Decrypts data using RSA OAEP.
/// </summary>
/// <param name="keyId">RSA private key ID</param>
/// <param name="ciphertext">Ciphertext to decrypt</param>
/// <returns>Plaintext (up to 2048 bytes)</returns>
public byte[] DecryptOaep(ushort keyId, byte[] ciphertext)
```

#### EC Operations

```csharp
/// <summary>
/// Signs data using ECDSA.
/// </summary>
/// <param name="keyId">EC private key ID</param>
/// <param name="data">Hash to sign</param>
/// <returns>Signature (up to 256 bytes)</returns>
public byte[] SignEcdsa(ushort keyId, byte[] data)

/// <summary>
/// Signs data using EdDSA (Ed25519/Ed448).
/// </summary>
/// <param name="keyId">Ed25519/Ed448 key ID</param>
/// <param name="data">Data to sign</param>
/// <returns>Signature (up to 256 bytes)</returns>
public byte[] SignEddsa(ushort keyId, byte[] data)

/// <summary>
/// Performs ECDH key derivation.
/// </summary>
/// <param name="keyId">EC private key ID</param>
/// <param name="peerPublicKey">Peer's public key</param>
/// <returns>Derived shared secret (up to 512 bytes)</returns>
public byte[] EcdhDerivation(ushort keyId, byte[] peerPublicKey)
```

#### AES Operations

```csharp
/// <summary>
/// Encrypts data using AES.
/// </summary>
/// <param name="keyId">AES key ID</param>
/// <param name="plaintext">Data to encrypt</param>
/// <returns>Ciphertext</returns>
public byte[] EncryptAes(ushort keyId, byte[] plaintext)

/// <summary>
/// Decrypts data using AES.
/// </summary>
/// <param name="keyId">AES key ID</param>
/// <param name="ciphertext">Data to decrypt</param>
/// <returns>Plaintext</returns>
public byte[] DecryptAes(ushort keyId, byte[] ciphertext)
```

#### Key Wrapping

```csharp
/// <summary>
/// Exports a key in wrapped (encrypted) form.
/// </summary>
/// <param name="wrapKeyId">Key encryption key ID</param>
/// <param name="objectType">Type of object to export</param>
/// <param name="objectId">Object ID to export</param>
/// <returns>Wrapped key data (up to 2048 bytes)</returns>
public byte[] ExportWrappedKey(ushort wrapKeyId, YhObjectType objectType, ushort objectId)

/// <summary>
/// Imports a previously wrapped key.
/// </summary>
/// <param name="wrapKeyId">Key encryption key ID</param>
/// <param name="wrappedObject">Wrapped key data</param>
/// <returns>The assigned ID of the imported object</returns>
public ushort ImportWrappedKey(ushort wrapKeyId, byte[] wrappedObject)
```

#### Object Management

```csharp
/// <summary>
/// Retrieves metadata about an object on the device.
/// </summary>
public YhObjectInfo GetObjectInfo(ushort objectId, YhObjectType objectType)

/// <summary>
/// Lists objects with optional filtering.
/// </summary>
/// <param name="typeFilter">Filter by object type (null = all types)</param>
/// <param name="idFilter">Filter by object ID (null = all IDs)</param>
/// <returns>Array of matching objects</returns>
public YhObjectInfo[] ListObjects(YhObjectType? typeFilter = null, ushort? idFilter = null)

/// <summary>
/// Sets the label attribute of an object.
/// </summary>
public void SetObjectAttributes(ushort objectId, YhObjectType objectType, string label)

/// <summary>
/// Deletes an object from the device.
/// </summary>
public void DeleteObject(ushort objectId, YhObjectType objectType)
```

#### Device Operations

```csharp
/// <summary>
/// Retrieves device storage information.
/// </summary>
/// <param name="totalSlots">Output: total storage slots</param>
/// <param name="freeSlots">Output: free storage slots</param>
/// <param name="usedRecords">Output: used audit log records</param>
public void GetStorageInfo(out ushort totalSlots, out ushort freeSlots, out ushort usedRecords)

/// <summary>
/// Retrieves pseudo-random bytes from the device.
/// </summary>
/// <param name="count">Number of bytes to retrieve</param>
/// <returns>Random bytes</returns>
public byte[] GetRandomBytes(int count)

/// <summary>
/// Resets the YubiHSM device to factory defaults.
/// WARNING: This operation is destructive and cannot be undone.
/// </summary>
public void ResetDevice()

/// <summary>
/// Gets a device option value.
/// </summary>
public byte[] GetOption(YhOption option)

/// <summary>
/// Sets a device option value.
/// </summary>
public void SetOption(YhOption option, byte[] value)
```

---

## Enumerations

### YhObjectType

Represents the type of object stored on the device.

```csharp
public enum YhObjectType : byte
{
    Opaque = 0x01,
    AuthenticationKey = 0x02,
    HmacKey = 0x03,
    BinaryKey = 0x04,
    RsaPrivateKey = 0x05,
    RsaPublicKey = 0x06,
    EcPrivateKey = 0x07,
    EcPublicKey = 0x08,
    Ed25519PrivateKey = 0x0E
}
```

### YhAlgorithm

Represents supported algorithms.

```csharp
public enum YhAlgorithm : byte
{
    // HMAC algorithms
    HmacSha1 = 0x03,
    HmacSha256 = 0x04,
    HmacSha384 = 0x05,
    HmacSha512 = 0x06,

    // RSA algorithms
    Rsa2048 = 0x09,
    Rsa3072 = 0x0A,
    Rsa4096 = 0x0B,

    // Elliptic Curve algorithms
    EcP256 = 0x0C,
    EcP384 = 0x0D,
    EcP521 = 0x0E,
    Secp256k1 = 0x0F,
    EcBrainpoolP256 = 0x10,
    EcBrainpoolP384 = 0x11,
    EcBrainpoolP512 = 0x12,
    Ed25519 = 0x22,
    Ed448 = 0x23,

    // AES algorithms
    Aes128 = 0x14,
    Aes192 = 0x15,
    Aes256 = 0x16
}
```

### YhCapability

Represents individual permission capabilities.

```csharp
[Flags]
public enum YhCapability : ulong
{
    SignHmac = 0x0000000000000001,
    VerifyHmac = 0x0000000000000002,
    SignPkcs = 0x0000000000000004,
    SignPss = 0x0000000000000008,
    SignEcdsa = 0x0000000000000010,
    SignEddsa = 0x0000000000000020,
    DecryptOaep = 0x0000000000000040,
    DecryptPkcs = 0x0000000000000080,
    EcdhDerivation = 0x0000000000000100,
    ExportWrapped = 0x0000000000000200,
    ImportWrapped = 0x0000000000000400,
    GenerateAsymmetricKey = 0x0000000000000800,
    GenerateSymmetricKey = 0x0000000000001000,
    GenerateHmacKey = 0x0000000000002000,
    GetObject = 0x0000000000004000,
    ListObjects = 0x0000000000008000,
    DeleteObject = 0x0000000000010000,
    GetOption = 0x0000000000020000,
    SetOption = 0x0000000000040000,
    GetPseudoRandom = 0x0000000000080000,
    EncryptAes = 0x0000000000100000,
    DecryptAes = 0x0000000000200000
    // ... additional capabilities
}
```

### YhReturnCode

Represents device return codes.

```csharp
public enum YhReturnCode
{
    Success = 0,
    MemoryError = -1,
    ConnectionError = -3,
    InvalidArgument = -4,
    AuthenticationFailed = 0x00,
    InvalidCommand = 0x01,
    InvalidData = 0x02,
    InvalidSession = 0x03,
    AuthenticationRequired = 0x04,
    // ... additional codes
}
```

---

## Structures

### YhObjectInfo

```csharp
public struct YhObjectInfo
{
    public ushort Id { get; set; }
    public YhObjectType Type { get; set; }
    public YhAlgorithm Algorithm { get; set; }
    public string Label { get; set; }
    public ushort Domains { get; set; }
    public YhCapabilities Capabilities { get; set; }
    public YhObjectOrigin Origin { get; set; }
    public uint Sequence { get; set; }
    public bool DelegatedCapabilities { get; set; }
    public bool Exportable { get; set; }
    public bool Importable { get; set; }
    public bool InCache { get; set; }
    public uint CreatedTime { get; set; }
    public uint LastUsedTime { get; set; }

    public override string ToString(); // Returns "[Type:0xID] Label"
}
```

### YhDeviceInfo

```csharp
public struct YhDeviceInfo
{
    public uint SerialNumber { get; set; }
    public string FirmwareVersion { get; set; }
    public ushort SessionsCurrent { get; set; }
    public ushort ObjectsMax { get; set; }
    public ushort ObjectsCurrent { get; set; }
    public YhCapabilities Capabilities { get; set; }
    public ushort Domains { get; set; }
    public bool FipsMode { get; set; }
    public bool ForceAuditLog { get; set; }
    public ushort AuditLogEntries { get; set; }

    public override string ToString(); // Returns "YubiHSM Serial:X Firmware:X FIPS:X"
}
```

### YhCapabilities

A type-safe bitmask for representing capability permissions.

```csharp
public struct YhCapabilities : IEquatable<YhCapabilities>
{
    // Constructors
    public YhCapabilities();
    public YhCapabilities(byte[] bytes);

    // Factory methods
    public static YhCapabilities From(params YhCapability[] capabilities);
    public static YhCapabilities FromBytes(byte[] bytes);
    public static YhCapabilities FromFlags(YhCapability flags);
    public static YhCapabilities FromStringArray(params string[] names);

    // Queries
    public bool Has(YhCapability capability);
    public YhCapability GetFlags();
    public string[] ToStringArray();
    public byte[] ToByteArray();

    // Mutations
    public void SetCapability(YhCapability capability);
    public void Clear(YhCapability capability);

    // Convenience properties
    public bool CanSignHmac { get; }
    public bool CanVerifyHmac { get; }
    public bool CanSignPkcs { get; }
    public bool CanSignPss { get; }
    public bool CanSignEcdsa { get; }
    public bool CanSignEddsa { get; }
    public bool CanDecryptOaep { get; }
    public bool CanDecryptPkcs { get; }
    public bool CanEcdhDerivation { get; }
    public bool CanExportWrapped { get; }
    public bool CanImportWrapped { get; }
    public bool CanGenerateAsymmetricKey { get; }
    public bool CanGenerateSymmetricKey { get; }
    public bool CanGenerateHmacKey { get; }
    public bool CanGetObject { get; }
    public bool CanListObjects { get; }
    public bool CanDeleteObject { get; }
    public bool CanGetOption { get; }
    public bool CanSetOption { get; }
    public bool CanGetPseudoRandom { get; }
    public bool CanEncryptAes { get; }
    public bool CanDecryptAes { get; }

    // Equality
    public override bool Equals(object? obj);
    public bool Equals(YhCapabilities other);
    public override int GetHashCode();
    public static bool operator ==(YhCapabilities left, YhCapabilities right);
    public static bool operator !=(YhCapabilities left, YhCapabilities right);
}
```

---

## Exception Types

### YubiHsmException

Base exception for all YubiHsmSharp errors.

```csharp
public class YubiHsmException : Exception
{
    public YubiHsmException(string message);
    public YubiHsmException(string message, Exception innerException);
}
```

### YubiHsmDeviceException

Exception for device-specific errors.

```csharp
public class YubiHsmDeviceException : YubiHsmException
{
    public YhReturnCode ErrorCode { get; }

    public YubiHsmDeviceException(YhReturnCode errorCode, string message);
}
```

---

## Capability System

### Understanding Capabilities

Capabilities represent permissions for operations on keys and authentication credentials. Each capability corresponds to a specific operation:

- **Signing Operations**: SignHmac, SignPkcs, SignPss, SignEcdsa, SignEddsa
- **Decryption Operations**: DecryptPkcs, DecryptOaep
- **Key Agreement**: EcdhDerivation
- **Key Wrapping**: ExportWrapped, ImportWrapped
- **Key Generation**: GenerateAsymmetricKey, GenerateSymmetricKey, GenerateHmacKey
- **Object Management**: GetObject, ListObjects, DeleteObject
- **Encryption**: EncryptAes, DecryptAes
- **Device Configuration**: GetOption, SetOption, GetPseudoRandom

### Working with Capabilities

```csharp
// Create capabilities with specific permissions
var signCapabilities = YhCapabilities.From(
    YhCapability.SignHmac,
    YhCapability.VerifyHmac);

// Check if a capability is present
if (capabilities.Has(YhCapability.SignHmac))
{
    // Safe to perform HMAC signing
}

// Use convenience properties
if (capabilities.CanSignEcdsa && capabilities.CanDecryptOaep)
{
    // Can perform ECDSA signing and RSA OAEP decryption
}

// Convert to/from strings (useful for config files)
var capStrings = capabilities.ToStringArray();  // ["sign-hmac", "verify-hmac"]
var parsed = YhCapabilities.FromStringArray(capStrings);

// Manipulate capabilities
capabilities.SetCapability(YhCapability.ExportWrapped);
capabilities.Clear(YhCapability.ListObjects);
```

---

## Usage Patterns

### Connection and Session Lifecycle

```csharp
// Using statement ensures cleanup
using var connector = YhConnector.Create("yhusb://");

try
{
    connector.Connect(timeout: 5000);
    
    using var session = connector.CreateSessionDerived(
        authKeyId: 1,
        password: "password");
    
    // Use session...
} // Session automatically closed and cleaned up here
finally
{
    connector.Disconnect();
} // Connector resources cleaned up here
```

### Error Handling

```csharp
try
{
    var signature = session.SignHmac(keyId, data);
}
catch (YubiHsmDeviceException ex) when (ex.ErrorCode == YhReturnCode.ObjectNotFound)
{
    Console.WriteLine($"Key {keyId} not found");
}
catch (YubiHsmDeviceException ex)
{
    Console.WriteLine($"Device error: {ex.ErrorCode}");
}
catch (YubiHsmException ex)
{
    Console.WriteLine($"HSM error: {ex.Message}");
}
```

### Cryptographic Operations

```csharp
// Generate a key
var keyId = session.GenerateHmacKey(
    keyId: 0xFFFF,  // Auto-generate ID
    label: "app-key",
    domains: 1,
    capabilities: YhCapabilities.From(
        YhCapability.SignHmac,
        YhCapability.VerifyHmac),
    algorithm: YhAlgorithm.HmacSha256);

// Sign data
var signature = session.SignHmac(keyId, dataToSign);

// Verify signature
if (session.VerifyHmac(keyId, signature, dataToSign))
{
    Console.WriteLine("Signature is valid");
}

// Cleanup
session.DeleteObject(keyId, YhObjectType.HmacKey);
```

### Device Information

```csharp
var deviceInfo = connector.GetDeviceInfo();

if (deviceInfo.FipsMode)
{
    Console.WriteLine("Device is in FIPS mode");
}

Console.WriteLine($"Firmware: {deviceInfo.FirmwareVersion}");
Console.WriteLine($"Storage: {deviceInfo.ObjectsCurrent}/{deviceInfo.ObjectsMax} objects");
Console.WriteLine($"Capabilities: {string.Join(", ", deviceInfo.Capabilities.ToStringArray())}");
```
