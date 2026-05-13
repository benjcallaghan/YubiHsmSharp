# YubiHsmSharp Architecture Guide

## Overview

YubiHsmSharp is a comprehensive .NET wrapper for the YubiHSM 2 SDK (libyubihsm). The architecture is organized in layers, each with a specific responsibility and level of abstraction.

## Architecture Layers

```
┌─────────────────────────────────────────────────┐
│         Public API Layer (C#/.NET)              │
│  ┌──────────────────┐      ┌─────────────────┐  │
│  │   YhConnector    │      │    YhSession    │  │
│  │  (Connection &   │      │  (Cryptography  │  │
│  │  Device Ops)     │      │   & Key Mgmt)   │  │
│  └──────────────────┘      └─────────────────┘  │
├─────────────────────────────────────────────────┤
│      Supporting Types & Utilities               │
│  ┌──────────────────────────────────────────┐   │
│  │ Types.cs (ObjectInfo, DeviceInfo)        │   │
│  │ Enums.cs (Algorithm, Capability, etc.)   │   │
│  │ Capabilities.cs (Type-safe bitmask)      │   │
│  │ Exceptions.cs (Error types)              │   │
│  │ ErrorHandler.cs (Error translation)      │   │
│  └──────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤
│    P/Invoke Layer (Native Interop)              │
│  ┌──────────────────────────────────────────┐   │
│  │      NativeMethods.cs                    │   │
│  │   (~100+ extern function declarations)   │   │
│  └──────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤
│         Native Library (C/C++)                  │
│  ┌──────────────────────────────────────────┐   │
│  │         libyubihsm (shared library)      │   │
│  │    (Win: libyubihsm.dll, Unix: .so)      │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Core Components

### 1. Public API Layer

#### YhConnector
**Purpose**: Manages device connection lifecycle and device-level operations

**Responsibilities:**
- Establish/terminate connection to YubiHSM device
- Query device properties (firmware, serial, storage)
- Enumerate objects on device
- Create authenticated sessions

**Key Methods:**
```csharp
// Factory & lifecycle
Create(string url)
Connect(int timeout)
Disconnect()

// Device queries (no auth required)
GetDeviceInfo()
ListObjects()

// Session creation
CreateSessionDerived(keyId, password)
CreateSessionSymmetric(keyId, encKey, macKey)
BeginCreateSessionAsymmetric(keyId)
FinishCreateSessionAsymmetric(...)
```

#### YhSession
**Purpose**: Represents authenticated session for cryptographic operations

**Responsibilities:**
- Perform all cryptographic operations (sign, verify, encrypt, decrypt)
- Manage key lifecycle (generate, import, export, delete)
- Execute HMAC, RSA, EC, AES, EdDSA operations
- Handle key wrapping/unwrapping

**Key Methods:**
```csharp
// Key operations
GenerateHmacKey(...)
GenerateAsymmetricKey(...)
ImportSymmetricKey(...)
DeleteObject(...)

// Crypto operations
SignHmac(keyId, data)
SignPkcs(keyId, data)
SignEcdsa(keyId, data)
DecryptOaep(keyId, ciphertext)
EncryptAes(keyId, plaintext)

// Key wrapping
ExportWrappedKey(wrapId, type, objectId)
ImportWrappedKey(wrapId, wrapped)
```

### 2. Supporting Types Layer

#### Enums.cs
Comprehensive enum definitions for all named constants from the C library:

- **YhObjectType**: Key types (HMAC, RSA, EC, symmetric, etc.)
- **YhAlgorithm**: Supported algorithms (HMAC-SHA*, RSA*, EC curves, AES, EdDSA, etc.)
- **YhCapability**: Permission flags (~45 individual capabilities)
- **YhReturnCode**: Return/error codes
- **YhCommand**: Device commands
- **YhOption**: Device configuration options
- **YhConnectorOption**: Connection configuration

#### Types.cs
C#-idiomatic types representing device state:

- **YhObjectInfo**: Metadata about an object (id, type, algorithm, label, capabilities, timestamps)
- **YhDeviceInfo**: Device properties (serial, firmware, FIPS mode, storage info)

#### Capabilities.cs
Type-safe bitmask for 45+ permission capabilities:

```csharp
public struct YhCapabilities : IEquatable<YhCapabilities>
{
    // Core operations
    public bool Has(YhCapability cap);
    public void SetCapability(YhCapability cap);
    public void Clear(YhCapability cap);
    
    // Conversions
    public byte[] ToByteArray();
    public string[] ToStringArray();
    
    // Convenience properties
    public bool CanSignHmac { get; }
    public bool CanVerifyHmac { get; }
    public bool CanDecryptOaep { get; }
    // ... 22+ more convenience properties
}
```

Internal `CapabilityNameConverter` provides bidirectional mapping:
- Enum ↔ String conversions
- Used by ToStringArray() and FromStringArray()

#### Exceptions.cs
Exception hierarchy:

```csharp
YubiHsmException                    // Base exception
├── YubiHsmDeviceException          // Device-specific errors
    └── ErrorCode: YhReturnCode
```

Error translation via `ErrorHandler.ThrowIfError()`:
- Negative return codes → YubiHsmException
- Device errors (0x00-0x12) → YubiHsmDeviceException
- Success → no exception

#### ErrorHandler.cs
Centralized error handling:

```csharp
public static void ThrowIfError(YhReturnCode rc, string context = "")
{
    if (rc != YhReturnCode.Success)
    {
        string msg = GetErrorMessage(rc, context);
        if (IsDeviceError(rc))
            throw new YubiHsmDeviceException(rc, msg);
        else
            throw new YubiHsmException(msg);
    }
}
```

### 3. P/Invoke Layer

#### NativeMethods.cs
Raw P/Invoke declarations for ~100+ libyubihsm functions:

**Organization by Functional Category:**

- **Lifecycle**: yh_init, yh_exit
- **Connector Management**: yh_init_connector, yh_connect, yh_disconnect, yh_connector_free
- **Session Management**: yh_create_session_*, yh_destroy_session, yh_get_session_id
- **Device Operations**: yh_util_get_device_info_ex, yh_util_get_storage_info, yh_util_reset_device
- **Object Operations**: yh_list_objects, yh_util_get_object_info, yh_util_delete_object
- **Key Generation**: yh_util_generate_*_key, yh_util_import_*_key
- **Cryptographic**: yh_util_sign_*, yh_util_decrypt_*, yh_util_encrypt_*, etc.
- **Key Wrapping**: yh_util_export_wrapped, yh_util_import_wrapped
- **Configuration**: yh_util_get_option, yh_util_set_option, yh_util_get_pseudo_random
- **Raw Commands**: yh_send_secure_msg, yh_send_plain_msg
- **String Conversion**: yh_algorithm_to_string, yh_capabilities_to_strings, yh_strerror, etc.

**Signature Pattern:**
```csharp
[DllImport("libyubihsm", CallingConvention = CallingConvention.Cdecl)]
internal static extern YhReturnCode yh_function_name(
    IntPtr handle,
    [In] byte[] inData,
    ushort inLen,
    [Out] byte[] outData,
    ref ushort outLen);
```

---

## Design Patterns

### 1. Resource Management (IDisposable)

**YhConnector**:
```csharp
using var connector = YhConnector.Create();
connector.Connect();
// Cleanup: calls Disconnect() and yh_connector_free()
```

**YhSession**:
```csharp
using var session = connector.CreateSessionDerived(...);
// Cleanup: calls yh_util_close_session() or yh_destroy_session()
```

Both implement proper IDisposable pattern:
- Dispose(bool disposing) for clean shutdown
- Finalizer (~YhSession, ~YhConnector) as safety net
- Check IsDisposed flag before operations

### 2. Error Handling (Exception-Based)

**Instead of checking return codes:**
```csharp
// ❌ C-style (verbose)
var rc = yh_util_sign_hmac(...);
if (rc != YhReturnCode.Success)
    return HandleError(rc);

// ✅ C#-style (idiomatic)
try {
    var sig = session.SignHmac(keyId, data);
} catch (YubiHsmDeviceException ex) {
    // Handle device error
}
```

### 3. Factory Methods

**YhConnector.Create()** instead of constructor:
```csharp
// Calls yh_init() and yh_init_connector()
using var connector = YhConnector.Create("yhusb://");
```

Enables proper initialization sequencing and error handling.

### 4. Type-Safe Capabilities

**Bitmask with convenience properties:**
```csharp
// Instead of: uint caps = 0x0000000000000003
var caps = YhCapabilities.From(
    YhCapability.SignHmac,
    YhCapability.VerifyHmac);

// Instead of: if ((caps & 0x0000000000000001) != 0)
if (caps.CanSignHmac)
    // Can perform signing
```

---

## Data Flow Examples

### Example 1: Basic HMAC Signing

```
User Code
    ↓
session.SignHmac(keyId, data)
    ↓ (YhSession.cs)
ErrorHandler.ThrowIfError(...)
    ↓ (ErrorHandler.cs)
NativeMethods.yh_util_sign_hmac(...)
    ↓ (NativeMethods.cs)
[DllImport] → libyubihsm
    ↓ (Native code)
YubiHSM Device
    ↓ (Hardware)
Signature (byte[])
```

### Example 2: Session Creation with Error Handling

```
User Code
    ↓
connector.CreateSessionDerived(authKeyId, password)
    ↓ (YhConnector.cs)
NativeMethods.yh_create_session_derived(...)
    ↓ (P/Invoke)
[Device Error] → return YhReturnCode
    ↓
ErrorHandler.ThrowIfError() recognizes device error
    ↓
throw new YubiHsmDeviceException(errorCode, message)
    ↓
Caller's catch block handles specific error
```

---

## Extension Points

### Adding New Functionality

To add support for a new operation:

1. **Define P/Invoke**: Add to `NativeMethods.cs`
   ```csharp
   [DllImport("libyubihsm", CallingConvention = CallingConvention.Cdecl)]
   internal static extern YhReturnCode yh_util_new_operation(...);
   ```

2. **Add Wrapper Method**: In `YhSession` or `YhConnector`
   ```csharp
   public void NewOperation(...)
   {
       var rc = NativeMethods.yh_util_new_operation(...);
       ErrorHandler.ThrowIfError(rc, "New operation failed");
   }
   ```

3. **Add Enum/Type Support**: Update `Enums.cs` or `Types.cs` if needed

4. **Add Tests**: Create test cases in `YubiHsmSharp.Tests`

5. **Update Documentation**: Add doc comments and update API_REFERENCE.md

### Adding New Capabilities

To support a new permission capability:

1. **Define Enum Value**: In `YhCapability` enum in `Enums.cs`
   ```csharp
   NewCapability = 0x0000000001000000,
   ```

2. **Add Convenience Property**: In `YhCapabilities` struct
   ```csharp
   public bool CanPerformNewOp => Has(YhCapability.NewCapability);
   ```

3. **Update Converter**: In `CapabilityNameConverter`
   ```csharp
   { YhCapability.NewCapability, "perform-new-op" }
   ```

---

## Performance Considerations

1. **P/Invoke Overhead**: Minimal, called only for device operations
2. **Memory Marshaling**: Controlled, fixed-size buffers used where possible
3. **Session Reuse**: Create once, reuse for multiple operations
4. **Capability Caching**: YhCapabilities struct is value type, efficient to copy

---

## Testing Strategy

**Unit Tests** (YubiHsmSharp.Tests):
- Capability struct operations (parsing, conversion, bitwise ops)
- Type conversions and serialization
- Exception mapping
- No device required

**Integration Tests** (marked Skip, require device):
- Connection/disconnection lifecycle
- Session creation (derived, symmetric, asymmetric)
- Key generation and usage
- HMAC, RSA, EC, AES operations
- Device reset and configuration

---

## Security Considerations

1. **Password Handling**: Passed as string to session creation (consider secure string in production)
2. **Key Material**: Kept in memory as byte[], consider clearing after use
3. **Session Keys**: Automatically closed/destroyed via IDisposable
4. **Error Messages**: Include context but avoid sensitive data exposure
5. **Device Reset**: Explicit warning in documentation

---

## Future Architectural Enhancements

1. **Async Wrapper Layer**: Add Async variants of core methods
2. **Session Pooling**: Connection pool and session reuse
3. **Custom Native Library Loading**: RID-specific paths
4. **Strong Type Wrappers**: Dedicated types for EncryptionKey, MacKey, etc.
5. **Operation Batching**: Send multiple commands in single session

---

This architecture provides a clean, idiomatic C# API while maintaining full compatibility with the native libyubihsm library.
