using Xunit;
using YubiHsmSharp;

namespace YubiHsmSharp.Tests;

/// <summary>
/// Tests for YhCapabilities struct and capability management.
/// </summary>
public class CapabilitiesTests
{
    [Fact]
    public void Constructor_WithZeroBytes_CreatesEmptyCapabilities()
    {
        var caps = new YhCapabilities();
        // Default struct should have all bytes as zero
        Assert.Equal(new byte[8], caps.ToByteArray());
    }

    [Fact]
    public void From_MultipleCapabilities_SetsBits()
    {
        var caps = YhCapabilities.From(
            YhCapability.SignHmac,
            YhCapability.VerifyHmac);

        Assert.True(caps.CanSignHmac);
        Assert.True(caps.CanVerifyHmac);
        Assert.False(caps.CanSignPkcs);
    }

    [Fact]
    public void Has_ChecksIndividualBit()
    {
        var caps = YhCapabilities.From(YhCapability.SignHmac);
        
        Assert.True(caps.Has(YhCapability.SignHmac));
        Assert.False(caps.Has(YhCapability.VerifyHmac));
    }

    [Fact]
    public void ToByteArray_ReturnsEightBytes()
    {
        var caps = new YhCapabilities();
        var bytes = caps.ToByteArray();
        
        Assert.NotNull(bytes);
        Assert.Equal(8, bytes.Length);
    }

    [Fact]
    public void FromStringArray_ParsesCapabilityNames()
    {
        var caps = YhCapabilities.FromStringArray("sign-hmac", "verify-hmac");
        
        Assert.True(caps.CanSignHmac);
        Assert.True(caps.CanVerifyHmac);
    }

    [Fact]
    public void ToStringArray_ConvertsToNames()
    {
        var caps = YhCapabilities.From(
            YhCapability.SignHmac,
            YhCapability.VerifyHmac);

        var names = caps.ToStringArray();
        
        Assert.NotEmpty(names);
        Assert.Contains("sign-hmac", names);
        Assert.Contains("verify-hmac", names);
    }

    [Fact]
    public void Equality_ComparesByValue()
    {
        var caps1 = YhCapabilities.From(YhCapability.SignHmac);
        var caps2 = YhCapabilities.From(YhCapability.SignHmac);
        
        Assert.Equal(caps1, caps2);
        Assert.True(caps1 == caps2);
        Assert.False(caps1 != caps2);
    }

    [Fact]
    public void Clear_RemovesBit()
    {
        var caps = YhCapabilities.From(
            YhCapability.SignHmac,
            YhCapability.VerifyHmac);

        Assert.True(caps.CanSignHmac);
        
        caps.Clear(YhCapability.SignHmac);
        
        Assert.False(caps.CanSignHmac);
        Assert.True(caps.CanVerifyHmac);
    }

    [Fact]
    public void ToString_ReturnsCombinedNames()
    {
        var caps = YhCapabilities.From(YhCapability.SignHmac);
        var str = caps.ToString();
        
        Assert.NotEmpty(str);
        Assert.Contains("sign-hmac", str);
    }
}

/// <summary>
/// Tests for YhObjectInfo struct.
/// </summary>
public class ObjectInfoTests
{
    [Fact]
    public void ToString_FormatsCorrectly()
    {
        var info = new YhObjectInfo
        {
            Id = 0x0001,
            Type = YhObjectType.HmacKey,
            Label = "test-key"
        };

        var str = info.ToString();
        
        Assert.Contains("0x0001", str);
        Assert.Contains("HmacKey", str);
        Assert.Contains("test-key", str);
    }
}

/// <summary>
/// Tests for YhDeviceInfo struct.
/// </summary>
public class DeviceInfoTests
{
    [Fact]
    public void ToString_IncludesKeyInfo()
    {
        var info = new YhDeviceInfo
        {
            SerialNumber = 12345,
            FirmwareVersion = "2.4.2",
            FipsMode = true
        };

        var str = info.ToString();
        
        Assert.NotEmpty(str);
        Assert.Contains("12345", str);
        Assert.Contains("2.4.2", str);
        Assert.Contains("True", str);
    }
}

/// <summary>
/// Tests for exception types.
/// </summary>
public class ExceptionTests
{
    [Fact]
    public void YubiHsmException_HasMessage()
    {
        var ex = new YubiHsmException("Test error");
        Assert.Equal("Test error", ex.Message);
    }

    [Fact]
    public void YubiHsmDeviceException_StoresErrorCode()
    {
        var ex = new YubiHsmDeviceException(
            YhReturnCode.AuthenticationFailed,
            "Authentication failed");

        Assert.Equal(YhReturnCode.AuthenticationFailed, ex.ErrorCode);
        Assert.Equal("Authentication failed", ex.Message);
    }

    [Fact]
    public void YubiHsmDeviceException_InheritsFromYubiHsmException()
    {
        var ex = new YubiHsmDeviceException(
            YhReturnCode.ObjectNotFound,
            "Object not found");

        Assert.IsAssignableFrom<YubiHsmException>(ex);
    }
}

/// <summary>
/// Integration tests for connector and session (require YubiHSM device).
/// These tests are written but will be skipped if device is not available.
/// </summary>
public class ConnectorIntegrationTests
{
    private const string DeviceUrl = "yhusb://";
    private const ushort AuthKeyId = 1;
    private const string AuthPassword = "password";

    /// <summary>
    /// Test connector creation and cleanup.
    /// REQUIRES: YubiHSM device available.
    /// </summary>
    [Fact(Skip = "Requires YubiHSM device")]
    public void Create_ConnectsAndDisconnects()
    {
        using var connector = YhConnector.Create(DeviceUrl);
        Assert.NotNull(connector);
        Assert.False(connector.IsConnected);

        connector.Connect();
        Assert.True(connector.IsConnected);

        connector.Disconnect();
        Assert.False(connector.IsConnected);
    }

    /// <summary>
    /// Test device information retrieval.
    /// REQUIRES: YubiHSM device available.
    /// </summary>
    [Fact(Skip = "Requires YubiHSM device")]
    public void GetDeviceInfo_ReturnsValidData()
    {
        using var connector = YhConnector.Create(DeviceUrl);
        connector.Connect();

        var info = connector.GetDeviceInfo();
        
        Assert.True(info.SerialNumber > 0);
        Assert.NotEmpty(info.FirmwareVersion);
    }

    /// <summary>
    /// Test session creation and authentication.
    /// REQUIRES: YubiHSM device available with configured authentication key.
    /// </summary>
    [Fact(Skip = "Requires YubiHSM device with authentication key")]
    public void CreateSessionDerived_EstablishesSession()
    {
        using var connector = YhConnector.Create(DeviceUrl);
        connector.Connect();

        using var session = connector.CreateSessionDerived(AuthKeyId, AuthPassword);
        
        Assert.NotNull(session);
        Assert.True(session.IsValid);
        Assert.InRange(session.SessionId, 0, 15);
    }

    /// <summary>
    /// Test HMAC key generation and operations.
    /// REQUIRES: YubiHSM device with active session.
    /// </summary>
    [Fact(Skip = "Requires YubiHSM device with active session")]
    public void GenerateHmacKey_AndSign_Success()
    {
        using var connector = YhConnector.Create(DeviceUrl);
        connector.Connect();
        using var session = connector.CreateSessionDerived(AuthKeyId, AuthPassword);

        // Generate key
        var keyId = session.GenerateHmacKey(
            keyId: 0xFFFF,
            label: "test-hmac-key",
            domains: 1,
            capabilities: YhCapabilities.From(
                YhCapability.SignHmac,
                YhCapability.VerifyHmac),
            algorithm: YhAlgorithm.HmacSha256);

        Assert.NotEqual(0xFFFF, keyId);

        // Sign data
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = session.SignHmac(keyId, data);
        
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);

        // Verify signature
        var valid = session.VerifyHmac(keyId, signature, data);
        Assert.True(valid);

        // Cleanup
        session.DeleteObject(keyId, YhObjectType.HmacKey);
    }

    /// <summary>
    /// Test RSA key generation and signing.
    /// REQUIRES: YubiHSM device with active session.
    /// </summary>
    [Fact(Skip = "Requires YubiHSM device with active session")]
    public void GenerateAsymmetricKey_AndSign_Success()
    {
        using var connector = YhConnector.Create(DeviceUrl);
        connector.Connect();
        using var session = connector.CreateSessionDerived(AuthKeyId, AuthPassword);

        // Generate RSA key
        var keyId = session.GenerateAsymmetricKey(
            keyId: 0xFFFF,
            label: "test-rsa-key",
            domains: 1,
            capabilities: YhCapabilities.From(
                YhCapability.SignPkcs,
                YhCapability.GetObject),
            algorithm: YhAlgorithm.Rsa2048);

        Assert.NotEqual(0xFFFF, keyId);

        // Sign data
        var hashedData = new byte[32]; // SHA-256 hash
        var signature = session.SignPkcs(keyId, hashedData);
        
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);

        // Get public key
        session.GetPublicKey(keyId, out var pubKey, out var algo);
        
        Assert.NotNull(pubKey);
        Assert.NotEmpty(pubKey);
        Assert.Equal(YhAlgorithm.Rsa2048, algo);

        // Cleanup
        session.DeleteObject(keyId, YhObjectType.RsaPrivateKey);
    }

    /// <summary>
    /// Test AES encryption and decryption.
    /// REQUIRES: YubiHSM device with active session.
    /// </summary>
    [Fact(Skip = "Requires YubiHSM device with active session")]
    public void EncryptDecryptAes_RoundTrip_Success()
    {
        using var connector = YhConnector.Create(DeviceUrl);
        connector.Connect();
        using var session = connector.CreateSessionDerived(AuthKeyId, AuthPassword);

        // Generate AES key
        var keyId = session.GenerateSymmetricKey(
            keyId: 0xFFFF,
            label: "test-aes-key",
            domains: 1,
            capabilities: YhCapabilities.From(
                YhCapability.EncryptAes,
                YhCapability.DecryptAes),
            algorithm: YhAlgorithm.Aes256);

        // Test data
        var plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        // Encrypt
        var ciphertext = session.EncryptAes(keyId, plaintext);
        Assert.NotNull(ciphertext);
        Assert.NotEmpty(ciphertext);

        // Decrypt
        var decrypted = session.DecryptAes(keyId, ciphertext);
        
        Assert.NotNull(decrypted);
        Assert.Equal(plaintext, decrypted);

        // Cleanup
        session.DeleteObject(keyId, YhObjectType.BinaryKey);
    }
}
