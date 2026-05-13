namespace YubiHsmSharp;

/// <summary>
/// Represents YubiHSM object/key capabilities (permissions).
/// Wraps an 8-byte bitmask where each bit represents a capability.
/// See: https://docs.yubico.com/hardware/yubihsm-2/
/// </summary>
public struct YhCapabilities : IEquatable<YhCapabilities>
{
    /// <summary>
    /// Internal 8-byte capability bitmask.
    /// </summary>
    private byte[] _bytes;

    /// <summary>
    /// Initializes a new YhCapabilities struct with all bits set to zero.
    /// </summary>
    public YhCapabilities()
    {
        _bytes = new byte[8];
    }

    /// <summary>
    /// Initializes a new YhCapabilities struct from an 8-byte array.
    /// </summary>
    /// <param name="bytes">8-byte capability array (will be cloned).</param>
    /// <exception cref="ArgumentException">Thrown if bytes array is not exactly 8 bytes.</exception>
    public YhCapabilities(byte[] bytes)
    {
        if (bytes == null || bytes.Length != 8)
            throw new ArgumentException("Capabilities array must be exactly 8 bytes.", nameof(bytes));
        _bytes = (byte[])bytes.Clone();
    }

    /// <summary>
    /// Initializes a new YhCapabilities struct from a capability enum.
    /// </summary>
    /// <param name="capability">Single capability flag.</param>
    public YhCapabilities(YhCapability capability)
    {
        _bytes = new byte[8];
        SetCapability(capability);
    }

    /// <summary>
    /// Create YhCapabilities from an enumeration of YhCapability flags.
    /// </summary>
    /// <param name="capabilities">Flags to set.</param>
    /// <returns>New YhCapabilities instance.</returns>
    public static YhCapabilities From(params YhCapability[] capabilities)
    {
        var result = new YhCapabilities();
        foreach (var cap in capabilities)
        {
            result.SetCapability(cap);
        }
        return result;
    }

    /// <summary>
    /// Create YhCapabilities from a raw 8-byte array.
    /// </summary>
    /// <param name="bytes">8-byte array.</param>
    /// <returns>New YhCapabilities instance.</returns>
    /// <exception cref="ArgumentException">Thrown if bytes array is not exactly 8 bytes.</exception>
    public static YhCapabilities FromBytes(byte[] bytes)
    {
        return new YhCapabilities(bytes);
    }

    /// <summary>
    /// Create YhCapabilities from a capability enum (flags).
    /// </summary>
    /// <param name="flags">Capability flags.</param>
    /// <returns>New YhCapabilities instance.</returns>
    public static YhCapabilities FromFlags(YhCapability flags)
    {
        var result = new YhCapabilities();
        var bytes = result._bytes;
        ulong bitmask = (ulong)flags;
        for (int i = 0; i < 8; i++)
        {
            bytes[i] = (byte)((bitmask >> (i * 8)) & 0xFF);
        }
        result._bytes = bytes;
        return result;
    }

    /// <summary>
    /// Get the internal 8-byte capability array.
    /// </summary>
    /// <returns>Clone of the internal byte array.</returns>
    public byte[] ToByteArray() => (byte[])_bytes.Clone();

    /// <summary>
    /// Check if a specific capability is set.
    /// </summary>
    /// <param name="capability">Capability to check.</param>
    /// <returns>True if capability is set.</returns>
    public bool Has(YhCapability capability)
    {
        ulong bitmask = (ulong)capability;
        for (int i = 0; i < 8; i++)
        {
            byte shift = (byte)(i * 8);
            byte mask = (byte)((bitmask >> shift) & 0xFF);
            if (mask != 0 && (_bytes[i] & mask) != mask)
                return false;
        }
        return true;
    }

    /// <summary>
    /// Get all set capability flags as an enumeration.
    /// </summary>
    /// <returns>Bitmask of all set capabilities.</returns>
    public YhCapability GetFlags()
    {
        ulong result = 0;
        for (int i = 0; i < 8; i++)
        {
            result |= ((ulong)_bytes[i]) << (i * 8);
        }
        return (YhCapability)result;
    }

    /// <summary>
    /// Convert capabilities to an array of capability name strings.
    /// </summary>
    /// <returns>Array of capability names (e.g., ["sign-hmac", "verify-hmac"]).</returns>
    public string[] ToStringArray()
    {
        var flags = GetFlags();
        var names = new List<string>();

        foreach (YhCapability cap in Enum.GetValues(typeof(YhCapability)))
        {
            if (cap != YhCapability.None && cap != YhCapability.All && Has(cap))
            {
                // Convert enum name to capability string (e.g., SignHmac -> sign-hmac)
                var name = CapabilityNameConverter.EnumToString(cap);
                if (!string.IsNullOrEmpty(name))
                    names.Add(name);
            }
        }

        return names.ToArray();
    }

    /// <summary>
    /// Create capabilities from an array of capability name strings.
    /// </summary>
    /// <param name="capabilityNames">Array of capability names (e.g., ["sign-hmac", "verify-hmac"]).</param>
    /// <returns>New YhCapabilities instance.</returns>
    public static YhCapabilities FromStringArray(params string[] capabilityNames)
    {
        var result = new YhCapabilities();
        foreach (var name in capabilityNames)
        {
            var cap = CapabilityNameConverter.StringToEnum(name);
            if (cap.HasValue)
            {
                result.SetCapability(cap.Value);
            }
        }
        return result;
    }

    /// <summary>
    /// Set a specific capability bit.
    /// </summary>
    private void SetCapability(YhCapability capability)
    {
        ulong bitmask = (ulong)capability;
        for (int i = 0; i < 8; i++)
        {
            byte shift = (byte)(i * 8);
            byte mask = (byte)((bitmask >> shift) & 0xFF);
            _bytes[i] |= mask;
        }
    }

    /// <summary>
    /// Clear a specific capability bit.
    /// </summary>
    public void Clear(YhCapability capability)
    {
        ulong bitmask = (ulong)capability;
        for (int i = 0; i < 8; i++)
        {
            byte shift = (byte)(i * 8);
            byte mask = (byte)((bitmask >> shift) & 0xFF);
            _bytes[i] &= (byte)~mask;
        }
    }

    // Convenience helper properties for common capability checks
    /// <summary>
    /// Gets whether the HMAC sign capability is set.
    /// </summary>
    public bool CanSignHmac => Has(YhCapability.SignHmac);

    /// <summary>
    /// Gets whether the HMAC verify capability is set.
    /// </summary>
    public bool CanVerifyHmac => Has(YhCapability.VerifyHmac);

    /// <summary>
    /// Gets whether the RSA sign-PKCS capability is set.
    /// </summary>
    public bool CanSignPkcs => Has(YhCapability.SignPkcs);

    /// <summary>
    /// Gets whether the RSA sign-PSS capability is set.
    /// </summary>
    public bool CanSignPss => Has(YhCapability.SignPss);

    /// <summary>
    /// Gets whether the ECDSA sign capability is set.
    /// </summary>
    public bool CanSignEcdsa => Has(YhCapability.SignEcdsa);

    /// <summary>
    /// Gets whether the EdDSA sign capability is set.
    /// </summary>
    public bool CanSignEddsa => Has(YhCapability.SignEddsa);

    /// <summary>
    /// Gets whether the decrypt-OAEP capability is set.
    /// </summary>
    public bool CanDecryptOaep => Has(YhCapability.DecryptOaep);

    /// <summary>
    /// Gets whether the decrypt-PKCS capability is set.
    /// </summary>
    public bool CanDecryptPkcs => Has(YhCapability.DecryptPkcs);

    /// <summary>
    /// Gets whether the ECDH derivation capability is set.
    /// </summary>
    public bool CanEcdhDerivation => Has(YhCapability.EcdhDerivation);

    /// <summary>
    /// Gets whether the export-wrapped capability is set.
    /// </summary>
    public bool CanExportWrapped => Has(YhCapability.ExportWrapped);

    /// <summary>
    /// Gets whether the import-wrapped capability is set.
    /// </summary>
    public bool CanImportWrapped => Has(YhCapability.ImportWrapped);

    /// <summary>
    /// Gets whether the generate-asymmetric-key capability is set.
    /// </summary>
    public bool CanGenerateAsymmetricKey => Has(YhCapability.GenerateAsymmetricKey);

    /// <summary>
    /// Gets whether the generate-symmetric-key capability is set.
    /// </summary>
    public bool CanGenerateSymmetricKey => Has(YhCapability.GenerateSymmetricKey);

    /// <summary>
    /// Gets whether the generate-hmac-key capability is set.
    /// </summary>
    public bool CanGenerateHmacKey => Has(YhCapability.GenerateHmacKey);

    /// <summary>
    /// Gets whether the get-object capability is set.
    /// </summary>
    public bool CanGetObject => Has(YhCapability.GetObject);

    /// <summary>
    /// Gets whether the list-objects capability is set.
    /// </summary>
    public bool CanListObjects => Has(YhCapability.ListObjects);

    /// <summary>
    /// Gets whether the delete-object capability is set.
    /// </summary>
    public bool CanDeleteObject => Has(YhCapability.DeleteObject);

    /// <summary>
    /// Gets whether the get-option capability is set.
    /// </summary>
    public bool CanGetOption => Has(YhCapability.GetOption);

    /// <summary>
    /// Gets whether the set-option capability is set.
    /// </summary>
    public bool CanSetOption => Has(YhCapability.SetOption);

    /// <summary>
    /// Gets whether the get-pseudo-random capability is set.
    /// </summary>
    public bool CanGetPseudoRandom => Has(YhCapability.GetPseudoRandom);

    /// <summary>
    /// Gets whether the encrypt-aes capability is set.
    /// </summary>
    public bool CanEncryptAes => Has(YhCapability.EncryptAes);

    /// <summary>
    /// Gets whether the decrypt-aes capability is set.
    /// </summary>
    public bool CanDecryptAes => Has(YhCapability.DecryptAes);

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    public override bool Equals(object? obj) => obj is YhCapabilities other && Equals(other);

    /// <summary>
    /// Determines whether the specified YhCapabilities struct is equal to the current object.
    /// </summary>
    /// <param name="other">The YhCapabilities to compare with the current object.</param>
    /// <returns>True if equal; otherwise, false.</returns>
    public bool Equals(YhCapabilities other) => _bytes.SequenceEqual(other._bytes);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode() => _bytes.Aggregate(0, (acc, b) => acc ^ b.GetHashCode());

    /// <summary>
    /// Returns a string that represents the current object (comma-separated capability names).
    /// </summary>
    /// <returns>A string representation of the capabilities.</returns>
    public override string ToString() => string.Join(", ", ToStringArray());

    /// <summary>
    /// Determines whether two YhCapabilities instances are equal.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns>True if the instances are equal; otherwise, false.</returns>
    public static bool operator ==(YhCapabilities left, YhCapabilities right) => left.Equals(right);

    /// <summary>
    /// Determines whether two YhCapabilities instances are not equal.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns>True if the instances are not equal; otherwise, false.</returns>
    public static bool operator !=(YhCapabilities left, YhCapabilities right) => !(left == right);
}

/// <summary>
/// Helper for converting between capability enum values and string names.
/// </summary>
internal static class CapabilityNameConverter
{
    private static readonly Dictionary<YhCapability, string> EnumToStringMap = new()
    {
        { YhCapability.SignHmac, "sign-hmac" },
        { YhCapability.VerifyHmac, "verify-hmac" },
        { YhCapability.SignPkcs, "sign-pkcs" },
        { YhCapability.SignPss, "sign-pss" },
        { YhCapability.SignEcdsa, "sign-ecdsa" },
        { YhCapability.SignEddsa, "sign-eddsa" },
        { YhCapability.DecryptOaep, "decrypt-oaep" },
        { YhCapability.DecryptPkcs, "decrypt-pkcs" },
        { YhCapability.EcdhDerivation, "ecdh-derivation" },
        { YhCapability.ExportWrapped, "export-wrapped" },
        { YhCapability.ImportWrapped, "import-wrapped" },
        { YhCapability.PutAuthenticationKey, "put-authentication-key" },
        { YhCapability.PutAsymmetricKey, "put-asymmetric-key" },
        { YhCapability.GenerateAsymmetricKey, "generate-asymmetric-key" },
        { YhCapability.PutSymmetricKey, "put-symmetric-key" },
        { YhCapability.GenerateSymmetricKey, "generate-symmetric-key" },
        { YhCapability.PutHmacKey, "put-hmac-key" },
        { YhCapability.GenerateHmacKey, "generate-hmac-key" },
        { YhCapability.GetObject, "get-object" },
        { YhCapability.GetObjectInfo, "get-object-info" },
        { YhCapability.ListObjects, "list-objects" },
        { YhCapability.DeleteObject, "delete-object" },
        { YhCapability.GetOption, "get-option" },
        { YhCapability.SetOption, "set-option" },
        { YhCapability.GetPseudoRandom, "get-pseudo-random" },
        { YhCapability.GetAuditLog, "get-audit-log" },
        { YhCapability.CloseSession, "close-session" },
        { YhCapability.GetSessionInfo, "get-session-info" },
        { YhCapability.ResetDevice, "reset-device" },
        { YhCapability.ForceAuditLog, "force-audit-log" },
        { YhCapability.GetWrapped, "get-wrapped" },
        { YhCapability.PutWrapped, "put-wrapped" },
        { YhCapability.WrapWithKey, "wrap-with-key" },
        { YhCapability.PutOpaque, "put-opaque" },
        { YhCapability.GenerateOpaque, "generate-opaque" },
        { YhCapability.GetOtpAeadKey, "get-otp-aead-key" },
        { YhCapability.GenerateOtpAeadKey, "generate-otp-aead-key" },
        { YhCapability.DecryptAes, "decrypt-aes" },
        { YhCapability.EncryptAes, "encrypt-aes" },
        { YhCapability.CreateBackup, "create-backup" },
        { YhCapability.RestoreBackup, "restore-backup" },
        { YhCapability.VerifyLog, "verify-log" },
    };

    private static readonly Dictionary<string, YhCapability> StringToEnumMap =
        EnumToStringMap.ToDictionary(x => x.Value, x => x.Key, StringComparer.OrdinalIgnoreCase);

    public static string? EnumToString(YhCapability capability)
    {
        return EnumToStringMap.TryGetValue(capability, out var name) ? name : null;
    }

    public static YhCapability? StringToEnum(string capabilityName)
    {
        return StringToEnumMap.TryGetValue(capabilityName, out var capability) ? capability : null;
    }
}
