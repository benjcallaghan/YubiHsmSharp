namespace YubiHsmSharp;

/// <summary>
/// Represents YubiHSM object metadata.
/// Corresponds to yh_object_descriptor in the C library.
/// </summary>
public struct YhObjectInfo
{
    /// <summary>
    /// Object ID (0-65535).
    /// </summary>
    public ushort Id { get; init; }

    /// <summary>
    /// Object type.
    /// </summary>
    public YhObjectType Type { get; init; }

    /// <summary>
    /// Cryptographic algorithm (if applicable).
    /// </summary>
    public YhAlgorithm Algorithm { get; init; }

    /// <summary>
    /// Object label (up to 40 bytes).
    /// </summary>
    public string Label { get; init; }

    /// <summary>
    /// Domains the object belongs to (16-bit bitmask).
    /// </summary>
    public ushort Domains { get; init; }

    /// <summary>
    /// Object capabilities (64-bit bitmask).
    /// </summary>
    public YhCapabilities Capabilities { get; init; }

    /// <summary>
    /// Object origin (Generated, Imported, ImportedWrapped, etc.).
    /// </summary>
    public string Origin { get; init; }

    /// <summary>
    /// Object sequence number (incremented on modification).
    /// </summary>
    public uint Sequence { get; init; }

    /// <summary>
    /// Delegated capabilities flag.
    /// </summary>
    public bool DelegatedCapabilities { get; init; }

    /// <summary>
    /// Exportable flag.
    /// </summary>
    public bool Exportable { get; init; }

    /// <summary>
    /// Importable (wrapped) flag.
    /// </summary>
    public bool Importable { get; init; }

    /// <summary>
    /// In cache flag.
    /// </summary>
    public bool InCache { get; init; }

    /// <summary>
    /// Create time (Unix timestamp).
    /// </summary>
    public uint CreatedTime { get; init; }

    /// <summary>
    /// Last used time (Unix timestamp).
    /// </summary>
    public uint LastUsedTime { get; init; }

    public override string ToString() => $"[{Type}:0x{Id:X4}] {Label}";
}

/// <summary>
/// Represents YubiHSM device information.
/// </summary>
public struct YhDeviceInfo
{
    /// <summary>
    /// Device serial number.
    /// </summary>
    public uint SerialNumber { get; init; }

    /// <summary>
    /// Device firmware version (major.minor.patch).
    /// </summary>
    public string FirmwareVersion { get; init; }

    /// <summary>
    /// Maximum concurrent sessions (typically 16).
    /// </summary>
    public ushort SessionsCurrent { get; init; }

    /// <summary>
    /// Maximum object slots available.
    /// </summary>
    public ushort ObjectsMax { get; init; }

    /// <summary>
    /// Current object count.
    /// </summary>
    public ushort ObjectsCurrent { get; init; }

    /// <summary>
    /// Supported algorithms (capabilities).
    /// </summary>
    public YhCapabilities Capabilities { get; init; }

    /// <summary>
    /// Device domain configuration.
    /// </summary>
    public ushort Domains { get; init; }

    /// <summary>
    /// Whether device is in FIPS mode.
    /// </summary>
    public bool FipsMode { get; init; }

    /// <summary>
    /// Whether Force Audit Log is enabled.
    /// </summary>
    public bool ForceAuditLog { get; init; }

    /// <summary>
    /// Audit log entries (circular buffer, max 62).
    /// </summary>
    public ushort AuditLogEntries { get; init; }

    public override string ToString() =>
        $"YubiHSM Serial:{SerialNumber} Firmware:{FirmwareVersion} FIPS:{FipsMode}";
}
