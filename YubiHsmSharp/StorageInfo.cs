namespace YubiHsmSharp;

/// <summary>
/// Information about the free storage of the device.
/// </summary>
/// <param name="TotalRecords">Total number of records.</param>
/// <param name="FreeRecords">Number of free records.</param>
/// <param name="TotalPages">Total number of pages.</param>
/// <param name="FreePages">Number of free pages.</param>
/// <param name="PageSize">Page size in bytes.</param>
public record class StorageInfo(ushort TotalRecords, ushort FreeRecords, ushort TotalPages, ushort FreePages, ushort PageSize);