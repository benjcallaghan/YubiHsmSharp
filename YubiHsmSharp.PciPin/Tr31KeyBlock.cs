using System.Text;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Represents a TR-31 Key Block, with header fields parsed and verified.
/// </summary>
public record class Tr31KeyBlock
{
    /// <summary>
    /// Gets the Key Block Version ID, which defines the method by which it is cryptographically protected.
    /// </summary>
    public required string KeyBlockVersionId { get; init; }

    /// <summary>
    /// Gets the key-block length, including the header, encrypted data, and MAC.
    /// </summary>
    public required int KeyBlockLength { get; init; }

    /// <summary>
    /// Gets information about the intended function of the protected key.
    /// </summary>
    public required string KeyUsage { get; init; }

    /// <summary>
    /// Gets the approved algorithm for which the protected key may be used.
    /// </summary>
    public required string Algorithm { get; init; }

    /// <summary>
    /// Gets the operation the protected key can perform.
    /// </summary>
    public required string ModeOfUse { get; init; }

    /// <summary>
    /// Gets the version number of the protected key.
    /// </summary>
    public required int KeyVersionNumber { get; init; }

    /// <summary>
    /// Gets whether the key may be transferred outside the cryptographic domain.
    /// </summary>
    public required string Exportability { get; init; }

    /// <summary>
    /// Gets the number of optional blocks included in the key block.
    /// </summary>
    public required int NumberOfOptionalBlocks { get; init; }

    /// <summary>
    /// Gets whether the key is in a key exchange context or in a storage context.
    /// </summary>
    public required string KeyContext { get; init; }

    /// <summary>
    /// Gets the protected key, still encrypted under the Key Block Protection Key (KBPK) or Zone Master Key (ZMK).
    /// </summary>
    public required byte[] EncryptedKey { get; init; }

    /// <summary>
    /// Gets the Message Authenticatino Code (MAC) which encompasses the header and encrypted key data.
    /// </summary>
    public required byte[] Authentication { get; init; }

    /// <summary>
    /// Parses key block header data and captures encrypted key data and authentication codes.
    /// </summary>
    /// <param name="keyBlock">The key block to parse</param>
    /// <returns>The parsed key block data.</returns>
    /// <exception cref="ArgumentException">Thrown when the encoded length does not match the actual length of the key block.</exception>
    public static Tr31KeyBlock From(ReadOnlySpan<byte> keyBlock)
    {
        string versionId = Encoding.ASCII.GetString(keyBlock[0..1]);
        if (versionId != "D")
        {
            throw new NotImplementedException("Only Version D has been implemented so far.");
        }

        int keyBlockLength = Int32.Parse(keyBlock[1..5]);
        if (keyBlockLength != keyBlock.Length)
        {
            throw new ArgumentException($"The encoded key block length ({keyBlockLength}) does not match the actual length of the key block ({keyBlock.Length}).", nameof(keyBlock));
        }

        int optionalBlocks = Int32.Parse(keyBlock[12..14]);
        if (optionalBlocks != 0)
        {
            throw new NotImplementedException("Optional blocks are not yet implemented.");
        }

        // TODO: Infer from Version ID
        int macSize = 16 * 2; // Size in hex characters
        return new Tr31KeyBlock()
        {
            KeyBlockVersionId = versionId,
            KeyBlockLength = keyBlockLength,
            KeyUsage = Encoding.ASCII.GetString(keyBlock[5..7]),
            Algorithm = Encoding.ASCII.GetString(keyBlock[7..8]),
            ModeOfUse = Encoding.ASCII.GetString(keyBlock[8..9]),
            KeyVersionNumber = Int32.Parse(keyBlock[9..11]),
            Exportability = Encoding.ASCII.GetString(keyBlock[11..12]),
            NumberOfOptionalBlocks = optionalBlocks,
            KeyContext = Encoding.ASCII.GetString(keyBlock[14..16]),
            EncryptedKey = keyBlock[16..^macSize].ToArray(),
            Authentication = keyBlock[^macSize..].ToArray(),
        };
    }
}