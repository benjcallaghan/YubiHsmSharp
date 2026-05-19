using System.Text;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Represents a TR-31 Key Block, with header fields parsed and verified.
/// </summary>
public struct Tr31KeyBlock
{
    private readonly byte[] keyBlock;

    /// <summary>
    /// Parses key block header data and captures encrypted key data and authentication codes.
    /// </summary>
    /// <remarks>
    /// The full data of <paramref name="keyBlock"/> is copied into the newly constructed object.
    /// </remarks>
    /// <param name="keyBlock">The key block to parse</param>
    /// <exception cref="ArgumentException">Thrown when the encoded length does not match the actual length of the key block.</exception>
    public Tr31KeyBlock(ReadOnlySpan<byte> keyBlock)
    {
        this.keyBlock = keyBlock.ToArray();
        if (this.KeyBlockLength != keyBlock.Length)
        {
            throw new ArgumentException($"The encoded key block length ({this.KeyBlockLength}) does not match the actual length of the key block ({keyBlock.Length}).", nameof(keyBlock));
        }
    }

    /// <summary>
    /// Gets the Key Block Version ID, which defines the method by which it is cryptographically protected.
    /// </summary>
    public readonly string KeyBlockVersionId => Encoding.ASCII.GetString(this.keyBlock[0..1]);

    /// <summary>
    /// Gets the key-block length, including the header, encrypted data, and MAC.
    /// </summary>
    public readonly int KeyBlockLength => Int32.Parse(this.keyBlock[1..5]);

    /// <summary>
    /// Gets information about the intended function of the protected key.
    /// </summary>
    public readonly string KeyUsage => Encoding.ASCII.GetString(this.keyBlock[5..7]);

    /// <summary>
    /// Gets the approved algorithm for which the protected key may be used.
    /// </summary>
    public readonly string Algorithm => Encoding.ASCII.GetString(this.keyBlock[7..8]);

    /// <summary>
    /// Gets the operation the protected key can perform.
    /// </summary>
    public readonly string ModeOfUse => Encoding.ASCII.GetString(this.keyBlock[8..9]);

    /// <summary>
    /// Gets the version number of the protected key.
    /// </summary>
    public readonly int KeyVersionNumber => Int32.Parse(this.keyBlock[9..11]);

    /// <summary>
    /// Gets whether the key may be transferred outside the cryptographic domain.
    /// </summary>
    public readonly string Exportability => Encoding.ASCII.GetString(this.keyBlock[11..12]);

    /// <summary>
    /// Gets the number of optional blocks included in the key block.
    /// </summary>
    public readonly int NumberOfOptionalBlocks => Int32.Parse(this.keyBlock[12..14]);

    /// <summary>
    /// Gets whether the key is in a key exchange context or in a storage context.
    /// </summary>
    public readonly string KeyContext => Encoding.ASCII.GetString(this.keyBlock[14..16]);
}