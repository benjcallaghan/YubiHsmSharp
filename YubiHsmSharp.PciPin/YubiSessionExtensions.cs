namespace YubiHsmSharp.PciPin;

/// <summary>
/// Extensions to <see cref="YubiSession"/> to perform PIN-related cryptographic operations.
/// </summary>
public static class YubiSessionExtensions
{
    extension(YubiSession session)
    {
        /// <summary>
        /// Imports a Zone Master Key (ZMK) into YubiHSM 2 as an Opaque object.
        /// </summary>
        /// <remarks>
        /// The authentication key used to open the session requires the following capabilities: put-opaque
        /// </remarks>
        /// <param name="utf8Label">The label of the opaque object, UTF-8 encoded and null-terminated.</param>
        /// <param name="domains">The domains where the opaque object will be operating within.</param>
        /// <param name="zoneMasterKey">The key to import.</param>
        /// <param name="keyId">The ID of the ZMK. 0 if the ID should be assigned by the device.</param>
        /// <returns>The ID of the imported key.</returns>
        public ushort ImportZoneMasterKey(ReadOnlySpan<byte> utf8Label, Domains domains, ReadOnlySpan<byte> zoneMasterKey, ushort keyId = 0)
        {
            // TODO: Currently assuming that YubiHSM supports none of the required algorithms.            
            return session.ImportOpaque(utf8Label, domains, new Capabilities(), Algorithm.Aes256, zoneMasterKey, keyId);
        }
    }
}