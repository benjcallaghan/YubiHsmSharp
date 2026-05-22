using Org.BouncyCastle.Crypto;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// Extensions to <see cref="YubiSession"/> to perform PIN-related cryptographic operations.
/// </summary>
public static class YubiSessionExtensions
{
    extension(YubiSession session)
    {
        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored symmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored symmetric key.</param>
        /// <returns>A <see cref="YubiSymmetricKeyParameter"/> representing the stored symmetric key.</returns>
        public YubiSymmetricKeyParameter GetSymmetricKeyParameter(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.SymmetricKey);
            return new YubiSymmetricKeyParameter(keyId, descriptor.Length);
        }
    }
}