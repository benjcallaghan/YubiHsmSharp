using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An ECDH key agreement that uses the ECDH mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// derive-ecdh
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiEcdh(YubiSession session) : IBasicAgreement
{
    private YubiECPrivateKeyParameters? privateKey;

    /// <inheritdoc />
    public BigInteger CalculateAgreement(ICipherParameters pubKey)
    {
        if (this.privateKey is null)
        {
            throw new InvalidOperationException("The cipher must be initialized with a private key before calculating an agreement.");
        }

        ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
        Span<byte> publicKey = stackalloc byte[pub.Q.GetEncodedLength(compressed: false)];
        pub.Q.EncodeTo(compressed: false, publicKey);

        Span<byte> sharedSecret = stackalloc byte[this.GetFieldSize()];
        int written = session.DeriveEcdh(this.privateKey.KeyId, publicKey, sharedSecret);
        sharedSecret = sharedSecret[..written];

        return new BigInteger(sign: 1, sharedSecret[..written]);
    }

    /// <inheritdoc />
    public int GetFieldSize() => privateKey?.Parameters.Curve.FieldElementEncodingLength ?? 0;

    /// <inheritdoc />
    public void Init(ICipherParameters parameters)
    {
        if (parameters is YubiECPrivateKeyParameters yubiKey)
        {
            this.privateKey = yubiKey;
        }
    }
}