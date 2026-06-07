using System.Diagnostics;

namespace YubiHsmSharp;

/// <summary>
/// Represents the YubiHSM module. This class should be instantiated once per application,
/// and should be disposed when the application is finished using the module.
/// </summary>
public sealed class YubiModule : IDisposable
{
    /// <summary>
    /// Initializes the YubiHSM module.
    /// </summary>
    public YubiModule()
    {
        yh_rc err = yh_init();
        YubiHsmException.ThrowIfError(err);
        this.Handle = new SafeModuleHandle();
    }

    internal SafeModuleHandle Handle { get; }

    /// <summary>
    /// Initializes a connection to a YubiHSM device using the specified URL.
    /// </summary>
    /// <param name="utf8Url">The URL associated with this connector, encoded as UTF-8 and null-terminated.</param>
    /// <returns>A <see cref="YubiConnector"/> configured with the provided URL.</returns>
    public YubiConnector InitConnector(ReadOnlySpan<byte> utf8Url)
    {
        Debug.Assert(this.Handle != null, "YubiModule must be initialized before initializing a connector.");

        yh_rc err = yh_init_connector(utf8Url, out SafeConnectorHandle handle);
        YubiHsmException.ThrowIfError(err);
        return new YubiConnector(this, handle);
    }

    /// <summary>
    /// Derives an ec-p256 key pair from the given password.
    /// </summary>
    /// <remarks>
    /// 1. Apply pkcs5_pbkdf2_hmac-sha256 on the password to derive a pseudo-random private ec-p256 key.
    /// 2. Check that the derived key is a valid ec-p256 private key.
    /// 3. If not valid append a byte with the value 1 (2, 3, 4 etc for additional failures) to the password and repeat from step 1.
    /// 4. Calculate the corresponding public key from the private key and the ec-p256 curve parameters.
    /// </remarks>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="privateKey">The buffer to store the derived private key.</param>
    /// <param name="publicKey">The buffer to store the derived public key.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="privateKey"/> or <paramref name="publicKey"/> is too small.</exception>
    public void DeriveECP256Key(ReadOnlySpan<byte> password, Span<byte> privateKey, Span<byte> publicKey)
    {
        if (privateKey.Length < YH_EC_P256_PRIVKEY_LEN)
            throw new ArgumentException($"Private key buffer must be at least {YH_EC_P256_PRIVKEY_LEN} bytes long.", nameof(privateKey));
        if (publicKey.Length < YH_EC_P256_PUBKEY_LEN)
            throw new ArgumentException($"Public key buffer must be at least {YH_EC_P256_PUBKEY_LEN} bytes long.", nameof(publicKey));

        bool added = false;
        try
        {
            this.Handle.DangerousAddRef(ref added);
            yh_rc err = yh_util_derive_ec_p256_key(password, (nuint)password.Length,
                privateKey, (nuint)privateKey.Length,
                publicKey, (nuint)publicKey.Length);
            YubiHsmException.ThrowIfError(err);
        }
        finally
        {
            if (added)
            {
                this.Handle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Generates a random ec-p256 key pair.
    /// </summary>
    /// <param name="privateKey">The buffer to store the generated private key.</param>
    /// <param name="publicKey">The buffer to store the generated public key.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="privateKey"/> or <paramref name="publicKey"/> is too small.</exception>
    public void GenerateECP256Key(Span<byte> privateKey, Span<byte> publicKey)
    {
        if (privateKey.Length < YH_EC_P256_PRIVKEY_LEN)
            throw new ArgumentException($"Private key buffer must be at least {YH_EC_P256_PRIVKEY_LEN} bytes long.", nameof(privateKey));
        if (publicKey.Length < YH_EC_P256_PUBKEY_LEN)
            throw new ArgumentException($"Public key buffer must be at least {YH_EC_P256_PUBKEY_LEN} bytes long.", nameof(publicKey));

        bool added = false;
        try
        {
            this.Handle.DangerousAddRef(ref added);
            yh_rc err = yh_util_generate_ec_p256_key(
                privateKey, (nuint)privateKey.Length,
                publicKey, (nuint)publicKey.Length);
            YubiHsmException.ThrowIfError(err);
        }
        finally
        {
            if (added)
            {
                this.Handle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Pads data using PKCS #7 padding.
    /// </summary>
    /// <param name="data">Data to be padded. The buffer must be oversized to accommodate the padding.</param>
    /// <param name="currentLength">The current length of the data.</param>
    /// <param name="blockSize">The block size for padding.</param>
    /// <returns>The length of the padded data.</returns>
    public int PadPkcs7(Span<byte> data, int currentLength, byte blockSize)
    {
        bool added = false;
        try
        {
            this.Handle.DangerousAddRef(ref added);
            nuint length = (nuint)currentLength;
            yh_rc err = yh_util_pad_pkcs7(data, ref length, (nuint)data.Length, blockSize);
            return (int)length;
        }
        finally
        {
            if (added)
            {
                this.Handle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Unpad data that has PKCS #7 padding.
    /// </summary>
    /// <remarks>
    /// Unpadding unauthenticated ciphertext provides a padding oracle.
    /// </remarks>
    /// <param name="data">Data to be unpadded.</param>
    /// <param name="blockSize">The block size for unpadding.</param>
    /// <returns>The length of the un padded data.</returns>
    public int UnpadPkcs7(Span<byte> data, byte blockSize)
    {
        bool added = false;
        try
        {
            this.Handle.DangerousAddRef(ref added);
            nuint length = (nuint)data.Length;
            yh_rc err = yh_util_unpad_pkcs7(data, ref length, blockSize);
            YubiHsmException.ThrowIfError(err);
            return (int)length;
        }
        finally
        {
            if (added)
            {
                this.Handle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Cleans up the YubiHSM module.
    /// </summary>
    public void Dispose()
    {
        this.Handle.Dispose();
    }
}

// There is never an actual handle here. We're just relying on the cleanup of SafeHandle.
// Because this handle is never passed to P/Invoke methods, reference counting is handled manually.
internal class SafeModuleHandle : SafeHandle
{
    public SafeModuleHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => false;

    protected override bool ReleaseHandle()
    {
        yh_rc err = yh_exit();
        return err == yh_rc.YHR_SUCCESS;
    }
}