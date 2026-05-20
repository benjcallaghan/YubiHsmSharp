namespace YubiHsmSharp.PciPin.Tests;

public class UnitTest1
{
    [Theory]
    [InlineData("1234567890ABCDEFFEDCBA0987654321", "3F077B")]
    [InlineData("00112233445566778899AABBCCDDEEFF", "53E107")]
    [InlineData("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF", "0C1589")]
    [InlineData("0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF", "F66591")]
    public void AesKeyCheckValue_WithValidKey_ProducesValidCheckValue(string hexKey, string hexCheckValue)
    {
        // Arrange
        byte[] key = Convert.FromHexString(hexKey);

        // Act
        Span<byte> keyCheckValue = stackalloc byte[3];
        int written = KeyUtils.AesKeyCheckValue(key, keyCheckValue);
        keyCheckValue = keyCheckValue[..written];

        // Assert
        byte[] checkValue = Convert.FromHexString(hexCheckValue);
        Assert.Equal(checkValue, keyCheckValue);
    }
}
