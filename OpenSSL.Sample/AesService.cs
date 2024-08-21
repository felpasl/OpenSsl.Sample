using System;
using System.Security.Cryptography;

public class AesService : IDisposable
{
    private readonly Aes _aes;
    private readonly ICryptoTransform _encryptor;
    private readonly ICryptoTransform _decryptor;

    public AesService(byte[] key, byte[] iv)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (iv == null) throw new ArgumentNullException(nameof(iv));

        _aes = Aes.Create();
        _aes.Key = key;
        _aes.IV = iv;

        _encryptor = _aes.CreateEncryptor();
        _decryptor = _aes.CreateDecryptor();
    }

    public byte[] Encrypt(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (data.Length == 0) return data;

        using var ms = new System.IO.MemoryStream();
        using var cs = new CryptoStream(ms, _encryptor, CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    public byte[] Decrypt(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (data.Length == 0) return data;

        using var ms = new System.IO.MemoryStream(data);
        using var cs = new CryptoStream(ms, _decryptor, CryptoStreamMode.Read);
        using var reader = new System.IO.MemoryStream();
        cs.CopyTo(reader);
        return reader.ToArray();
    }

    public void Dispose()
    {
        _aes.Dispose();
        _encryptor.Dispose();
        _decryptor.Dispose();
        GC.SuppressFinalize(this);
    }

    public static AesService Create(byte[] key, byte[] iv)
    {
        return new AesService(key, iv);
    }
}