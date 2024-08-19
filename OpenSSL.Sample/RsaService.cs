

using System.Security.Cryptography;

public class RsaService : System.IDisposable
{
public delegate int TransformBlockCall(System.ReadOnlySpan<byte> data, System.Span<byte> destination);

private readonly RSA _encoder;
private readonly RSAEncryptionPadding _padding;

private readonly TransformBlockCall _encryptBlockCall;
private readonly TransformBlockCall _decryptBlockCall;

private int _encrypt_InputBlockSize;
private int _encrypt_OutputBlockSize;
private int _decrypt_InputBlockSize;
private int _decrypt_OutputBlockSize;

public RsaService(RSA encoder) {
    if(encoder == null)
        throw new System.ArgumentNullException(nameof(encoder));
    _encoder = encoder;

    _padding = RSAEncryptionPadding.Pkcs1;

    _encryptBlockCall = new TransformBlockCall(EncryptBlock);
    _decryptBlockCall = new TransformBlockCall(DecryptBlock);

    OnEndSetParameters();
}

private void OnEndSetParameters() {
    _encrypt_InputBlockSize = GetSizeOutputEncryptOfKeySize(_encoder.KeySize);
    _encrypt_OutputBlockSize = _encoder.KeySize / 8;
    _decrypt_InputBlockSize = _encrypt_OutputBlockSize;
    _decrypt_OutputBlockSize = _encrypt_OutputBlockSize;
}

public void ImportParameters(RSAParameters parameters) {
    _encoder.ImportParameters(parameters);
    OnEndSetParameters();
}

public byte[] Encrypt(byte[] data) {
    if(data == null) throw new System.ArgumentNullException(nameof(data));
    if(data.Length == 0) return data;
    int outputLength = GetEncryptOutputMaxByteCount(data.Length);
    byte[] outputData = new byte[outputLength];
    Encrypt(data, outputData);
    return outputData;
}


public byte[] Decrypt(byte[] data) {
    if(data == null) throw new System.ArgumentNullException(nameof(data));
    if(data.Length == 0) return data;
    int maxOutputLength = GetDecryptOutputMaxByteCount(data.Length);
    byte[] outputData = new byte[maxOutputLength];
    int actual_OutputLength = Decrypt(data, outputData);
    if(maxOutputLength > actual_OutputLength)
        System.Array.Resize(ref outputData, actual_OutputLength);
    return outputData;
}

public int Encrypt(System.ReadOnlySpan<byte> data, System.Span<byte> destination) {
#if DEBUG
    int inputBlockSize = _encrypt_InputBlockSize;
    int outputBlockSize = _encoder.KeySize / 8;
    int blockCount = (data.Length / inputBlockSize);
    if(data.Length % inputBlockSize != 0)
        blockCount++;
    System.Diagnostics.Debug.Assert((blockCount * outputBlockSize) <= destination.Length);
#endif

    if(data.Length > _encrypt_InputBlockSize)
        return TransformFinal(_encryptBlockCall, data, destination, _encrypt_InputBlockSize);
    else
        return _encryptBlockCall(data, destination);
}


public int Decrypt(System.ReadOnlySpan<byte> data, System.Span<byte> destination) {
    if(data.Length > _decrypt_InputBlockSize)
        return TransformFinal(_decryptBlockCall, data, destination, _decrypt_InputBlockSize);
    else
        return _decryptBlockCall(data, destination);
}

private int EncryptBlock(System.ReadOnlySpan<byte> data, System.Span<byte> destination) => _encoder.Encrypt(data, destination, _padding);
private int DecryptBlock(System.ReadOnlySpan<byte> data, System.Span<byte> destination) => _encoder.Decrypt(data, destination, _padding);

public int GetEncryptOutputMaxByteCount(int inputCount) => GetBlockCount(inputCount, _encrypt_InputBlockSize) * _encrypt_OutputBlockSize;
public int GetDecryptOutputMaxByteCount(int inputCount) => GetBlockCount(inputCount, _decrypt_InputBlockSize) * _decrypt_OutputBlockSize;
public void Dispose() {
    _encoder.Dispose();
    System.GC.SuppressFinalize(this);
}


#region Methods_Helper

public static RsaService Create(RSAParameters parameters) => new RsaService(RSA.Create(parameters));

public static RsaService Create() => new RsaService(RSA.Create());

// [keySize] ÷ 8 - [11 bytes for padding] = Result
// Exsimple: [2048 key size] ÷ 8 - [11 bytes for padding] = 245
public static int GetSizeOutputEncryptOfKeySize(int keySize) => (keySize / 8) - 11;

private static int GetBlockCount(int dataLength,int inputBlockSize) {
    int blockCount = (dataLength / inputBlockSize);
    if(dataLength % inputBlockSize != 0)
        blockCount++;
    return blockCount;
}

public static int TransformFinal(TransformBlockCall transformBlockCall, System.ReadOnlySpan<byte> data, System.Span<byte> destination, int inputBlockSize) {

    int blockCount = GetBlockCount(data.Length, inputBlockSize);

    int data_writtenCount = 0;
    int destination_writtenCount = 0;
    while(blockCount-- > 0) {
        if(blockCount == 0) {
            inputBlockSize = data.Length - data_writtenCount;
            if(inputBlockSize == 0) break;
        }
        destination_writtenCount += transformBlockCall(data: data.Slice(data_writtenCount, inputBlockSize)
            , destination: destination.Slice(destination_writtenCount));
        data_writtenCount += inputBlockSize;
    }
    return destination_writtenCount;
}


public static (RSAParameters keyPublic, RSAParameters keyPrivate) GenerateKeyPair(int keySize = 2048) {
    RSAParameters keyPriv;
    RSAParameters keyPub;
    using(var rsa = RSA.Create(keySize)) {
        keyPriv = rsa.ExportParameters(true);
        keyPub = rsa.ExportParameters(false);
    }
    return (keyPub, keyPriv);
}

#endregion Methods_Helper


}