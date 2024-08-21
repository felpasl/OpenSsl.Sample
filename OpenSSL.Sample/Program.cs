
using System;
using System.IO;
using System.Security.Cryptography;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("OpenSSL Sample");

string filePath = "csv_to_cript.csv";
int numRows = 10; // Number of rows in the CSV file

// deleta all .csv and .bin files
foreach (var file in Directory.GetFiles(Directory.GetCurrentDirectory(), "*.csv"))
    File.Delete(file);
foreach (var file in Directory.GetFiles(Directory.GetCurrentDirectory(), "*.bin"))
    File.Delete(file);


// Generate random data and write to the CSV file
using (StreamWriter writer = new StreamWriter(filePath))
{
    // Write the header row
    writer.WriteLine("Int,Double,String");

    // Generate and write the data rows
    Random random = new Random();
    for (int i = 0; i < numRows; i++)
    {
        int column1 = random.Next(100);
        double column2 = random.NextDouble() * 100;
        string column3 = Guid.NewGuid().ToString();

        writer.WriteLine($"{column1},{column2},{column3}");
    }
}

Console.WriteLine("CSV file created successfully.");

// Load the public key from file
byte[] publicKeyBytes = File.ReadAllBytes("public_key.pem");
string publicKeyString = System.Text.Encoding.UTF8.GetString(publicKeyBytes);


using (RSA rsa = RSA.Create(2048))
{
    rsa.ImportFromPem(publicKeyString); 
    var encryptor = new RsaService(rsa);
    
    // Read the file to encrypt
    byte[] fileData = File.ReadAllBytes("csv_to_cript.csv");

    var encryptedData = encryptor.Encrypt(fileData);

    // Save the encrypted data to a new file
    File.WriteAllBytes("encrypted_csv_to_cript.csv", encryptedData);
    Console.WriteLine("File encrypted and saved to encrypted_csv_to_cript.csv");
}

// Load the private key from file
byte[] privateKeyBytes = File.ReadAllBytes("private_key.pem");
string privateKeyString = System.Text.Encoding.UTF8.GetString(privateKeyBytes);
string password = "password";

using (RSA rsa = RSA.Create(2048))
{
    rsa.ImportFromEncryptedPem(privateKeyString, password);
    var decryptor = new RsaService(rsa);

    // Read the encrypted file
    byte[] encryptedFileData = File.ReadAllBytes("encrypted_csv_to_cript.csv");

    var decryptedData = decryptor.Decrypt(encryptedFileData);

    // Save the decrypted data to a new file
    File.WriteAllBytes("decrypted_csv_to_cript.csv", decryptedData);
    Console.WriteLine("File decrypted and saved to decrypted_csv_to_cript.csv");
}

using (Aes aes = Aes.Create())
{
    aes.GenerateKey();
    aes.GenerateIV();

    // Load key and iv from file if exists
    if (File.Exists("aes_key.bin"))
        aes.Key = File.ReadAllBytes("aes_key.bin");
    if (File.Exists("aes_iv.bin"))
        aes.IV = File.ReadAllBytes("aes_iv.bin");

    byte[] key = aes.Key;
    byte[] iv = aes.IV;

    // save the key and iv to a file if not exists
    if (!File.Exists("aes_key.bin"))
        File.WriteAllBytes("aes_key.bin", key);
    if (!File.Exists("aes_iv.bin"))
        File.WriteAllBytes("aes_iv.bin", iv);


    var aesService = new AesService(key, iv);

    // Read the file to encrypt
    byte[] fileData = File.ReadAllBytes("csv_to_cript.csv");

    var encryptedData = aesService.Encrypt(fileData);

    // Save the encrypted data to a new file
    File.WriteAllBytes("encrypted_csv_to_cript_aes.csv", encryptedData);
    Console.WriteLine("File encrypted with AES and saved to encrypted_csv_to_cript_aes.csv");

    var decryptedData = aesService.Decrypt(encryptedData);

    // Save the decrypted data to a new file
    File.WriteAllBytes("decrypted_csv_to_cript_aes.csv", decryptedData);
    Console.WriteLine("File decrypted with AES and saved to decrypted_csv_to_cript_aes.csv");
}