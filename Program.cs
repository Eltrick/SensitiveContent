using System.Security.Cryptography;
using System.Text;

const string FORMAT = "yyyy-MM-dd";
const string KEY_FOLDER = "keys";

Aes AesObject = Aes.Create();

RSA RsaObject;
RSAEncryptionPadding RsaPadding = RSAEncryptionPadding.OaepSHA256;

ECDiffieHellman ECDiffieHellmanObject;

DirectoryInfo keyDirectory = new(KEY_FOLDER);
if (!keyDirectory.Exists)
    keyDirectory.Create();

void GenerateECDHKey(bool wait = true)
{
    ECDiffieHellmanObject = ECDiffieHellman.Create();

    Guid guid = Guid.NewGuid();
    string date = DateTime.Now.ToString(FORMAT);
    File.WriteAllText($"{keyDirectory.FullName}\\ecdh-{date}-{guid}-private.pem", ECDiffieHellmanObject.ExportECPrivateKeyPem());
    File.WriteAllText($"{keyDirectory.FullName}\\ecdh-{date}-{guid}-public.pem", ECDiffieHellmanObject.ExportSubjectPublicKeyInfoPem());
    Console.WriteLine($"Saved to {keyDirectory.FullName}\\ecdh-{date}-{guid}-public.pem");
    if (wait)
        Console.ReadKey();
}

void SetECDHKey(bool generate)
{
    if (generate)
    {
        GenerateECDHKey();
        return;
    }

    Console.Write("Path to Diffie-Hellman private key: ");
    string ecPath = Console.ReadLine()!;

    ECDiffieHellmanObject.ImportFromPem(File.ReadAllText(ecPath));
}

void GenerateAndSetKeyUsingDH()
{
    Console.Write("Path to other party's Public Key: ");
    string pkPath = Console.ReadLine()!;

    ECDiffieHellman otherPk = ECDiffieHellman.Create();
    otherPk.ImportFromPem(File.ReadAllText(pkPath));

    AesObject.SetKey(ECDiffieHellmanObject.DeriveKeyMaterial(otherPk.PublicKey));
}

void GenerateRSAKey(bool wait = true)
{
    RsaObject = RSA.Create(4096);

    Guid guid = Guid.NewGuid();
    string date = DateTime.Now.ToString(FORMAT);
    File.WriteAllText($"{keyDirectory.FullName}\\rsa-{date}-{guid}-private.pem", RsaObject.ExportRSAPrivateKeyPem());
    File.WriteAllText($"{keyDirectory.FullName}\\rsa-{date}-{guid}-public.pem", RsaObject.ExportRSAPublicKeyPem());
    Console.WriteLine($"Saved to {keyDirectory.FullName}\\rsa-{date}-{guid}-public.pem");
    if (wait)
        Console.ReadKey();
}

void SetRsaKey(bool generate)
{
    if (generate)
    {
        GenerateRSAKey();
        return;
    }

    Console.Write("Path to RSA key: ");
    string rsaPath = Console.ReadLine()!;

    RsaObject.ImportFromPem(File.ReadAllText(rsaPath));
}

void RsaCrypt(bool isEncrypt)
{
    if (isEncrypt)
        Console.WriteLine($"CT: {Convert.ToBase64String(RsaObject.Encrypt(AesObject.Key, RsaPadding))}");
    else
    {
        Console.Write("Data: ");
        byte[] data = Convert.FromBase64String(Console.ReadLine()!);

        try
        {
            AesObject.SetKey(RsaObject.Decrypt(data, RsaPadding));
            Console.WriteLine("Key unwrap success.");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Key unwrap failure. Check that this key was wrapped using your key.");
        }
    }

    Console.ReadKey();
}

void GenerateNewAesKey()
{
    AesObject.GenerateKey();
    Console.WriteLine("AES key generation success.");
    Console.ReadKey();
    return;
}

void AesCrypt(bool isEncrypt)
{
    if (isEncrypt)
        AesObject.GenerateIV();

    Console.Write("0=Text, 1=File: ");
    bool isFile = int.Parse(Console.ReadLine()!) == 1;

    if (!isFile)
    {
        Console.Write("Data: ");
        string data = Console.ReadLine()!;

        if (isEncrypt)
        {
            byte[] d = AesObject.EncryptCbc(Encoding.UTF8.GetBytes(data), AesObject.IV);
            Console.WriteLine($"CT: {Convert.ToBase64String([.. AesObject.IV.Concat(d)])}");
        }
        else
        {
            byte[] enc = Convert.FromBase64String(data);
            AesObject.IV = enc.AsSpan(0, 16).ToArray();
            byte[] ct = enc.AsSpan(16).ToArray();

            Console.WriteLine($"PT: {Encoding.UTF8.GetString(AesObject.DecryptCbc(ct, AesObject.IV))}");
        }
    }
    else
    {
        Console.Write("Input path: ");
        byte[] input = File.ReadAllBytes(Console.ReadLine()!);

        Console.Write("Output path: ");
        string outputPath = Console.ReadLine()!;

        if (isEncrypt)
        {
            byte[] d = AesObject.EncryptCbc(input, AesObject.IV);
            File.WriteAllBytes(outputPath, [.. AesObject.IV.Concat(d)]);
            Console.WriteLine("Encrypted file written successfully");
        }
        else
        {
            AesObject.IV = input.AsSpan(0, 16).ToArray();
            byte[] ct = input.AsSpan(16).ToArray();

            File.WriteAllBytes(outputPath, AesObject.DecryptCbc(ct, AesObject.IV));
            Console.WriteLine("Decrypted file written successfully");
        }
    }
    Console.ReadKey();
}

void Menu()
{
    int option;

    do
    {
        Console.Clear();
        Console.WriteLine("1. Generate, save, and set RSA key");
        Console.WriteLine("2. Set custom RSA key");
        Console.WriteLine("3. RSA Key Wrap");
        Console.WriteLine("4. RSA Key Unwrap and set AES key");
        Console.WriteLine("5. Generate, save, and set ECDH key");
        Console.WriteLine("6. Set custom ECDH key");
        Console.WriteLine("7. Derive and set AES key using other party");
        Console.WriteLine("8. Generate and set AES key");
        Console.WriteLine("9. AES Encrypt");
        Console.WriteLine("10. AES Decrypt");
        Console.WriteLine("0. Exit");

        Console.Write("Option: ");
        option = int.Parse(Console.ReadLine()!);

        switch (option)
        {
            case 1:
                SetRsaKey(generate: true);
                break;
            case 2:
                SetRsaKey(generate: false);
                break;
            case 3:
                RsaCrypt(isEncrypt: true);
                break;
            case 4:
                RsaCrypt(isEncrypt: false);
                break;
            case 5:
                SetECDHKey(generate: true);
                break;
            case 6:
                SetECDHKey(generate: false);
                break;
            case 7:
                GenerateAndSetKeyUsingDH();
                break;
            case 8:
                GenerateNewAesKey();
                break;
            case 9:
                AesCrypt(isEncrypt: true);
                break;
            case 10:
                AesCrypt(isEncrypt: false);
                break;
            default:
                break;
        }
    } while (option != 0);
}

GenerateRSAKey(false);
GenerateECDHKey();
Menu();