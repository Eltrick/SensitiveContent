using System.Security.Cryptography;
using System.Text;

const string FORMAT = "yyyy-MM-dd";

Aes AesObject = Aes.Create();

RSA RsaObject = RSA.Create(4096);
RSAEncryptionPadding RsaPadding = RSAEncryptionPadding.OaepSHA256;

ECDiffieHellman ECDiffieHellmanObject = ECDiffieHellman.Create();

void SetECDHKey(bool generate)
{
    if (generate)
    {
        ECDiffieHellmanObject = ECDiffieHellman.Create();
        Console.Write("Path to save Diffie-Hellman public key: ");
        string savePath = Console.ReadLine()!;

        string namePrefix = DateTime.Now.ToString(FORMAT);
        File.WriteAllText(savePath + $"\\ecdh-{namePrefix}-private.pub", ECDiffieHellmanObject.ExportECPrivateKeyPem());
        File.WriteAllText(savePath + $"\\ecdh-{namePrefix}-public.pub", ECDiffieHellmanObject.ExportSubjectPublicKeyInfoPem());
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

void SetRsaKey(bool generate)
{
    if (generate)
    {
        RsaObject = RSA.Create(4096);

        Console.Write("Path to save RSA key pair: ");
        string savePath = Console.ReadLine()!;

        string namePrefix = DateTime.Now.ToString(FORMAT);
        File.WriteAllText(savePath + $"\\rsa-{namePrefix}-private.key", RsaObject.ExportRSAPrivateKeyPem());
        File.WriteAllText(savePath + $"\\rsa-{namePrefix}-public.pub", RsaObject.ExportRSAPublicKeyPem());
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
            Console.WriteLine(Convert.ToBase64String(AesObject.Key));
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
        Console.WriteLine("A. AES Decrypt");
        Console.WriteLine("0. Exit");

        Console.Write("Option: ");
        option = "0123456789A".IndexOf(Console.ReadLine()!.ToUpper());

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

Menu();