using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

RSA RsaObject = RSA.Create();
bool IsPublic = true;
RSAEncryptionPadding RsaPadding = RSAEncryptionPadding.OaepSHA256;

Aes AesObject = Aes.Create();
const string FORMAT = "yyyy-MM-dd";

void SetRsaKey(bool generate)
{
    if (generate)
    {
        RsaObject = RSA.Create();

        Console.Write("Path to save RSA key pair: ");
        string savePath = Console.ReadLine()!;

        string namePrefix = DateTime.Now.ToString(FORMAT);
        File.WriteAllText(savePath + $"\\{namePrefix}-private.key", RsaObject.ExportRSAPrivateKeyPem());
        File.WriteAllText(savePath + $"\\{namePrefix}-public.pub", RsaObject.ExportRSAPublicKeyPem());

        RsaObject.ImportFromPem(RsaObject.ExportRSAPublicKeyPem());
        return;
    }

    Console.Write("Path to RSA key: ");
    string rsaPath = Console.ReadLine()!;
    IsPublic = rsaPath.EndsWith(".pub");

    RsaObject.ImportFromPem(File.ReadAllText(rsaPath));
}

void RsaCrypt(bool isEncrypt)
{
    if (isEncrypt)
        Console.WriteLine($"CT: {Convert.ToHexString(RsaObject.Encrypt(AesObject.Key, RsaPadding))}");
    else
    {
        Console.Write("Data: ");
        byte[] data = Convert.FromHexString(Console.ReadLine()!);

        try
        {
            AesObject.SetKey(RsaObject.Decrypt(data, RsaPadding));
            Console.WriteLine(Convert.ToHexString(AesObject.Key));
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

    Console.Write("Data: ");
    string data = Console.ReadLine()!;

    if (isEncrypt)
    {
        byte[] d = AesObject.EncryptCbc(Encoding.UTF8.GetBytes(data), AesObject.IV);
        Console.WriteLine($"CT: {Convert.ToHexString([.. AesObject.IV.Concat(d)])}");
    }
    else
    {
        AesObject.IV = Convert.FromHexString(data.AsSpan(0, 32));
        byte[] enc = Convert.FromHexString(data.AsSpan(32));

        Console.WriteLine($"PT: {Encoding.UTF8.GetString(AesObject.DecryptCbc(enc, AesObject.IV))}");
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
        Console.WriteLine("5. Generate and set AES key");
        Console.WriteLine("6. AES Encrypt");
        Console.WriteLine("7. AES Decrypt");
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
                GenerateNewAesKey();
                break;
            case 6:
                AesCrypt(isEncrypt: true);
                break;
            case 7:
                AesCrypt(isEncrypt: false);
                break;
            default:
                break;
        }
    } while (option != 0);
}

Menu();