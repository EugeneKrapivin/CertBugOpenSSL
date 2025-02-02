using System.Security.Cryptography;
using OpenSSL.PrivateKeyDecoder;
using System.Threading;

// capture ctrl+c and cancel a token
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

// add a writing to click ctrl+c or alt-s to stop
Console.WriteLine("Press Ctrl+C or Alt+S to stop.");

// Start a new thread to listen for Alt+S key combination
var keyListenerThread = new Thread(() =>
{
    while (!cts.Token.IsCancellationRequested)
    {
        if (Console.KeyAvailable)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.S && key.Modifiers == ConsoleModifiers.Alt)
            {
                cts.Cancel();
            }
        }
        Thread.Sleep(100); // Reduce CPU usage
    }
});
keyListenerThread.Start();

while (!cts.Token.IsCancellationRequested)
{
    var rsa = new RSACryptoServiceProvider(512);
    var cert = rsa.ExportRSAPrivateKeyPem();

    var decoder = new OpenSSLPrivateKeyDecoder();
    try
    {
        var decoded = decoder.Decode(cert, null);
    }
    catch
    {
        Console.WriteLine(cert);

        PrintLineSeparator();

        Console.WriteLine("OpenSSLPrivateKeyDecoder:");
        var parameters = decoder.DecodeParameters(cert);
        Dump(parameters);

        PrintLineSeparator();

        Console.WriteLine("dotnet original:");

        Dump(rsa.ExportParameters(true));

        PrintLineSeparator();

        Console.WriteLine("dotnet reimport:");
        var rsa2 = RSA.Create();
        rsa2.ImportFromPem(cert);
        var reimported = rsa2.ExportParameters(true);
        Dump(reimported);

        PrintLineSeparator(); 

        CompareRSAParameters(parameters, reimported);

        cts.Cancel();
        break;
    }
}

void Dump(RSAParameters parameters)
{
    Console.WriteLine($"D:  {BitConverter.ToString(parameters.D!)}");
    Console.WriteLine($"DP: {BitConverter.ToString(parameters.DP!)}");
    Console.WriteLine($"DQ: {BitConverter.ToString(parameters.DQ!)}");
    Console.WriteLine($"EX: {BitConverter.ToString(parameters.Exponent!)}");
    Console.WriteLine($"IQ: {BitConverter.ToString(parameters.InverseQ!)}");
    Console.WriteLine($"M:  {BitConverter.ToString(parameters.Modulus!)}");
    Console.WriteLine($"P:  {BitConverter.ToString(parameters.P!)}");
    Console.WriteLine($"Q:  {BitConverter.ToString(parameters.Q!)}");
}

bool CompareRSAParameters(RSAParameters left, RSAParameters right)
{
    return CompareByteArrays(left.D, right.D, "D")
        || CompareByteArrays(left.DP, right.DP, "DP")
        || CompareByteArrays(left.DQ, right.DQ, "DQ")
        || CompareByteArrays(left.Exponent, right.Exponent, "Exponent")
        || CompareByteArrays(left.InverseQ, right.InverseQ, "InverseQ")
        || CompareByteArrays(left.Modulus, right.Modulus, "Modulus")
        || CompareByteArrays(left.P, right.P, "P")
        || CompareByteArrays(left.Q, right.Q, "Q");
}

bool CompareByteArrays(byte[]? left, byte[]? right, string title)
{
    if (left == null || right == null)
    {
        Console.WriteLine("One or both byte arrays are null.");
        return false;
    }

    int minLength = Math.Min(left.Length, right.Length);
    bool differenceFound = false;

    for (int i = 0; i < minLength; i++)
    {
        if (left[i] != right[i])
        {
            Console.WriteLine($"field diff: " + title);
            Console.WriteLine($"left:  {BitConverter.ToString(left)}");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("       " + new string(' ', i * 3) + "\\/");
            Console.WriteLine("       " + new string(' ', i * 3) + "||");
            Console.WriteLine("       " + new string(' ', i * 3) + "\\/");
            Console.ResetColor();
            Console.WriteLine($"right: {BitConverter.ToString(right)}");
            differenceFound = true;
            break;
        }
    }

    if (left.Length != right.Length)
    {
        Console.WriteLine($"length diff for array: " + title);
        if (!differenceFound)
        {
            Console.WriteLine("left:  " + BitConverter.ToString(left));
            Console.WriteLine("right: " + BitConverter.ToString(right));
        }
        Console.WriteLine("Arrays have different lengths.");
        Console.WriteLine($"{nameof(left)} Length: {left.Length}");
        Console.WriteLine($"{nameof(right)} Length: {right.Length}");
        differenceFound = true;
    }

    return differenceFound;
}

static void PrintLineSeparator()
{
    Console.WriteLine();
    Console.WriteLine("================================================");
    Console.WriteLine();
}