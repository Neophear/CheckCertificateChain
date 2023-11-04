using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        string thumbPrint;

        // Read thumbprint from console, unless command is EXIT, then exit
        while (true)
        {
            Console.Write("Enter thumbprint (or EXIT to exit): ");
            var input = Console.ReadLine();
            if (input == "EXIT")
                return;

            if (string.IsNullOrWhiteSpace(input))
                continue;

            thumbPrint = input;
            break;
        }
        
        var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        
        try
        {
            store.Open(OpenFlags.ReadOnly);

            PrintTitle(thumbPrint);

            Console.WriteLine($"Looking for certificate with thumbprint '{thumbPrint}' in store '{store.Name}'...");
            var collection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint, false);
            
            if (collection.Count == 0)
            {
                Console.WriteLine("No certificate found.");
                return;
            }

            Console.WriteLine("Found certificate(s)...");
            Console.WriteLine();

            foreach (var cert in collection)
            {
                Console.WriteLine(cert.Verify() ? "Certificate is valid." : "Certificate is NOT valid.");

                X509Chain chain = new();
                chain.Build(cert);
                
                foreach (var element in chain.ChainElements)
                {
                    PrintTitle(element.Certificate.FriendlyName, false, false);
                    Console.WriteLine ("Element issuer name: {0}", element.Certificate.Issuer);
                    Console.WriteLine ("Element certificate valid until: {0}", element.Certificate.NotAfter);
                    Console.WriteLine ("Element certificate is valid: {0}", element.Certificate.Verify ());
                    Console.WriteLine ("Element error status length: {0}", element.ChainElementStatus.Length);
                    Console.WriteLine ("Element information: {0}", element.Information);
                    Console.WriteLine ("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);
                    
                    // Check if element has CRL
                    var ext = element.Certificate.Extensions["2.5.29.31"];
                    var oidValue = ext?.Oid?.Value;
                    if (oidValue != null)
                    {
                        var asOid = new Oid(oidValue);
                        Console.WriteLine("Extension type: {0}", asOid.FriendlyName);
                        Console.WriteLine("Oid value: {0}", asOid.Value);
                        Console.WriteLine("Extension critical: {0}", ext!.Critical);
                        Console.WriteLine("Extension format: {0}{1}", ext.Format(true), Environment.NewLine);
                    }

                    if (chain.ChainStatus.Length <= 1)
                        continue;

                    foreach (var t in element.ChainElementStatus)
                    {
                        Console.WriteLine (t.Status);
                        Console.WriteLine (t.StatusInformation);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
        
        Console.ReadKey();
    }

    private static void PrintTitle(string desc, bool withPrefix = true, bool withSuffix = true)
    {
        const int minTitleWidth = 46;
        var titleWidth = Math.Max(desc.Length + 4, minTitleWidth);

        if (withPrefix)
            Console.WriteLine(new string('#', titleWidth));

        // Write out the description centered and with padded hashtags on each side
        var paddingLeft = (titleWidth - desc.Length - 2) / 2;
        var paddingRight = desc.Length % 2 == 0 ? paddingLeft : paddingLeft + 1;
        Console.Write(new string('#', paddingLeft));
        Console.Write($" {desc} ");
        Console.WriteLine(new string('#', paddingRight));

        if (withSuffix)
            Console.WriteLine(new string('#', titleWidth));
    }
}
