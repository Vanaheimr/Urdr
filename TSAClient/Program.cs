/*
 * Copyright (c) 2015-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Urdr <https://github.com/Vanaheimr/Urdr>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Globalization;
using System.Security.Cryptography.X509Certificates;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Client
{

    public static class Program
    {

        private const String DefaultCertPath = "tsa.pfx";

        private static async Task<Int32> Stamp(Dictionary<String, String> opts)
        {

            var url                       = opts.GetValueOrDefault("url",  TSAClient.DefaultTsaUrl);
            var certPath                  = opts.GetValueOrDefault("cert", DefaultCertPath);
            var password                  = opts.GetValueOrDefault("password");
            var inputPath                 = opts.GetValueOrDefault("in");
            var outputPath                = opts.GetValueOrDefault("out");
            var policy                    = opts.GetValueOrDefault("policy");
            var hashAlgorithm             = ParseHashAlgorithm(opts.GetValueOrDefault("hash", "sha256"));

            using var trustedCertificate  = LoadTrustedCertificate(certPath, password);
            using var client              = new TSAClient(url, trustedCertificate);

            TimeStampResult result;

            if (!String.IsNullOrWhiteSpace(inputPath))
                result = await client.GetFileTimestamp(inputPath, hashAlgorithm, policy);

            else
            {
                var sample = "Hello from the local TimeStampService client.\n"u8.ToArray();
                result = await client.GetTimestamp(sample, hashAlgorithm, policy);
            }

            if (!String.IsNullOrWhiteSpace(outputPath))
                await File.WriteAllBytesAsync(outputPath, result.Response.Encode());

            Console.WriteLine("Timestamp granted");
            Console.WriteLine($"  Server:       {url}");
            Console.WriteLine($"  Certificate:  {certPath}");
            Console.WriteLine($"  Time UTC:     {result.TstInfo.GenTime:O}");
            Console.WriteLine($"  Serial:       {result.TstInfo.SerialNumber}");
            Console.WriteLine($"  Policy:       {result.TstInfo.Policy}");
            Console.WriteLine($"  Hash OID:     {result.TstInfo.MessageImprint.HashAlgorithm.Algorithm}");
            Console.WriteLine($"  Accuracy:     {result.TstInfo.Accuracy?.ToString() ?? "not specified"}");
            Console.WriteLine($"  Ordering:     {result.TstInfo.Ordering}");
            Console.WriteLine($"  Signer:       {result.SignerCertificate.Subject}");

            if (!String.IsNullOrWhiteSpace(outputPath))
                Console.WriteLine($"  Response DER: {outputPath}");

            return 0;

        }

        private static X509Certificate2 LoadTrustedCertificate(String path, String? password)
        {

            var extension = Path.GetExtension(path).ToLowerInvariant();

            return extension is ".pfx" or ".p12"
                       ? X509CertificateLoader.LoadPkcs12FromFile(path, password)
                       : X509CertificateLoader.LoadCertificateFromFile(path);

        }

        private static AlgorithmIdentifier ParseHashAlgorithm(String value)

            => value.ToLowerInvariant() switch {
                   "sha256" or "sha-256"  => AlgorithmIdentifier.Sha256,
                   "sha384" or "sha-384"  => AlgorithmIdentifier.Sha384,
                   "sha512" or "sha-512"  => AlgorithmIdentifier.Sha512,
                   _                      => throw new ArgumentException($"Unsupported hash algorithm '{value}'. Use sha256, sha384, or sha512!")
               };

        private static Dictionary<String, String> ParseOptions(IEnumerable<String> args)
        {

            var options = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);
            var list = args.ToList();

            for (var i = 0; i < list.Count; i++)
            {

                var arg = list[i];
                if (arg.Equals("stamp", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!arg.StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException($"Unexpected argument '{arg}'.");

                var key = arg[2..];
                var value = i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal)
                    ? list[++i]
                    : "true";

                options[key] = value;

            }

            return options;
        }

        private static int PrintUsage()
        {

            Console.WriteLine(String.Create(CultureInfo.InvariantCulture, $"""
                TSAClient - request an RFC 3161 timestamp from a Time Stamp Authority (TSA) server

                Usage:
                  dotnet run --project TSAClient -- [stamp]
                      [--url http://localhost:8080/]
                      [--cert tsa.pfx] [--password secret]
                      [--in file.bin] [--out response.tsr]
                      [--hash sha256|sha384|sha512]
                      [--policy oid]

                Defaults:
                  --url   {TSAClient.DefaultTsaUrl}
                  --cert  {DefaultCertPath}
                  --hash  sha256

                Examples:
                  dotnet run --project TSAServer -- serve
                  dotnet run --project TSAClient -- --in README.md --out README.tsr
                  dotnet run --project TSAClient -- --hash sha384 --in README.md
                  dotnet run --project TSAClient -- --policy 1.3.6.1.4.1.99999.1.1 --in README.md --out README.tsr
                """));

            return 0;

        }


        public static async Task<Int32> Main(String[] Arguments)
        {

            var opts = ParseOptions(Arguments);

            if (opts.ContainsKey("help") || opts.ContainsKey("h"))
                return PrintUsage();

            try
            {
                return await Stamp(opts);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[TSAClient] {ex.Message}");
                return 1;
            }

        }

    }

}
