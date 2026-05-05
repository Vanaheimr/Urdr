// ---------------------------------------------------------------------------
//  Tsa.Cli - Program.cs
//
//  Usage:
//    Tsa.Cli serve  [--port 8080] [--pfx tsa.pfx] [--password ...]
//                   [--accuracy-seconds 1] [--accuracy-millis 500] [--accuracy-micros 250]
//                   [--no-accuracy] [--ordering]
//                   [--policy oid] [--accept-policy oid[,oid...]]
//    Tsa.Cli stamp  --url http://host:port/  [--in file] [--out token.tsr]
//    Tsa.Cli selftest
//
//  selftest spins the server in-process, makes a request, verifies the
//  token round-trip, and shuts down.
// ---------------------------------------------------------------------------

#region Usings

using TSA.Server;

using System.Globalization;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Server
{

    public static class Program
    {


        private static async Task<int> Serve(Dictionary<string, string> o)
        {
            int port = o.TryGetValue("port", out var p) ? int.Parse(p, CultureInfo.InvariantCulture) : 8080;
            string pfx = o.GetValueOrDefault("pfx", "tsa.pfx");
            string? pwd = o.GetValueOrDefault("password");
            var includeAccuracy = !o.ContainsKey("no-accuracy");
            var accuracy = includeAccuracy ? ParseAccuracy(o) : null;
            var ordering = o.ContainsKey("ordering");
            var defaultPolicyOid = o.GetValueOrDefault("policy");
            var acceptedPolicyOids = ParsePolicyList(o, defaultPolicyOid);
            await TSAServer.RunAsync(
                port,
                pfx,
                pwd,
                defaultPolicyOid,
                acceptedPolicyOids,
                accuracy,
                includeAccuracy,
                ordering);
            return 0;
        }

        private static IReadOnlyList<string>? ParsePolicyList(Dictionary<string, string> o, string? defaultPolicyOid)
        {
            var policies = new List<string>();
            if (!string.IsNullOrWhiteSpace(defaultPolicyOid))
                policies.Add(defaultPolicyOid);

            if (o.TryGetValue("accept-policy", out var raw))
            {
                policies.AddRange(
                    raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }

            return policies.Count > 0 ? policies : null;
        }

        private static Accuracy? ParseAccuracy(Dictionary<string, string> o)
        {
            int? seconds = TryParseInt(o, "accuracy-seconds");
            int? millis = TryParseInt(o, "accuracy-millis");
            int? micros = TryParseInt(o, "accuracy-micros");

            if (seconds is null && millis is null && micros is null)
                return null;

            return new Accuracy(seconds, millis, micros);
        }

        private static int? TryParseInt(Dictionary<string, string> o, string key)
            => o.TryGetValue(key, out var value)
                ? int.Parse(value, CultureInfo.InvariantCulture)
                : null;

        //private static async Task<int> Stamp(Dictionary<string, string> o)
        //{
        //    string url = o.GetValueOrDefault("url", "http://localhost:8080/");
        //    string? input = o.GetValueOrDefault("in");
        //    string? outFile = o.GetValueOrDefault("out");
        //    return await TsaClient.RunAsync(url, input, outFile);
        //}

        //private static async Task<int> Selftest(Dictionary<string, string> o)
        //{
        //    int port = o.TryGetValue("port", out var p) ? int.Parse(p, CultureInfo.InvariantCulture) : 18080;
        //    string pfx = Path.Combine(Path.GetTempPath(), $"tsa-selftest-{Guid.NewGuid():N}.pfx");

        //    var serverTask = TsaServer.RunAsync(port, pfx, null);
        //    await Task.Delay(700); // give Kestrel a moment

        //    // small synthetic payload
        //    var tmpFile = Path.Combine(Path.GetTempPath(), $"selftest-{Guid.NewGuid():N}.bin");
        //    await File.WriteAllTextAsync(tmpFile, "Vanaheimr Norn meets RFC 3161.");

        //    var tokenFile = tmpFile + ".tsr";
        //    int rc = await TsaClient.RunAsync($"http://localhost:{port}/", tmpFile, tokenFile);

        //    Console.WriteLine($"[selftest] result code: {rc}");
        //    Console.WriteLine($"[selftest] token file:  {tokenFile}");
        //    Console.WriteLine($"[selftest] cert file:   {pfx}");
        //    Console.WriteLine("[selftest] hint: openssl ts -reply -in {0} -text", tokenFile);
        //    return rc;

        //    // Note: server task keeps running; ctrl-c to exit.  We deliberately
        //    // do not await serverTask so the selftest exits its synchronous
        //    // checks first.
        //}

        private static Dictionary<string, string> ParseOptions(IEnumerable<string> args)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var list = args.ToList();
            for (int i = 0; i < list.Count; i++)
            {
                var a = list[i];
                if (!a.StartsWith("--", StringComparison.Ordinal)) continue;
                string key = a[2..];
                string? val = (i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal))
                    ? list[++i] : "true";
                d[key] = val;
            }
            return d;
        }

        private static int PrintUsage()
        {

            Console.WriteLine("""
                Tsa.Cli — minimal hand-rolled RFC 3161 TimeStamping Authority

                Commands:
                  serve     [--port 8080] [--pfx tsa.pfx] [--password ...]
                            [--accuracy-seconds 1] [--accuracy-millis 500] [--accuracy-micros 250]
                            [--no-accuracy] [--ordering]
                            [--policy oid] [--accept-policy oid[,oid...]]
                  stamp     [--url http://host:port/] [--in file] [--out token.tsr]
                  selftest  [--port 18080]

                Examples:
                  dotnet run --project src/Tsa.Cli -- serve
                  dotnet run --project src/Tsa.Cli -- stamp --in README.md --out readme.tsr
                  dotnet run --project src/Tsa.Cli -- selftest
                """);

            return 0;

        }



        public static async Task<Int32> Main(String[] args)
        {

            if (args.Length == 0)
            {
                await Serve([]);
                return 0;
            }

            var cmd  = args[0].ToLowerInvariant();
            var opts = ParseOptions(args.Skip(1));

            return cmd switch {
                "serve"    => await Serve(opts),
                //"stamp"    => await Stamp(opts),
                //"selftest" => await Selftest(opts),
                "--help" or "-h" or "help" => PrintUsage(),
                _ => PrintUsage()
            };

        }

    }

}
