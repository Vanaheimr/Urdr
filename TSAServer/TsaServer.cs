// ---------------------------------------------------------------------------
//  TsaServer
//  Minimal Kestrel-hosted HTTP TSA endpoint.
//
//  POST /  Content-Type: application/timestamp-query
//          Body: DER-encoded TimeStampReq
//
//  Response: Content-Type: application/timestamp-reply
//            Body: DER-encoded TimeStampResp
// ---------------------------------------------------------------------------

using org.GraphDefined.Vanaheimr.Urdr;
using org.GraphDefined.Vanaheimr.Urdr.Asn1;

namespace TSA.Server;

public static class TSAServer
{

    public const String MediaTypeQuery = "application/timestamp-query";
    public const String MediaTypeReply = "application/timestamp-reply";
    private const int MaxTimestampRequestBytes = 16 * 1024;

    public static async Task RunAsync(
        int port,
        string pfxPath,
        string? pfxPassword,
        string? defaultPolicyOid = null,
        IEnumerable<string>? acceptedPolicyOids = null,
        Accuracy? accuracy = null,
        bool includeAccuracy = true,
        bool ordering = false)
    {
        var (cert, key) = TsaCertificateFactory.LoadOrCreate(pfxPath, pfxPassword);
        var tsa = new TimeStampAuthority(
            cert,
            key,
            policyOid: defaultPolicyOid,
            acceptedPolicyOids: acceptedPolicyOids,
            accuracy: accuracy,
            includeAccuracy: includeAccuracy,
            ordering: ordering);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(port));
        builder.Services.AddSingleton(tsa);

        var app = builder.Build();

        app.MapPost("/", async (HttpRequest req, HttpResponse res, TimeStampAuthority tsa) =>
        {

            var mediaType = req.GetTypedHeaders().ContentType?.MediaType.Value;
            if (!string.Equals(mediaType, MediaTypeQuery, StringComparison.OrdinalIgnoreCase))
            {
                res.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                return;
            }

            if (req.ContentLength is > MaxTimestampRequestBytes)
            {
                res.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }

            var requestDer = await ReadRequestBodyAsync(
                req.Body,
                MaxTimestampRequestBytes,
                req.HttpContext.RequestAborted);

            if (requestDer is null)
            {
                res.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }

            byte[] replyDer;
            try
            {
                replyDer = tsa.Process(requestDer);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[TSA] failure: {ex}");
                res.StatusCode = StatusCodes.Status500InternalServerError;
                return;
            }

            res.ContentType = MediaTypeReply;
            res.ContentLength = replyDer.Length;
            await res.Body.WriteAsync(replyDer);
        });

        app.MapGet("/", () => Results.Text(
            "RFC 3161 TimeStampingAuthority\n" +
            "POST DER-encoded TimeStampReq with Content-Type 'application/timestamp-query'.\n",
            "text/plain"));

        Console.WriteLine($"[TSA] listening on http://0.0.0.0:{port}/  (cert={pfxPath})");
        await app.RunAsync();

    }

    private static async Task<byte[]?> ReadRequestBodyAsync(Stream body, int maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        using var ms = new MemoryStream();

        while (true)
        {
            var read = await body.ReadAsync(buffer, cancellationToken);
            if (read == 0)
                return ms.ToArray();

            if (ms.Length + read > maxBytes)
                return null;

            ms.Write(buffer, 0, read);
        }
    }

}
