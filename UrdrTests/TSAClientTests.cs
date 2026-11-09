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

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

[TestFixture]
public sealed class TSAClientTests
{

    [Test]
    public async Task TimestampAsync_Rejects_ResponseForDifferentMessageImprint()
    {

        using var cert                      = TestCertificate.CreateRsa();

              var tsa                       = new TimeStampAuthority(
                                                  cert.Info,
                                                  cert.PrivateKey
                                              );

              var responseForDifferentData  = tsa.Process(
                                                  TimeStampRequest.ForData(
                                                      [9, 9, 9],
                                                      certReq: true
                                                  ).Encode()
                                              );

        using var server                    = new LoopbackTSA(request => responseForDifferentData);

        using var client                    = new TSAClient(
                                                  $"http://127.0.0.1:{server.Port}/",
                                                  cert.Certificate,
                                                  DNSClient: null
                                              );

        await Assert.ThatAsync(
            async () => await client.GetTimestamp([1, 2, 3]),
            Throws.InstanceOf<InvalidDataException>()
        );

    }


    [Test]
    public async Task GetStreamTimestamp_HashesStreamWithSmallBuffer()
    {

              using var cert        = TestCertificate.CreateRsa();

                    var tsa         = new TimeStampAuthority(
                                          cert.Info,
                                          cert.PrivateKey
                                      );

                    var payload     = Enumerable.Range  (0, 128 * 1024 + 333).
                                                 Select (i => (Byte) ((i * 29 + 13) & 0xFF)).
                                                 ToArray();

        await using var stream      = new ChunkedReadStream(
                                          payload,
                                          MaxChunkSize: 17
                                      );

              using var server      = new LoopbackTSA(tsa.Process);

              using var client      = new TSAClient(
                                          $"http://127.0.0.1:{server.Port}/",
                                          cert.Certificate,
                                          DNSClient: null
                                      );

                    var result      = await client.GetStreamTimestamp(
                                                stream,
                                                AlgorithmIdentifier.Sha256,
                                                BufferSize: 1024
                                            );

        Assert.Multiple(() => {
            Assert.That(result.TstInfo.MessageImprint.HashAlgorithm.Algorithm,  Is.EqualTo(OIDMap.Sha256));
            Assert.That(result.TstInfo.MessageImprint.HashedMessage,            Is.EqualTo(SHA256.HashData(payload)));
            Assert.That(stream.Position,                                        Is.EqualTo(stream.Length));
        });

    }


    /// <summary>
    /// The TSA's host name is resolved with the DNS client the TSAClient is given, and never with the
    /// resolver of the operating system: .invalid is a name no operating system answers (RFC 6761).
    /// </summary>
    [Test]
    [CancelAfter(20000)]
    public async Task ATSAsHostNameIsResolvedWithTheDNSClientOnly(CancellationToken CancellationToken)
    {

        using var cert       = TestCertificate.CreateRsa();

              var tsa        = new TimeStampAuthority(
                                   cert.Info,
                                   cert.PrivateKey
                               );

        using var server     = new LoopbackTSA(tsa.Process);

              var dnsClient  = new LoopbackDNS();

        using var client     = new TSAClient(
                                   $"http://tsa.invalid:{server.Port}/stamp",
                                   cert.Certificate,
                                   dnsClient
                               );

              var result     = await client.GetTimestamp([1, 2, 3], CancellationToken: CancellationToken);

        Assert.Multiple(() => {
            Assert.That(result.TstInfo.MessageImprint.HashedMessage,  Is.EqualTo(SHA256.HashData([1, 2, 3])));
            Assert.That(dnsClient.Asked.Distinct(),                    Is.EqualTo(new[] { "tsa.invalid" }));
            Assert.That(server.Requests,                               Has.Some.StartsWith("POST /stamp HTTP/1.1"));
            Assert.That(server.Requests,                               Has.Some.Contains("application/timestamp-query"));
        });

    }


    #region (private) LoopbackTSA

    /// <summary>
    /// A Time Stamp Authority on the loopback, speaking just enough HTTP/1.1: each request's body is
    /// answered with what the given function makes of it, and the connection is closed.
    /// </summary>
    private sealed class LoopbackTSA : IDisposable
    {

        private readonly TcpListener              listener = new (System.Net.IPAddress.Loopback, 0);
        private readonly CancellationTokenSource  stopping = new ();
        private readonly List<String>             requests = [];

        public UInt16 Port { get; }

        /// <summary>
        /// The request lines and headers that came in.
        /// </summary>
        public IReadOnlyList<String> Requests
        {
            get
            {
                lock (requests)
                    return [.. requests];
            }
        }

        public LoopbackTSA(Func<Byte[], Byte[]> Answer)
        {

            listener.Start();
            Port = (UInt16) ((System.Net.IPEndPoint) listener.LocalEndpoint).Port;

            _ = Task.Run(async () => {
                    while (!stopping.IsCancellationRequested)
                    {
                        try
                        {
                            using var connection = await listener.AcceptTcpClientAsync(stopping.Token);
                            await Serve(connection.GetStream(), Answer);
                        }
                        catch (OperationCanceledException) { return; }
                        catch (ObjectDisposedException)    { return; }
                        catch (IOException)                { }
                        catch (SocketException)            { }
                    }
                });

        }

        private async Task Serve(NetworkStream Stream, Func<Byte[], Byte[]> Answer)
        {

            var received = new List<Byte>();
            var buffer   = new Byte[8192];
            var headEnd  = -1;

            while (headEnd < 0)
            {
                var read = await Stream.ReadAsync(buffer, stopping.Token);
                if (read == 0)
                    return;
                received.AddRange(buffer.AsSpan(0, read));
                headEnd = IndexOfEmptyLine(received);
            }

            var head          = Encoding.ASCII.GetString([.. received.Take(headEnd)]);
            var contentLength = head.Split("\r\n").
                                     Where (line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)).
                                     Select(line => Int32.Parse(line[15..].Trim())).
                                     FirstOrDefault();

            lock (requests)
                requests.Add(head);

            while (received.Count < headEnd + 4 + contentLength)
            {
                var read = await Stream.ReadAsync(buffer, stopping.Token);
                if (read == 0)
                    return;
                received.AddRange(buffer.AsSpan(0, read));
            }

            var body   = received.Skip(headEnd + 4).Take(contentLength).ToArray();
            var answer = Answer(body);

            await Stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n" +
                                                            "Content-Type: application/timestamp-reply\r\n" +
                                                            $"Content-Length: {answer.Length}\r\n" +
                                                            "Connection: close\r\n\r\n"), stopping.Token);
            await Stream.WriteAsync(answer, stopping.Token);

        }

        private static Int32 IndexOfEmptyLine(List<Byte> Bytes)
        {
            for (var i = 0; i + 3 < Bytes.Count; i++)
                if (Bytes[i] == '\r' && Bytes[i + 1] == '\n' && Bytes[i + 2] == '\r' && Bytes[i + 3] == '\n')
                    return i;
            return -1;
        }

        public void Dispose()
        {
            stopping.Cancel();
            listener.Stop();
            stopping.Dispose();
        }

    }

    #endregion

    #region (private) LoopbackDNS

    /// <summary>
    /// A DNS client that names the loopback for every host, and records what it was asked.
    /// </summary>
    private sealed class LoopbackDNS : IDNSClient
    {

        private static readonly DNSServerConfig origin = new (IPv4Address.Localhost, IPPort.Parse(53));

        private readonly List<String> asked = [];

        public IReadOnlyList<String> Asked
        {
            get
            {
                lock (asked)
                    return [.. asked];
            }
        }

        public Task<DNSInfo> Query(DomainName DomainName, IEnumerable<DNSResourceRecordTypes> ResourceRecordTypes, TimeSpan? Timeout = null,
                                   Boolean? RecursionDesired = true, Boolean? ForceUpdate = false, CancellationToken CancellationToken = default)
            => Query(DNSServiceName.Parse(DomainName.FullName), ResourceRecordTypes, Timeout, RecursionDesired, ForceUpdate, CancellationToken);

        public Task<DNSInfo> Query(DNSServiceName DNSServiceName, IEnumerable<DNSResourceRecordTypes> ResourceRecordTypes, TimeSpan? Timeout = null,
                                   Boolean? RecursionDesired = true, Boolean? ForceUpdate = false, CancellationToken CancellationToken = default)
        {

            lock (asked)
                asked.Add(DNSServiceName.FullName.TrimEnd('.'));

            IDNSResourceRecord[] answers = ResourceRecordTypes.Contains(DNSResourceRecordTypes.A)
                                               ? [ new A(DNSServiceName, DNSQueryClasses.IN, TimeSpan.FromMinutes(1), IPv4Address.Localhost) ]
                                               : [];

            return Task.FromResult(new DNSInfo(origin, 0, true, false, true, true, DNSResponseCodes.NoError,
                                               answers, [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero));

        }

        public void Dispose() { }

        public ValueTask DisposeAsync()
            => ValueTask.CompletedTask;

        public override String ToString()
            => nameof(LoopbackDNS);

    }

    #endregion

    #region (private) ChunkedReadStream

    private sealed class ChunkedReadStream(Byte[]  Payload,
                                           Int32   MaxChunkSize) : MemoryStream(Payload)
    {

        public override ValueTask<Int32>

            ReadAsync(Memory<Byte>       Buffer,
                      CancellationToken  CancellationToken = default)

        {

            var length = Math.Min(
                             Buffer.Length,
                             MaxChunkSize
                         );

            return base.ReadAsync(
                       Buffer[..length],
                       CancellationToken
                   );

        }

    }

    #endregion

}
