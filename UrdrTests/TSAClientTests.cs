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

using System.Net;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

[TestFixture]
public sealed class TSAClientTests
{

    [Test]
    public void TimestampAsync_Rejects_ResponseForDifferentMessageImprint()
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

        using var httpClient                = new HttpClient(
                                                  new StaticResponseHandler(responseForDifferentData)
                                              );

        using var client                    = new TSAClient(
                                                  httpClient,
                                                  "https://tsa.example.test/",
                                                  cert.Certificate
                                              );

        Assert.That(
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

              using var httpClient  = new HttpClient(
                                          new TimestampingHandler(tsa)
                                      );

              using var client      = new TSAClient(
                                          httpClient,
                                          "https://tsa.example.test/",
                                          cert.Certificate
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


    private sealed class StaticResponseHandler(Byte[] ResponseBytes) : HttpMessageHandler
    {

        protected override Task<HttpResponseMessage>

            SendAsync(HttpRequestMessage  Request,
                      CancellationToken   CancellationToken)

        {

            var response  = new HttpResponseMessage(HttpStatusCode.OK) {
                                Content = new ByteArrayContent(ResponseBytes)
                            };

            response.Content.Headers.ContentType = new ("application/timestamp-reply");

            return Task.FromResult(response);

        }

    }


    private sealed class TimestampingHandler(TimeStampAuthority TimeStampAuthority) : HttpMessageHandler
    {

        protected override async Task<HttpResponseMessage>

            SendAsync(HttpRequestMessage  Request,
                      CancellationToken   CancellationToken)

        {

            var response  = new HttpResponseMessage(HttpStatusCode.OK) {

                                Content = new ByteArrayContent(
                                              TimeStampAuthority.Process(
                                                  await Request.Content!.ReadAsByteArrayAsync(CancellationToken)
                                              )
                                          )

                            };

            response.Content.Headers.ContentType = new ("application/timestamp-reply");

            return response;

        }

    }


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

}
