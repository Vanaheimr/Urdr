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

using NUnit.Framework;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

[TestFixture]
public sealed class TSAClientTests
{
    [Test]
    public void TimestampAsync_Rejects_ResponseForDifferentMessageImprint()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var responseForDifferentData = tsa.Process(TimeStampRequest.ForData([9, 9, 9], certReq: true).Encode());

        using var httpClient = new HttpClient(new StaticResponseHandler(responseForDifferentData));
        using var client     = new TSAClient(httpClient, "https://tsa.example.test/", cert.Certificate);

        Assert.That(
            async () => await client.GetTimestamp([1, 2, 3]),
            Throws.InstanceOf<InvalidDataException>());
    }

    private sealed class StaticResponseHandler(byte[] responseBytes) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(responseBytes)
            };
            response.Content.Headers.ContentType = new("application/timestamp-reply");

            return Task.FromResult(response);
        }
    }
}
