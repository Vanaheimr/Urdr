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

using System.Numerics;
using NUnit.Framework;
using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

[TestFixture]
public sealed class TimeStampRequestTests
{
    [Test]
    public void EncodeDecode_RoundTrips_OptionalFields()
    {
        var request = new TimeStampRequest(
            new MessageImprint(AlgorithmIdentifier.Sha384, Enumerable.Repeat((byte)0x42, 48).ToArray()),
            reqPolicy: "1.2.3.4.5",
            nonce: new BigInteger(123456789),
            certReq: true,
            extensions:
            [
                new TSP_Extension("1.2.3.4.5.6", IsCritical: true, Value: [0x05, 0x00])
            ]);

        var decoded = TimeStampRequest.Decode(request.Encode());

        Assert.Multiple(() =>
        {
            Assert.That(decoded.Version, Is.EqualTo(1));
            Assert.That(decoded.ReqPolicy, Is.EqualTo(request.ReqPolicy));
            Assert.That(decoded.Nonce, Is.EqualTo(request.Nonce));
            Assert.That(decoded.CertReq, Is.True);
            Assert.That(decoded.MessageImprint.HashAlgorithm.Algorithm, Is.EqualTo(OIDMap.Sha384));
            Assert.That(decoded.MessageImprint.HashedMessage, Is.EqualTo(request.MessageImprint.HashedMessage));
            Assert.That(decoded.Extensions, Has.Count.EqualTo(1));
            Assert.That(decoded.Extensions[0].Oid, Is.EqualTo("1.2.3.4.5.6"));
            Assert.That(decoded.Extensions[0].IsCritical, Is.True);
            Assert.That(decoded.Extensions[0].Value, Is.EqualTo(new byte[] { 0x05, 0x00 }));
        });
    }

    [Test]
    public void Decode_Rejects_TrailingBytes()
    {
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);
        var der = request.Encode();
        var withTrailingGarbage = der.Concat(new byte[] { 0x05, 0x00 }).ToArray();

        Assert.That(
            () => TimeStampRequest.Decode(withTrailingGarbage),
            Throws.InstanceOf<InvalidDataException>());
    }
}
