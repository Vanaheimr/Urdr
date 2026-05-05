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
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

[TestFixture]
public sealed class TimeStampAuthorityTests
{

    [Test]
    public void Process_Rejects_UnsupportedHashLength()
    {

        using var cert = TestCertificate.CreateRsa();

        var tsa       = new TimeStampAuthority(
                            cert.Info,
                            cert.PrivateKey
                        );

        var request   = new TimeStampRequest(
                            new MessageImprint(
                                AlgorithmIdentifier.Sha256,
                                [1, 2, 3] // Should be 32 bytes for SHA-256, but is only 3 bytes here!
                            ),
                            certReq: true
                        );

        var response  = TimeStampResponse.Decode(
                            tsa.Process(
                                request.Encode()
                            )
                        );

        Assert.Multiple(() => {
            Assert.That(response.Status.Status,      Is.EqualTo(PKI_Status.Rejection));
            Assert.That(response.Status.FailureInfo, Is.EqualTo(PKI_FailureInfo.BadAlg));
            Assert.That(response.TimeStampToken,     Is.Null);
        });

    }

    [Test]
    public void Process_Rejects_RequestWithUnknownExtension()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var request = new TimeStampRequest(
            TimeStampRequest.ForData([1, 2, 3]).MessageImprint,
            nonce: new BigInteger(123456789),
            certReq: true,
            extensions:
            [
                new TSP_Extension("1.2.3.4.5.999", IsCritical: false, Value: [0x05, 0x00])
            ]);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));

        Assert.Multiple(() => {
            Assert.That(response.Status.Status, Is.EqualTo(PKI_Status.Rejection));
            Assert.That(response.Status.FailureInfo, Is.EqualTo(PKI_FailureInfo.UnacceptedExtension));
            Assert.That(response.TimeStampToken, Is.Null);
        });

    }

    [Test]
    public void Process_WithoutRequestedPolicy_UsesDefaultPolicy()
    {

        using var cert  = TestCertificate.CreateRsa();

        var tsa         = new TimeStampAuthority(
                              cert.Info,
                              cert.PrivateKey,
                              policyOid:           "1.3.6.1.4.1.99999.1.10",
                              acceptedPolicyOids:  [
                                                       "1.3.6.1.4.1.99999.1.10",
                                                       "1.3.6.1.4.1.99999.1.11"
                                                   ]
                          );

        var request     = TimeStampRequest. ForData([1, 2, 3], certReq: true);
        var response    = TimeStampResponse.Decode (tsa.Process(request.Encode()));
        var tstInfo     = response.Verify(cert.Certificate);

        Assert.That(
            tstInfo.Policy,
            Is.EqualTo("1.3.6.1.4.1.99999.1.10")
        );

    }

    [Test]
    public void Process_WithAcceptedRequestedPolicy_UsesRequestedPolicy()
    {
        using var cert = TestCertificate.CreateRsa();
        var requestedPolicy = "1.3.6.1.4.1.99999.1.11";
        var tsa = new TimeStampAuthority(
            cert.Info,
            cert.PrivateKey,
            policyOid: "1.3.6.1.4.1.99999.1.10",
            acceptedPolicyOids:
            [
                "1.3.6.1.4.1.99999.1.10",
                requestedPolicy
            ]);

        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true, policy: requestedPolicy);
        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.Multiple(() =>
        {
            Assert.That(response.Status.Status, Is.EqualTo(PKI_Status.Granted));
            Assert.That(tstInfo.Policy, Is.EqualTo(requestedPolicy));
        });
    }

    [Test]
    public void Process_WithUnknownRequestedPolicy_RejectsRequest()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(
            cert.Info,
            cert.PrivateKey,
            policyOid: "1.3.6.1.4.1.99999.1.10",
            acceptedPolicyOids:
            [
                "1.3.6.1.4.1.99999.1.10",
                "1.3.6.1.4.1.99999.1.11"
            ]);

        var request = TimeStampRequest.ForData(
            [1, 2, 3],
            certReq: true,
            policy: "1.3.6.1.4.1.99999.1.99");
        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));

        Assert.Multiple(() =>
        {
            Assert.That(response.Status.Status, Is.EqualTo(PKI_Status.Rejection));
            Assert.That(response.Status.FailureInfo, Is.EqualTo(PKI_FailureInfo.UnacceptedPolicy));
            Assert.That(response.TimeStampToken, Is.Null);
        });
    }

    [Test]
    public void Process_DefaultPolicyIsAlwaysAccepted()
    {
        using var cert = TestCertificate.CreateRsa();
        var defaultPolicy = "1.3.6.1.4.1.99999.1.10";
        var tsa = new TimeStampAuthority(
            cert.Info,
            cert.PrivateKey,
            policyOid: defaultPolicy,
            acceptedPolicyOids: []);

        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true, policy: defaultPolicy);
        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.That(tstInfo.Policy, Is.EqualTo(defaultPolicy));
    }

    [Test]
    public void Process_WithRsaCertificate_TimestampsByteBlobAndVerifiesEndToEnd()
    {
        using var cert = TestCertificate.CreateRsa();
        var payload = Enumerable.Range(0, 4096)
            .Select(i => (byte)((i * 31 + 7) & 0xFF))
            .ToArray();

        AssertTimestampEndToEnd(cert, payload);
    }

    [Test]
    public void Process_WithEcdsaCertificate_TimestampsByteBlobAndVerifiesEndToEnd()
    {
        using var cert = TestCertificate.CreateEcdsa();
        var payload = Enumerable.Range(0, 4096)
            .Select(i => (byte)((i * 17 + 19) & 0xFF))
            .ToArray();

        AssertTimestampEndToEnd(cert, payload);
    }

    [Test]
    public void Process_WithEcdsaCertificate_ProducesCmsTokenAcceptedBySignedCms()
    {
        using var cert = TestCertificate.CreateEcdsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);
        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));

        var signedCms = new SignedCms();
        signedCms.Decode(response.TimeStampToken!);

        Assert.That(
            () => signedCms.CheckSignature(
                [ cert.Certificate ],
                verifySignatureOnly: true),
            Throws.Nothing);
    }

    [Test]
    public void Process_IncludesTsaDirectoryNameByDefault()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.That(tstInfo.TsaGeneralName, Is.Not.Null.And.Not.Empty);

        var generalName = new Asn1Reader(tstInfo.TsaGeneralName!);
        var directoryName = generalName.ReadExplicit(4);
        _ = directoryName.ReadSequence();

        Assert.That(generalName.HasMore, Is.False);
    }

    [Test]
    public void Process_CanOmitTsaDirectoryName()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey, tsaNameMode: TSA_NameMode.None);
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.That(tstInfo.TsaGeneralName, Is.Null);
    }

    [Test]
    public void Process_UsesDefaultAccuracy()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.Multiple(() =>
        {
            Assert.That(tstInfo.Accuracy, Is.Not.Null);
            Assert.That(tstInfo.Accuracy!.Seconds, Is.EqualTo(1));
            Assert.That(tstInfo.Accuracy.Milliseconds, Is.Null);
            Assert.That(tstInfo.Accuracy.Microseconds, Is.Null);
        });
    }

    [Test]
    public void Process_CanUseCustomAccuracy()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(
            cert.Info,
            cert.PrivateKey,
            accuracy: new Accuracy(Seconds: 2, Milliseconds: 500, Microseconds: 250));
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.Multiple(() =>
        {
            Assert.That(tstInfo.Accuracy, Is.Not.Null);
            Assert.That(tstInfo.Accuracy!.Seconds, Is.EqualTo(2));
            Assert.That(tstInfo.Accuracy.Milliseconds, Is.EqualTo(500));
            Assert.That(tstInfo.Accuracy.Microseconds, Is.EqualTo(250));
        });
    }

    [Test]
    public void Process_CanOmitAccuracy()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey, includeAccuracy: false);
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.That(tstInfo.Accuracy, Is.Null);
    }

    [Test]
    public void Process_DoesNotSetOrderingByDefault()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var request = TimeStampRequest.ForData([1, 2, 3], certReq: true);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.That(tstInfo.Ordering, Is.False);
    }

    [Test]
    public void Process_WithOrdering_SetsOrderingAndUsesStrictlyIncreasingGenTime()
    {
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey, ordering: true);

        var first = Timestamp(tsa, cert, [1, 2, 3]);
        var second = Timestamp(tsa, cert, [4, 5, 6]);
        var third = Timestamp(tsa, cert, [7, 8, 9]);

        Assert.Multiple(() =>
        {
            Assert.That(first.Ordering, Is.True);
            Assert.That(second.Ordering, Is.True);
            Assert.That(third.Ordering, Is.True);
            Assert.That(second.GenTime, Is.GreaterThan(first.GenTime));
            Assert.That(third.GenTime, Is.GreaterThan(second.GenTime));
        });
    }

    private static void AssertTimestampEndToEnd(TestCertificate cert, byte[] payload)
    {
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);
        var request = TimeStampRequest.ForData(payload, certReq: true, policy: OIDMap.DefaultTsaPolicy);

        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        var extractedTstInfoDer = response.ExtractTstInfoDer();
        var extractedTstInfo = TSTInfo.Decode(extractedTstInfoDer);
        var verifiedTstInfo = response.Verify(cert.Certificate);

        var signedCms = new SignedCms();
        signedCms.Decode(response.TimeStampToken!);
        signedCms.CheckSignature(new X509Certificate2Collection { cert.Certificate }, verifySignatureOnly: true);

        var expectedHash = SHA256.HashData(payload);
        var tokenContainsSignerCertificate = signedCms.Certificates
            .Cast<X509Certificate2>()
            .Any(x => x.RawData.SequenceEqual(cert.Certificate.RawData));

        Assert.Multiple(() =>
        {
            Assert.That(response.Status.Status, Is.EqualTo(PKI_Status.Granted));
            Assert.That(response.TimeStampToken, Is.Not.Null.And.Not.Empty);
            Assert.That(signedCms.ContentInfo.ContentType.Value, Is.EqualTo(OIDMap.IdCtTstInfo));
            Assert.That(tokenContainsSignerCertificate, Is.True);

            Assert.That(request.MessageImprint.HashedMessage, Is.EqualTo(expectedHash));
            Assert.That(extractedTstInfo.MessageImprint.HashedMessage, Is.EqualTo(expectedHash));
            Assert.That(verifiedTstInfo.MessageImprint.HashedMessage, Is.EqualTo(expectedHash));
            Assert.That(verifiedTstInfo.MessageImprint.HashAlgorithm.Algorithm, Is.EqualTo(OIDMap.Sha256));
            Assert.That(verifiedTstInfo.Nonce, Is.EqualTo(request.Nonce));
            Assert.That(verifiedTstInfo.Policy, Is.EqualTo(OIDMap.DefaultTsaPolicy));
            Assert.That(verifiedTstInfo.TsaGeneralName, Is.Not.Null.And.Not.Empty);
            Assert.That(verifiedTstInfo.Ordering, Is.False);
            Assert.That(verifiedTstInfo.SerialNumber.Sign, Is.Positive);
            Assert.That(verifiedTstInfo.GenTime, Is.EqualTo(DateTime.UtcNow).Within(TimeSpan.FromSeconds(10)));
        });
    }

    private static TSTInfo Timestamp(TimeStampAuthority tsa, TestCertificate cert, byte[] payload)
    {
        var request = TimeStampRequest.ForData(payload, certReq: true);
        var response = TimeStampResponse.Decode(tsa.Process(request.Encode()));
        return response.Verify(cert.Certificate);
    }
}
