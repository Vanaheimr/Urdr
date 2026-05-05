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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using org.GraphDefined.Vanaheimr.Urdr.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

internal sealed class TestCertificate : IDisposable
{
    public X509Certificate2 Certificate { get; }
    public AsymmetricAlgorithm PrivateKey { get; }
    public CertificateInfo Info { get; }

    private TestCertificate(X509Certificate2 certificate, AsymmetricAlgorithm privateKey)
    {
        Certificate = certificate;
        PrivateKey = privateKey;
        Info = CertificateInfo.Parse(certificate.RawData);
    }

    public static TestCertificate CreateRsa()
    {
        var rsa = RSA.Create(2048);
        return new TestCertificate(CreateCertificate(rsa), rsa);
    }

    public static TestCertificate CreateEcdsa()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new TestCertificate(CreateCertificate(ecdsa), ecdsa);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa)
    {
        var request = new CertificateRequest(
            "CN=Unit Test TSA, O=OpenChargingCloud, C=DE",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        AddTsaExtensions(request);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateCertificate(ECDsa ecdsa)
    {
        var request = new CertificateRequest(
            "CN=Unit Test TSA, O=OpenChargingCloud, C=DE",
            ecdsa,
            HashAlgorithmName.SHA256);

        AddTsaExtensions(request);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private static void AddTsaExtensions(CertificateRequest request)
    {
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.8", "Time Stamping") },
                critical: true));
    }

    public void Dispose()
    {
        Certificate.Dispose();
        PrivateKey.Dispose();
    }
}
