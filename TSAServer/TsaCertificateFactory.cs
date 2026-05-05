// ---------------------------------------------------------------------------
//  Urdr - TsaCertificateFactory.cs
//  Generates or loads the TSA's signing certificate.
//
//  The certificate carries:
//    - keyUsage = digitalSignature
//    - extKeyUsage = id-kp-timeStamping (1.3.6.1.5.5.7.3.8), critical
//
//  We use .NET's CertificateRequest only to MINT the cert; everything else
//  in this project is hand-rolled ASN.1.
// ---------------------------------------------------------------------------

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Urdr.Crypto;

namespace TSA.Server;

public enum TsaKeyType
{
    Rsa3072,
    Rsa4096,
    EcdsaP256,   // secp256r1 – empfohlen für moderne TSA
    EcdsaP384,   // secp384r1
    EcdsaP521,   // secp521r1
    Eddsa25519,  // Ed25519
    Eddsa448     // Ed448
}

public static class TsaCertificateFactory
{

    /// <summary>
    /// Loads an existing PKCS#12 bundle from <paramref name="pfxPath"/> or
    /// generates a fresh self-signed RSA key/cert pair and writes it.
    /// </summary>
    public static (CertificateInfo Cert, AsymmetricAlgorithm Key)

        LoadOrCreate(String      pfxPath,
                     String?     password    = null,
                     String      subjectCn   = "Vanaheimr Test TSA",
                     TsaKeyType  keyType     = TsaKeyType.EcdsaP256,
                     TimeSpan?   validity    = null)

    {

        AsymmetricAlgorithm key;

        if (File.Exists(pfxPath))
        {

            var existing  = X509CertificateLoader.LoadPkcs12FromFile(
                                pfxPath,
                                password,
                                X509KeyStorageFlags.Exportable
                            );

            key           = (AsymmetricAlgorithm?) existing.GetRSAPrivateKey()
                                ?? existing.GetECDsaPrivateKey()
                                //?? existing.GetEd25519PrivateKey()
                                //?? existing.GetEd448PrivateKey()
                                ?? throw new InvalidOperationException("PFX enthält keinen unterstützten Private-Key.");

            return (CertificateInfo.Parse(existing.RawData), key);

        }

        CertificateRequest  req;

        var dn = new X500DistinguishedName($"CN={subjectCn}, O=Vanaheimr, C=DE");

        switch (keyType)
        {

            case TsaKeyType.Rsa3072:
            case TsaKeyType.Rsa4096:
                var rsa = RSA.Create(keyType == TsaKeyType.Rsa3072 ? 3072 : 4096);
                req = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                key = rsa;
                break;

            case TsaKeyType.EcdsaP256:
                var ecdsa256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                req = new CertificateRequest(dn, ecdsa256, HashAlgorithmName.SHA256);
                key = ecdsa256;
                break;

            case TsaKeyType.EcdsaP384:
                var ecdsa384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                req = new CertificateRequest(dn, ecdsa384, HashAlgorithmName.SHA384);
                key = ecdsa384;
                break;

            case TsaKeyType.EcdsaP521:
                var ecdsa521 = ECDsa.Create(ECCurve.NamedCurves.nistP521);
                req = new CertificateRequest(dn, ecdsa521, HashAlgorithmName.SHA512);
                key = ecdsa521;
                break;

            //case TsaKeyType.Eddsa25519:
            //    var ed25519 = Ed25519.Create();
            //    req = new CertificateRequest(dn, ed25519);
            //    key = ed25519;
            //    break;

            //case TsaKeyType.Eddsa448:
            //    var ed448 = Ed448.Create();
            //    req = new CertificateRequest(dn, ed448);
            //    key = ed448;
            //    break;

            default:
                throw new ArgumentOutOfRangeException(nameof(keyType));
        }



        // Basic constraints: CA=false
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        // Key usage: digital signature
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true));

        // Extended key usage: id-kp-timeStamping (critical, per RFC 3161 §2.3)
        var ekuOid = new Oid("1.3.6.1.5.5.7.3.8", "Time Stamping");
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ ekuOid ], critical: true));

        // Subject Key Identifier
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));

        var v = validity ?? TimeSpan.FromDays(365 * 5);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter  = notBefore.Add(v);
        var cert = req.CreateSelfSigned(notBefore, notAfter);

        var pfxBytes = cert.Export(X509ContentType.Pkcs12, password);
        File.WriteAllBytes(pfxPath, pfxBytes);

        var info2 = CertificateInfo.Parse(cert.RawData);
        return (info2, key);

    }

}
