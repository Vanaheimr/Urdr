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

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Crypto
{

    public sealed class CmsSignedDataBuilder
    {

        //  Builds a CMS SignedData (RFC 5652) carrying a DER-encoded TSTInfo
        //  (RFC 3161 §2.4.2), suitable for use as a TimeStampToken.
        //
        //  Includes the SignedAttributes required by RFC 3161 §2.4.2:
        //      - id-contentType        = id-ct-TSTInfo
        //      - id-messageDigest      = SHA-256(eContent)
        //      - id-aa-signingCertificateV2  (RFC 5816)
        //
        //  The signature algorithm is RSA-SHA256.  The SignerIdentifier is
        //  IssuerAndSerialNumber.  Certificates field carries the TSA cert.


        private readonly CertificateInfo      _signerCert;
        private readonly AsymmetricAlgorithm  _signerKey;
        private readonly AlgorithmIdentifier  _digestAlgorithm;
        private readonly AlgorithmIdentifier  _signatureAlgorithm;

        public CmsSignedDataBuilder(
            CertificateInfo signerCert,
            AsymmetricAlgorithm signerKey,
            AlgorithmIdentifier? digestAlgorithm = null)
        {
            _signerCert = signerCert;
            _signerKey = signerKey;
            _digestAlgorithm = digestAlgorithm ?? AlgorithmIdentifier.Sha256;
            _signatureAlgorithm = GetSignatureAlgorithm(signerKey, _digestAlgorithm);
        }

        private static AlgorithmIdentifier GetSignatureAlgorithm(AsymmetricAlgorithm  Key,
                                                                 AlgorithmIdentifier  Digest)

            => Key switch {

                   RSA     => Digest.Algorithm switch {
                       OIDMap.Sha256  => AlgorithmIdentifier.Sha256WithRsa,
                       OIDMap.Sha384  => AlgorithmIdentifier.Sha384WithRsa,
                       OIDMap.Sha512  => AlgorithmIdentifier.Sha512WithRsa,
                       _            => AlgorithmIdentifier.Sha256WithRsa
                   },

                   ECDsa   => Digest.Algorithm switch {
                       OIDMap.Sha256  => AlgorithmIdentifier.EcdsaWithSha256,
                       OIDMap.Sha384  => AlgorithmIdentifier.EcdsaWithSha384,
                       OIDMap.Sha512  => AlgorithmIdentifier.EcdsaWithSha512,
                       _            => AlgorithmIdentifier.EcdsaWithSha256
                   },

                   //Ed25519          => AlgorithmIdentifier.Ed25519,
                   //Ed448            => AlgorithmIdentifier.Ed448,

                   _                => throw new NotSupportedException("Unsupported key type (only RSA and ECDSA are supported).")

            };


        public byte[] Build(byte[] tstInfoDer, bool includeCert)
        {
            var messageDigest = ComputeMessageDigest(tstInfoDer);
            byte[] signedAttrsForSignature = EncodeSignedAttributes(messageDigest, asSet: true);

            var signature = SignData(signedAttrsForSignature);

            byte[] signerInfo = EncodeSignerInfo(signedAttrsForSignature, signature);
            byte[] signedData = EncodeSignedData(tstInfoDer, signerInfo, includeCert);

            var w = new Asn1Writer();
            using (w.PushSequence())
            {
                w.WriteOid(OIDMap.IdSignedData);
                using (w.PushExplicit(0))
                    w.WriteEncoded(signedData);
            }
            return w.ToArray();
        }

        private byte[] ComputeMessageDigest(byte[] tstInfoDer)
            => _digestAlgorithm.Algorithm switch
            {
                OIDMap.Sha256 => SHA256.HashData(tstInfoDer),
                OIDMap.Sha384 => SHA384.HashData(tstInfoDer),
                OIDMap.Sha512 => SHA512.HashData(tstInfoDer),
                _ => throw new NotSupportedException("Unsupported digest algorithm.")
            };

        private byte[] SignData(byte[] data)
        {
            return _signerKey switch {
                RSA     rsa     => rsa.SignData(data, GetHashAlgorithmName(), RSASignaturePadding.Pkcs1),
                ECDsa   ecdsa   => ecdsa.SignData(data, GetHashAlgorithmName(), DSASignatureFormat.Rfc3279DerSequence),
                //Ed25519 ed25519 => ed25519.SignData(data),
                //Ed448   ed448   => ed448.SignData(data),
                _ => throw new NotSupportedException("Unsupported key type for signing.")
            };
        }

        private HashAlgorithmName GetHashAlgorithmName()
            => _digestAlgorithm.Algorithm switch
            {
                OIDMap.Sha256 => HashAlgorithmName.SHA256,
                OIDMap.Sha384 => HashAlgorithmName.SHA384,
                OIDMap.Sha512 => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

        // -------------------------------------------------------------------
        //  SignedAttributes
        //
        //  When signed:        SET (tag 0x31) of Attribute -- this is what we
        //                      DER-encode and pass to RSA.SignData.
        //  When emitted in
        //  SignerInfo:         IMPLICIT [0] -- same content, tag 0xA0.
        //
        //  We compute the SET form and, for the SignerInfo, simply rewrite the
        //  outermost tag from 0x31 to 0xA0 (DER lengths and content unchanged).
        // -------------------------------------------------------------------
        private byte[] EncodeSignedAttributes(byte[] messageDigest, bool asSet)
        {
            // Build ordered list of attributes.  RFC 5652 §5.4 mandates DER
            // ordering: SET OF means the elements are sorted by their DER
            // encoding.  For our three attributes the OIDs are distinct, so
            // ordering by OID OBJECT IDENTIFIER value is sufficient.
            var attrs = new List<byte[]>
            {
                EncodeAttribute_ContentType(),
                EncodeAttribute_MessageDigest(messageDigest),
                EncodeAttribute_SigningCertificateV2(),
            };

            attrs.Sort(static (a, b) => CompareDer(a, b));

            var w = new Asn1Writer();
            byte tag = asSet ? Asn1Writer.TagSet : (byte)0xA0;
            using (w.PushTag(tag))
            {
                foreach (var a in attrs) w.WriteEncoded(a);
            }
            return w.ToArray();
        }

        private static int CompareDer(byte[] x, byte[] y)
        {
            int n = Math.Min(x.Length, y.Length);
            for (int i = 0; i < n; i++)
            {
                int c = x[i].CompareTo(y[i]);
                if (c != 0) return c;
            }
            return x.Length.CompareTo(y.Length);
        }

        /// <summary>Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }</summary>
        private static byte[] EncodeAttribute(string oid, Action<Asn1Writer> writeSingleValue)
        {
            var w = new Asn1Writer();
            using (w.PushSequence())
            {
                w.WriteOid(oid);
                using (w.PushSet())
                    writeSingleValue(w);
            }
            return w.ToArray();
        }

        private static byte[] EncodeAttribute_ContentType() =>
            EncodeAttribute(OIDMap.ContentType, w => w.WriteOid(OIDMap.IdCtTstInfo));

        private static byte[] EncodeAttribute_MessageDigest(byte[] digest) =>
            EncodeAttribute(OIDMap.MessageDigest, w => w.WriteOctetString(digest));

        /// <summary>
        /// signingCertificateV2 (RFC 5816):
        ///   SigningCertificateV2 ::= SEQUENCE {
        ///       certs       SEQUENCE OF ESSCertIDv2,
        ///       policies    SEQUENCE OF PolicyInformation OPTIONAL
        ///   }
        ///   ESSCertIDv2 ::= SEQUENCE {
        ///       hashAlgorithm   AlgorithmIdentifier DEFAULT { id-sha256 },
        ///       certHash        OCTET STRING,
        ///       issuerSerial    IssuerSerial OPTIONAL
        ///   }
        ///   IssuerSerial ::= SEQUENCE {
        ///       issuer          GeneralNames,                   -- [4] directoryName
        ///       serialNumber    CertificateSerialNumber
        ///   }
        /// </summary>
        private byte[] EncodeAttribute_SigningCertificateV2()
        {
            return EncodeAttribute(OIDMap.IdAaSigningCertificateV2, w =>
            {
                using (w.PushSequence())            // SigningCertificateV2
                using (w.PushSequence())            // certs SEQUENCE OF ESSCertIDv2
                using (w.PushSequence())            // ESSCertIDv2
                {

                    // hashAlgorithm DEFAULT id-sha256 -> we explicitly emit it
                    AlgorithmIdentifier.Sha256.Encode(w);

                    // certHash OCTET STRING
                    w.WriteOctetString(_signerCert.CertHashSha256);

                    // issuerSerial IssuerSerial OPTIONAL
                    using (w.PushSequence())
                    {
                        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
                        using (w.PushSequence())
                        {
                            // GeneralName CHOICE: directoryName [4] EXPLICIT Name
                            using (w.PushExplicit(4))
                                w.WriteEncoded(_signerCert.IssuerDerSeq);
                        }
                        // serialNumber INTEGER
                        w.WriteRawTlv(Asn1Writer.TagInteger, _signerCert.SerialBytes);
                    }
                }
            });
        }

        // -------------------------------------------------------------------
        //  SignerInfo
        //
        //  SignerInfo ::= SEQUENCE {
        //    version              CMSVersion,                   -- INTEGER 1 (IssuerAndSerialNumber)
        //    sid                  SignerIdentifier,             -- CHOICE: IssuerAndSerialNumber
        //    digestAlgorithm      DigestAlgorithmIdentifier,    -- sha256
        //    signedAttrs      [0] IMPLICIT SignedAttributes OPTIONAL,
        //    signatureAlgorithm   SignatureAlgorithmIdentifier, -- rsaEncryption (or sha256WithRSAEncryption)
        //    signature            SignatureValue,               -- OCTET STRING
        //    unsignedAttrs    [1] IMPLICIT UnsignedAttributes OPTIONAL
        //  }
        // -------------------------------------------------------------------
        private byte[] EncodeSignerInfo(byte[] signedAttrsAsSet, byte[] signature)
        {
            var w = new Asn1Writer();
            using (w.PushSequence())
            {

                w.WriteInteger(1); // CMSVersion = 1 (IssuerAndSerialNumber)

                // sid: IssuerAndSerialNumber
                using (w.PushSequence())
                {
                    w.WriteEncoded(_signerCert.IssuerDerSeq);
                    w.WriteRawTlv(Asn1Writer.TagInteger, _signerCert.SerialBytes);
                }

                _digestAlgorithm.Encode(w);

                // signedAttrs [0] IMPLICIT  -- rewrite leading tag 0x31 -> 0xA0
                var implicitAttrs = (byte[])signedAttrsAsSet.Clone();
                implicitAttrs[0] = 0xA0;
                w.WriteEncoded(implicitAttrs);

                _signatureAlgorithm.Encode(w);

                // signature OCTET STRING
                w.WriteOctetString(signature);

            }
            return w.ToArray();
        }

        // -------------------------------------------------------------------
        //  SignedData
        //
        //  SignedData ::= SEQUENCE {
        //      version              CMSVersion,                  -- 3 when certificates present and SignerInfo v=1; we use 3
        //      digestAlgorithms     SET OF DigestAlgorithmIdentifier,
        //      encapContentInfo     EncapsulatedContentInfo,
        //      certificates     [0] IMPLICIT CertificateSet OPTIONAL,
        //      crls             [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        //      signerInfos          SET OF SignerInfo
        //  }
        // -------------------------------------------------------------------
        private byte[] EncodeSignedData(byte[] tstInfoDer, byte[] signerInfo, bool includeCert)
        {
            var w = new Asn1Writer();
            using (w.PushSequence())
            {
                // version: per RFC 5652 §5.1, = 3 when we have SignedAttributes
                // referencing eContentType != id-data and SignerInfo v=1.
                w.WriteInteger(3);

                // digestAlgorithms SET
                using (w.PushSet())                     // ← hier wird jetzt der gewählte Digest verwendet
                    _digestAlgorithm.Encode(w);

                // encapContentInfo
                using (w.PushSequence())
                {
                    w.WriteOid(OIDMap.IdCtTstInfo);
                    using (w.PushExplicit(0))
                        w.WriteOctetString(tstInfoDer);
                }

                // certificates [0] IMPLICIT  CertificateSet
                // (CertificateChoices CHOICE: certificate  Certificate -- DER bytes)
                if (includeCert)
                {
                    using (w.PushImplicitConstructed(0))
                        w.WriteEncoded(_signerCert.RawDer);
                }

                // signerInfos SET OF SignerInfo
                using (w.PushSet())
                    w.WriteEncoded(signerInfo);

            }

            return w.ToArray();

        }

    }

}
