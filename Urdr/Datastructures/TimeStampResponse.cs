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

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    /// <summary>
    /// A TimeStampResponse (RFC 3161 §2.4.2) is sent by a TimeStamp Authority (TSA)
    /// in response to a TimeStampRequest.
    /// 
    ///  TimeStampResp ::= SEQUENCE {
    ///      status          PKIStatusInfo,
    ///      timeStampToken  TimeStampToken     OPTIONAL  -- ContentInfo (CMS)
    ///  }
    ///
    ///  TimeStampToken ::= ContentInfo
    ///      -- contentType is id-signedData
    ///      -- content is SignedData; eContent encapsulates DER(TSTInfo)
    /// </summary>
    public sealed class TimeStampResponse
    {
        public PKI_StatusInfo  Status            { get; }

        /// <summary>Pre-encoded DER bytes of the ContentInfo (TimeStampToken) or <c>null</c>.</summary>
        public Byte[]?        TimeStampToken    { get; }

        public TimeStampResponse(PKI_StatusInfo status, byte[]? token = null)
        {
            Status = status;
            TimeStampToken = token;
        }

        public byte[] Encode()
        {
            var w = new Asn1Writer();
            using (w.PushSequence())
            {
                Status.Encode(w);
                if (TimeStampToken is not null) w.WriteEncoded(TimeStampToken);
            }
            return w.ToArray();
        }

        public static TimeStampResponse Decode(ReadOnlySpan<byte> der)
        {

            var r      = new Asn1Reader(der);
            var seq    = r.ReadSequence();
            if (r.HasMore)
                throw new InvalidDataException("Trailing data after TimeStampResp.");

            var status = PKI_StatusInfo.Decode(ref seq);

            byte[]? token = null;
            if (seq.HasMore)
            {
                // Re-emit the remaining bytes verbatim as ContentInfo DER.
                var tlv = seq.ReadAny();
                var w = new Asn1Writer();
                w.WriteRawTlv(tlv.Tag, tlv.Content);
                token = w.ToArray();
            }

            return new TimeStampResponse(status, token);

        }

        /// <summary>
        /// Extract the DER-encoded TSTInfo from a <c>granted</c> response.
        /// </summary>
        public byte[] ExtractTstInfoDer()
        {

            if (TimeStampToken is null)
                throw new InvalidOperationException("No TimeStampToken.");

            // TimeStampToken is ContentInfo:
            //   SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
            //
            // SignedData ::= SEQUENCE {
            //   version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
            // }
            //
            // encapContentInfo:
            //   SEQUENCE { eContentType OID, [0] EXPLICIT OCTET STRING eContent }
            // eContent OCTET STRING wraps DER(TSTInfo).

            var ci = new Asn1Reader(TimeStampToken).ReadSequence();
            _ = ci.ReadOid();                       // id-signedData
            var content0 = ci.ReadExplicit(0);      // [0] EXPLICIT
            var sd = content0.ReadSequence();       // SignedData
            _ = sd.ReadInteger();                   // version
            _ = sd.ReadSet();                       // digestAlgorithms
            var eci = sd.ReadSequence();            // EncapsulatedContentInfo
            _ = eci.ReadOid();                      // id-ct-TSTInfo
            var eContent0 = eci.ReadExplicit(0);    // [0] EXPLICIT
            var os = eContent0.ReadAny();           // OCTET STRING

            if (os.Tag != Asn1Writer.TagOctetString)
                throw new InvalidDataException("eContent is not OCTET STRING.");

            return os.Content.ToArray();

        }

        /// <summary>
        /// Verifiziert die CMS-Signatur des TimeStampTokens **vollständig** (RFC 5652)
        /// inklusive Signatur, SignedAttributes, MessageDigest und SignerInfo.
        /// Wirft eine Ausnahme bei jedem Verifikationsfehler.
        /// </summary>
        /// <param name="trustedTsaCertificate">Das vertrauenswürdige TSA-Zertifikat (öffentlicher Teil).</param>
        /// <returns>Das verifizierte und geparste <see cref="TSTInfo"/>.</returns>
        public TSTInfo Verify(X509Certificate2 trustedTsaCertificate)
        {

            if (Status.Status != PKI_Status.Granted)
                throw new InvalidOperationException(
                    $"TSA hat die Anfrage abgelehnt: {Status.Status} – {Status.StatusText}");

            if (TimeStampToken is null)
                throw new InvalidOperationException("TimeStampResponse enthält kein TimeStampToken.");

            var signedCms = new SignedCms();
            signedCms.Decode(TimeStampToken);

            if (signedCms.SignerInfos.Count != 1)
                throw new InvalidDataException("Keine SignerInfo im TimeStampToken gefunden.");

            if (signedCms.ContentInfo.ContentType.Value != OIDMap.IdCtTstInfo)
                throw new InvalidDataException("Falscher ContentType – kein id-ct-TSTInfo.");

            var signerInfo = signedCms.SignerInfos[0];
            var certCollection = new X509Certificate2Collection { trustedTsaCertificate };
            signerInfo.CheckSignature(certCollection, verifySignatureOnly: true);

            if (signerInfo.Certificate is X509Certificate2 embeddedSigner &&
                !CertificateEquals(embeddedSigner, trustedTsaCertificate))
            {
                throw new InvalidDataException("TimeStampToken wurde nicht vom erwarteten TSA-Zertifikat signiert.");
            }

            var tstInfo = TSTInfo.Decode(signedCms.ContentInfo.Content);
            ValidateTsaCertificate(trustedTsaCertificate, tstInfo.GenTime);

            return tstInfo;

        }

        /// <summary>
        /// Nicht-werfende Variante – ideal für produktiven Code.
        /// </summary>
        public bool TryVerify(X509Certificate2                  trustedTsaCertificate,
                              [NotNullWhen(true)] out TSTInfo?  tstInfo,
                              out String?                       errorMessage)
        {

            tstInfo = null;
            errorMessage = null;

            try
            {
                tstInfo = Verify(trustedTsaCertificate);
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }

        }

        private static bool CertificateEquals(X509Certificate2 left, X509Certificate2 right)
        {
            Span<byte> leftHash = stackalloc byte[SHA256.HashSizeInBytes];
            Span<byte> rightHash = stackalloc byte[SHA256.HashSizeInBytes];

            if (!SHA256.TryHashData(left.RawData, leftHash, out var leftWritten) ||
                !SHA256.TryHashData(right.RawData, rightHash, out var rightWritten) ||
                leftWritten != SHA256.HashSizeInBytes ||
                rightWritten != SHA256.HashSizeInBytes)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(leftHash, rightHash);
        }

        private static void ValidateTsaCertificate(X509Certificate2 certificate, DateTime genTime)
        {
            var at = DateTime.SpecifyKind(genTime, DateTimeKind.Utc);
            if (at < certificate.NotBefore.ToUniversalTime() ||
                at > certificate.NotAfter.ToUniversalTime())
            {
                throw new InvalidDataException("TSA-Zertifikat war zum GenTime-Zeitpunkt nicht gültig.");
            }

            var eku = certificate.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .SingleOrDefault();

            if (eku is null)
                throw new InvalidDataException("TSA-Zertifikat enthält keine Extended-Key-Usage-Erweiterung.");

            if (!eku.Critical)
                throw new InvalidDataException("TSA-Zertifikat muss eine kritische Extended-Key-Usage-Erweiterung enthalten.");

            var hasTimeStampingEku = eku.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => oid.Value == OIDMap.EkuTimeStamping);

            if (!hasTimeStampingEku)
                throw new InvalidDataException("TSA-Zertifikat enthält nicht die Time-Stamping-EKU.");
        }

    }

}
