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

    //  Minimal X.509 dissector used to extract the bits we need for CMS:
    //    - issuer Name (raw DER, re-encoded SEQUENCE)
    //    - subject Name (raw DER, re-encoded SEQUENCE)
    //    - serial number INTEGER bytes
    //    - SHA-256 hash of the full DER certificate

    public sealed class CertificateInfo
    {
        public byte[] RawDer       { get; }
        public byte[] IssuerDerSeq { get; }   // full SEQUENCE DER of issuer Name
        public byte[] SubjectDerSeq { get; }  // full SEQUENCE DER of subject Name
        public byte[] SerialBytes  { get; }   // big-endian, signed (i.e. INTEGER content octets)
        public byte[] CertHashSha256 { get; }

        public CertificateInfo(byte[] rawDer, byte[] issuerDerSeq, byte[] subjectDerSeq, byte[] serialBytes)
        {
            RawDer = rawDer;
            IssuerDerSeq = issuerDerSeq;
            SubjectDerSeq = subjectDerSeq;
            SerialBytes = serialBytes;
            CertHashSha256 = SHA256.HashData(rawDer);
        }

        public static CertificateInfo Parse(byte[] derCert)
        {
            var r = new Asn1Reader(derCert);
            var cert = r.ReadSequence();        // Certificate
            var tbs  = cert.ReadSequence();     // TBSCertificate

            // [0] EXPLICIT Version DEFAULT v1  -- optional
            if (tbs.PeekTag() == 0xA0) _ = tbs.ReadAny();

            // serialNumber INTEGER
            var serialTlv = tbs.ReadExpected(Asn1Writer.TagInteger);
            var serial = serialTlv.Content.ToArray();

            // signature AlgorithmIdentifier
            _ = tbs.ReadSequence();

            // issuer Name -- this is where we re-emit the full SEQUENCE
            // We need the bytes including the outer SEQUENCE tag+length.
            // Trick: parse and re-encode using a fresh writer.
            var issuerTlv = tbs.ReadExpected(Asn1Writer.TagSequence);
            var w = new Asn1Writer();
            w.WriteRawTlv(Asn1Writer.TagSequence, issuerTlv.Content);
            var issuerDer = w.ToArray();

            // validity
            _ = tbs.ReadSequence();

            var subjectTlv = tbs.ReadExpected(Asn1Writer.TagSequence);
            var subjectWriter = new Asn1Writer();
            subjectWriter.WriteRawTlv(Asn1Writer.TagSequence, subjectTlv.Content);
            var subjectDer = subjectWriter.ToArray();

            return new CertificateInfo(derCert, issuerDer, subjectDer, serial);
        }

    }

}
