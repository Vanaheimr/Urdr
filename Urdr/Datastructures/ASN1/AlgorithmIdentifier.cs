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

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

//  AlgorithmIdentifier ::= SEQUENCE {
//      algorithm   OBJECT IDENTIFIER,
//      parameters  ANY DEFINED BY algorithm OPTIONAL
//  }


    public sealed class AlgorithmIdentifier
    {

        public String Algorithm { get; }

        /// <summary>
        /// Pre-encoded DER for the parameters field; <c>null</c> = absent.
        /// </summary>
        public byte[]? RawParameters { get; }

        public AlgorithmIdentifier(string oid, byte[]? rawParameters = null)
        {
            Algorithm = oid;
            RawParameters = rawParameters;
        }

        // ── Hash-Algorithmen ─────────────────────────────────────────────────────────────────────────
        public static readonly AlgorithmIdentifier Sha256           = new (OIDMap.Sha256, NullParameters());
        public static readonly AlgorithmIdentifier Sha384           = new (OIDMap.Sha384, NullParameters());
        public static readonly AlgorithmIdentifier Sha512           = new (OIDMap.Sha512, NullParameters());

        // ── RSA-Signatur-Algorithmen ─────────────────────────────────────────────────────────────────
        public static readonly AlgorithmIdentifier Sha256WithRsa    = new (OIDMap.Sha256WithRsa, NullParameters());
        public static readonly AlgorithmIdentifier Sha384WithRsa    = new (OIDMap.Sha384WithRsa, NullParameters());
        public static readonly AlgorithmIdentifier Sha512WithRsa    = new (OIDMap.Sha512WithRsa, NullParameters());

        // ── ECDSA-Signatur ───────────────────────────────────────────────────────────────────────────
        // RFC 5754 §3.2: parameters field MUST be absent for ECDSA signature algorithms
        public static readonly AlgorithmIdentifier EcdsaWithSha256  = new (OIDMap.EcdsaWithSha256, null);
        public static readonly AlgorithmIdentifier EcdsaWithSha384  = new (OIDMap.EcdsaWithSha384, null);
        public static readonly AlgorithmIdentifier EcdsaWithSha512  = new (OIDMap.EcdsaWithSha512, null);

        // EdDSA-Signatur (keine Parameter)
        public static readonly AlgorithmIdentifier Ed25519          = new (OIDMap.Ed25519, null);
        public static readonly AlgorithmIdentifier Ed448            = new (OIDMap.Ed448,   null);

        // ── Basis-Algorithmen ────────────────────────────────────────────────────────────────────────────────
        public static readonly AlgorithmIdentifier RsaEncryption    = new (OIDMap.RsaEncryption, NullParameters());

        public static byte[] NullParameters()
        {
            var w = new Asn1Writer();
            w.WriteNull();
            return w.ToArray();
        }

        public void Encode(Asn1Writer w)
        {
            using (w.PushSequence())
            {
                w.WriteOid(Algorithm);
                if (RawParameters is not null) w.WriteEncoded(RawParameters);
            }
        }

        public static AlgorithmIdentifier Decode(ref Asn1Reader r)
        {

            var inner = r.ReadSequence();
            var oid   = inner.ReadOid();
            byte[]? raw = null;

            if (inner.HasMore)
            {
                // Re-encode the remaining TLV verbatim.
                var tlv = inner.ReadAny();
                var w = new Asn1Writer();
                w.WriteRawTlv(tlv.Tag, tlv.Content);
                raw = w.ToArray();
            }

            if (inner.HasMore)
                throw new InvalidDataException("Trailing data after AlgorithmIdentifier parameters.");

            return new AlgorithmIdentifier(oid, raw);

        }

    }

}
