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
using System.Text;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    /// <summary>
    /// A TSTInfo (RFC 3161 §2.4.2) is the main content of a TimeStampToken and contains
    /// the actual time-stamp information, including the policy under which the time-stamp
    /// was issued, the message imprint (hash of the original data), the serial number,
    /// generation time, and optional fields such as accuracy, ordering, nonce, TSA name,
    /// and extensions.
    /// 
    ///  TSTInfo ::= SEQUENCE {
    ///      version         INTEGER  { v1(1) },
    ///      policy          TSAPolicyId,
    ///      messageImprint  MessageImprint,
    ///      serialNumber    INTEGER,
    ///      genTime         GeneralizedTime,
    ///      accuracy        Accuracy                 OPTIONAL,
    ///      ordering        BOOLEAN                  DEFAULT FALSE,
    ///      nonce           INTEGER                  OPTIONAL,
    ///      tsa         [0] GeneralName              OPTIONAL,
    ///      extensions  [1] IMPLICIT Extensions      OPTIONAL
    ///  }
    /// </summary>
    public sealed class TSTInfo
    {
        public int            Version        { get; }
        public string         Policy         { get; }
        public MessageImprint MessageImprint { get; }
        public BigInteger     SerialNumber   { get; }
        public DateTime       GenTime        { get; }
        public Accuracy?      Accuracy       { get; }
        public bool           Ordering       { get; }
        public BigInteger?    Nonce          { get; }
        /// <summary>If set, encoded verbatim as the EXPLICIT [0] TSA <c>GeneralName</c> field (already including its tag).</summary>
        public byte[]?        TsaGeneralName { get; }
        public IReadOnlyList<TSP_Extension> Extensions { get; }

        public TSTInfo(
            string         policy,
            MessageImprint messageImprint,
            BigInteger     serialNumber,
            DateTime       genTime,
            Accuracy?      accuracy       = null,
            bool           ordering       = false,
            BigInteger?    nonce          = null,
            byte[]?        tsaGeneralName = null,
            int            version        = 1,
            IEnumerable<TSP_Extension>? extensions = null)
        {
            Version        = version;
            Policy         = policy;
            MessageImprint = messageImprint;
            SerialNumber   = serialNumber;
            GenTime        = genTime.Kind == DateTimeKind.Utc ? genTime : genTime.ToUniversalTime();
            Accuracy       = accuracy;
            Ordering       = ordering;
            Nonce          = nonce;
            TsaGeneralName = tsaGeneralName;
            Extensions     = extensions?.ToArray() ?? [];
        }

        public byte[] Encode()
        {
            var w = new Asn1Writer();
            Encode(w);
            return w.ToArray();
        }

        public void Encode(Asn1Writer w)
        {
            using (w.PushSequence())
            {
                w.WriteInteger(Version);
                w.WriteOid(Policy);
                MessageImprint.Encode(w);
                w.WriteIntegerUnsigned(SerialNumber);
                w.WriteGeneralizedTime(GenTime);
                Accuracy?.Encode(w);
                if (Ordering) w.WriteBoolean(true); // DEFAULT FALSE
                if (Nonce is BigInteger n) w.WriteIntegerUnsigned(n);
                if (TsaGeneralName is not null)
                {
                    using (w.PushExplicit(0))
                        w.WriteEncoded(TsaGeneralName);
                }
                TSP_Extension.EncodeImplicit(w, 1, Extensions);
            }
        }

        public static TSTInfo Decode(ReadOnlySpan<byte> der)
        {

            var r = new Asn1Reader(der);
            var seq = r.ReadSequence();
            if (r.HasMore)
                throw new InvalidDataException("Trailing data after TSTInfo.");

            int version = (int)seq.ReadInteger();
            string policy = seq.ReadOid();
            var mi = MessageImprint.Decode(ref seq);
            var serial = new BigInteger(seq.ReadIntegerBytes(), isUnsigned: false, isBigEndian: true);
            var gen = seq.ReadGeneralizedTime();

            Accuracy? acc = null;
            bool ordering = false;
            BigInteger? nonce = null;
            byte[]? tsaGeneralName = null;
            IReadOnlyList<TSP_Extension> extensions = [];

            while (seq.HasMore)
            {
                byte tag = seq.PeekTag();

                if (tag == Asn1Writer.TagSequence)
                {
                    // Accuracy jetzt vollständig parsen
                    acc = Accuracy.Decode(ref seq);
                }
                else if (tag == Asn1Writer.TagBoolean)
                {
                    ordering = seq.ReadBoolean();
                }
                else if (tag == Asn1Writer.TagInteger)
                {
                    nonce = seq.ReadInteger();
                }
                else if (tag == 0xA0) // [0] EXPLICIT GeneralName (TSA)
                {
                    var tlv = seq.ReadAny();
                    tsaGeneralName = tlv.Content.ToArray(); // Roh-Bytes für spätere Verwendung
                }
                else if (tag == 0xA1) // [1] IMPLICIT Extensions
                {
                    extensions = TSP_Extension.DecodeImplicit(ref seq, 1);
                }
                else
                {
                    throw new InvalidDataException($"Unexpected tag 0x{tag:X2} in TSTInfo.");
                }
            }

            return new TSTInfo(
                policy: policy,
                messageImprint: mi,
                serialNumber: serial,
                genTime: gen,
                accuracy: acc,
                ordering: ordering,
                nonce: nonce,
                tsaGeneralName: tsaGeneralName,
                version: version,
                extensions: extensions);
        }


        /// <summary>
        /// Schöne, lesbare Darstellung für Debugging und Logging.
        /// </summary>
        public override string ToString()
        {

            var sb = new StringBuilder();

            sb.Append("TSTInfo [");
            sb.Append(GenTime.ToString("yyyy-MM-dd HH:mm:ss.fff"));
            sb.Append(" UTC]");

            sb.Append(" | Serial: ").Append(SerialNumber);

            // Policy
            if (!string.IsNullOrEmpty(Policy) && Policy != OIDMap.DefaultTsaPolicy)
                sb.Append(" | Policy: ").Append(Policy);

            // MessageImprint (kurz)
            sb.Append(" | Hash: ")
              .Append(MessageImprint.HashAlgorithm.Algorithm.Split('.').Last())
              .Append('(')
              .Append(Convert.ToHexString(MessageImprint.HashedMessage.AsSpan(0, Math.Min(8, MessageImprint.HashedMessage.Length))))
              .Append("...)");

            // Accuracy
            if (Accuracy is not null)
                sb.Append(" | ").Append(Accuracy);

            // Ordering
            if (Ordering)
                sb.Append(" | Ordering: true");

            // Nonce
            if (Nonce is BigInteger n)
                sb.Append(" | Nonce: ").Append(n);

            // TSA Name (falls vorhanden)
            if (TsaGeneralName is not null && TsaGeneralName.Length > 0)
                sb.Append(" | TSA: [present]");

            sb.Append(" | Version: ").Append(Version);

            return sb.ToString();
        }

    }

}
