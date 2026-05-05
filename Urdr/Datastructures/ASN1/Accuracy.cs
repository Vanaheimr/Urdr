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

using System.Text;
using System.Numerics;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Asn1
{

    /// <summary>
    /// The Accuracy field (RFC 3161 §2.4.2) indicates the accuracy of the time source.
    /// It is an optional field that can contain up to three components:
    /// seconds, milliseconds, and microseconds.
    /// 
    /// The Accuracy field allows a TimeStamp Authority (TSA) to specify the
    /// precision of the time it provides, which can be important for
    /// applications that require high-precision timestamps.
    /// </summary>
    public sealed class Accuracy
    {

        public Int32?  Seconds         { get; }
        public Int32?  Milliseconds    { get; }
        public Int32?  Microseconds    { get; }

        public Accuracy(Int32?  Seconds        = null,
                        Int32?  Milliseconds   = null,
                        Int32?  Microseconds   = null)
        {

            if (Milliseconds is Int32 ms && (ms < 1 || ms > 999)) 
                throw new ArgumentOutOfRangeException(nameof(Milliseconds));

            if (Microseconds is Int32 µs && (µs < 1 || µs > 999)) 
                throw new ArgumentOutOfRangeException(nameof(Microseconds));

            this.Seconds       = Seconds;
            this.Milliseconds  = Milliseconds;
            this.Microseconds  = Microseconds;

        }

        public void Encode(Asn1Writer ASN1Writer)
        {
            using (ASN1Writer.PushSequence())
            {
                if (Seconds      is Int32  s) ASN1Writer.WriteInteger(s);
                if (Milliseconds is Int32 ms) WriteImplicitInteger(ASN1Writer, 0x80, ms);
                if (Microseconds is Int32 µs) WriteImplicitInteger(ASN1Writer, 0x81, µs);
            }
        }

        public static Accuracy Decode(ref Asn1Reader reader)
        {

            var seq = reader.ReadSequence();

            Int32? seconds       = null;
            Int32? milliseconds  = null;
            Int32? microseconds  = null;

            while (seq.HasMore)
            {

                var tag = seq.PeekTag();

                if (tag == Asn1Writer.TagInteger)
                    seconds       = (Int32) seq.ReadInteger();

                // [0] IMPLICIT INTEGER (milliseconds)
                else if (tag == 0x80)
                {
                    var tlv = seq.ReadAny();
                    milliseconds  = (Int32) new BigInteger(
                                                tlv.Content,
                                                isUnsigned:  false,
                                                isBigEndian: true
                                            );
                }

                // [1] IMPLICIT INTEGER (microseconds)
                else if (tag == 0x81)
                {
                    var tlv = seq.ReadAny();
                    microseconds  = (Int32) new BigInteger(
                                                tlv.Content,
                                                isUnsigned:  false,
                                                isBigEndian: true
                                            );
                }

                // Skipping unknown tags, as per RFC 3161 §2.4.2:
                // If the Accuracy field contains any other components, they MUST be ignored!
                else
                    _ = seq.ReadAny();

            }

            return new Accuracy(
                       seconds,
                       milliseconds,
                       microseconds
                   );

        }




        private static void WriteImplicitInteger(Asn1Writer w, byte implicitTag, int value)
        {
            var tmp = new Asn1Writer();
            tmp.WriteInteger(value);
            var encoded = tmp.ToArray();
            w.WriteRawTlv(implicitTag, ExtractContent(encoded));
        }

        private static ReadOnlySpan<byte> ExtractContent(ReadOnlySpan<byte> tlv)
        {
            int p = 1; // Tag überspringen
            byte first = tlv[p++];
            int len = first < 0x80 ? first : ReadLength(tlv, ref p);
            return tlv.Slice(p, len);
        }

        private static int ReadLength(ReadOnlySpan<byte> tlv, ref int pos)
        {
            byte first = tlv[pos - 1]; // der Längen-Byte
            int n = first & 0x7F;
            int len = 0;
            for (int i = 0; i < n; i++)
                len = (len << 8) | tlv[pos++];
            return len;
        }



        public override string ToString()
        {
            if (Seconds is null && Milliseconds is null && Microseconds is null)
                return "Accuracy: unspecified";

            var sb = new StringBuilder("Accuracy: ");

            bool first = true;

            if (Seconds is int s)
            {
                sb.Append(s).Append("s");
                first = false;
            }

            if (Milliseconds is int ms)
            {
                if (!first) sb.Append(' ');
                sb.Append(ms).Append("ms");
                first = false;
            }

            if (Microseconds is int us)
            {
                if (!first) sb.Append(' ');
                sb.Append(us).Append("µs");
            }

            return sb.ToString();

        }

    }

}
