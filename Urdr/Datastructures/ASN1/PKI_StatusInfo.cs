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

namespace org.GraphDefined.Vanaheimr.Urdr.Asn1
{

    //  PKIStatusInfo ::= SEQUENCE {
    //      status        PKIStatus,
    //      statusString  PKIFreeText     OPTIONAL,
    //      failInfo      PKIFailureInfo  OPTIONAL  -- BIT STRING
    //  }

    /// <summary>
    /// The PkiStatusInfo structure (RFC 3161 §2.4.2) contains the status of a time-stamp request or response.
    /// </summary>
    public sealed class PKI_StatusInfo
    {
        public PKI_Status      Status      { get; }
        public String?        StatusText  { get; }
        public PKI_FailureInfo FailureInfo { get; }

        public PKI_StatusInfo(PKI_Status status, String? text = null, PKI_FailureInfo fail = PKI_FailureInfo.None)
        {
            Status = status;
            StatusText = text;
            FailureInfo = fail;
        }

        public void Encode(Asn1Writer w)
        {
            using (w.PushSequence())
            {
                w.WriteInteger((int)Status);

                if (StatusText is not null)
                {
                    using (w.PushSequence()) // PKIFreeText ::= SEQUENCE OF UTF8String
                        w.WriteUtf8String(StatusText);
                }

                if (FailureInfo != PKI_FailureInfo.None)
                    WriteFailureBitString(w, (uint)FailureInfo);
            }
        }

        public static PKI_StatusInfo Decode(ref Asn1Reader r)
        {
            var inner = r.ReadSequence();
            var status = (PKI_Status)(int)inner.ReadInteger();
            string? text = null;
            PKI_FailureInfo fail = PKI_FailureInfo.None;
            while (inner.HasMore)
            {
                byte tag = inner.PeekTag();
                if (tag == Asn1Writer.TagSequence)
                {
                    var freeText = inner.ReadSequence();
                    if (freeText.HasMore) text = freeText.ReadAnyString();
                }
                else if (tag == Asn1Writer.TagBitString)
                {
                    var bs = inner.ReadAny();
                    fail = (PKI_FailureInfo)DecodeFailureBitString(bs.Content);
                }
                else
                {
                    _ = inner.ReadAny();
                }
            }
            return new PKI_StatusInfo(status, text, fail);
        }

        // ---- failureInfo BIT STRING helpers ----------------------------------
        private static void WriteFailureBitString(Asn1Writer w, uint bits)
        {
            // Determine highest set bit.
            int highest = -1;
            for (int i = 31; i >= 0; i--) if ((bits & (1u << i)) != 0) { highest = i; break; }
            if (highest < 0) { w.WriteBitString([], 0); return; }

            int byteCount = (highest / 8) + 1;
            var data = new byte[byteCount];
            for (int i = 0; i <= highest; i++)
                if ((bits & (1u << i)) != 0)
                {
                    // RFC 3161: bit n is bit n of the BIT STRING, with the leftmost
                    // (MS) bit being bit 0.  In DER BIT STRING, byte0.bit7 == bit 0.
                    int byteIdx = i / 8;
                    int bitIdx  = 7 - (i % 8);
                    data[byteIdx] |= (byte)(1 << bitIdx);
                }
            int unusedBits = (8 * byteCount) - (highest + 1);
            w.WriteBitString(data, unusedBits);
        }

        private static uint DecodeFailureBitString(ReadOnlySpan<byte> raw)
        {
            // raw[0] = number of unused bits in the last content octet.
            // Abstract bit n is at byte (n/8), MSB-first within the byte:
            //   byte index = n / 8
            //   bit mask   = 1 << (7 - (n % 8))
            if (raw.Length < 1) return 0;
            int unused = raw[0];
            var data   = raw[1..];
            uint bits  = 0;
            for (int b = 0; b < data.Length; b++)
            {
                for (int bi = 0; bi < 8; bi++) // bi == 0 reads MSB
                {
                    if (b == data.Length - 1 && bi >= 8 - unused) break;
                    int abstractBitIdx = b * 8 + bi;
                    if ((data[b] & (1 << (7 - bi))) != 0)
                        bits |= 1u << abstractBitIdx;
                }
            }
            return bits;
        }

    }

}
