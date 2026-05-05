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
using System.Globalization;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Asn1
{

    /// <summary>
    /// Cursor over a DER-encoded buffer.  All read operations advance the
    /// cursor and validate length boundaries.  Nested structures are walked
    /// by calling <see cref="ReadSequence"/> / <see cref="ReadSet"/> which
    /// return a sub-reader bounded by the inner content.
    /// </summary>
    public ref struct Asn1Reader
    {
        private readonly ReadOnlySpan<byte> _data;
        private int _pos;

        public Asn1Reader(ReadOnlySpan<byte> data) { _data = data; _pos = 0; }

        public bool HasMore => _pos < _data.Length;
        public int Position => _pos;
        public int Length   => _data.Length;
        public ReadOnlySpan<byte> Remaining => _data[_pos..];

        // ---- TLV header -------------------------------------------------------
        public byte PeekTag()
        {
            if (_pos >= _data.Length) throw new EndOfStreamException();
            return _data[_pos];
        }

        /// <summary>Read a TLV and return (tag, content) without recursing.</summary>
        public Asn1Tlv ReadAny()
        {
            if (_pos >= _data.Length) throw new EndOfStreamException();
            byte tag = _data[_pos++];
            if ((tag & 0x1F) == 0x1F)
                throw new NotSupportedException("Multi-byte tags are not supported.");
            int length = ReadLength();
            if (length > _data.Length - _pos)
                throw new InvalidDataException(
                    $"Asn1Reader: declared length {length} exceeds buffer (pos {_pos}, total {_data.Length}).");
            var content = _data.Slice(_pos, length);
            _pos += length;
            return new Asn1Tlv(tag, content);
        }

        public Asn1Tlv ReadExpected(byte expectedTag)
        {
            var tlv = ReadAny();
            if (tlv.Tag != expectedTag)
                throw new InvalidDataException(
                    $"Asn1Reader: expected tag 0x{expectedTag:X2}, got 0x{tlv.Tag:X2}.");
            return tlv;
        }

        public bool TryReadExpected(byte expectedTag, out Asn1Tlv tlv)
        {
            tlv = default;
            if (_pos >= _data.Length || _data[_pos] != expectedTag) return false;
            tlv = ReadAny();
            return true;
        }

        private int ReadLength()
        {
            if (_pos >= _data.Length) throw new EndOfStreamException();
            byte first = _data[_pos++];
            if (first < 0x80) return first;
            int n = first & 0x7F;
            if (n == 0) throw new InvalidDataException("DER forbids indefinite length.");
            if (n > 4) throw new InvalidDataException($"Length octets {n} > 4 not supported.");
            if (_pos + n > _data.Length) throw new EndOfStreamException();
            if (_data[_pos] == 0x00) throw new InvalidDataException("DER length is not minimally encoded.");
            int len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | _data[_pos++];
            if (len < 0x80) throw new InvalidDataException("DER length must use short form below 128 bytes.");
            if (len < 0) throw new InvalidDataException("Length overflow.");
            return len;
        }

        // ---- typed primitive reads -------------------------------------------
        public Asn1Reader ReadSequence()
            => new(ReadExpected(Asn1Writer.TagSequence).Content);

        public Asn1Reader ReadSet()
            => new(ReadExpected(Asn1Writer.TagSet).Content);

        public Asn1Reader ReadExplicit(int tagNumber)
            => new(ReadExpected((byte)(0xA0 | (tagNumber & 0x1F))).Content);

        public bool TryReadExplicit(int tagNumber, out Asn1Reader inner)
        {
            if (TryReadExpected((byte)(0xA0 | (tagNumber & 0x1F)), out var tlv))
            {
                inner = new Asn1Reader(tlv.Content);
                return true;
            }
            inner = default;
            return false;
        }

        public bool ReadBoolean()
        {
            var tlv = ReadExpected(Asn1Writer.TagBoolean);
            if (tlv.Content.Length != 1) throw new InvalidDataException("BOOLEAN length != 1.");
            if (tlv.Content[0] is not 0x00 and not 0xFF) throw new InvalidDataException("DER BOOLEAN must be 0x00 or 0xFF.");
            return tlv.Content[0] != 0x00;
        }

        public byte[] ReadOctetString()
            => ReadExpected(Asn1Writer.TagOctetString).Content.ToArray();

        public void ReadNull() => _ = ReadExpected(Asn1Writer.TagNull);

        public string ReadOid()
        {
            var tlv = ReadExpected(Asn1Writer.TagOid);
            return DecodeOidContent(tlv.Content);
        }

        public BigInteger ReadInteger()
        {
            var tlv = ReadExpected(Asn1Writer.TagInteger);
            ValidateIntegerContent(tlv.Content);
            return new BigInteger(tlv.Content, isUnsigned: false, isBigEndian: true);
        }

        public byte[] ReadIntegerBytes()
        {
            var content = ReadExpected(Asn1Writer.TagInteger).Content;
            ValidateIntegerContent(content);
            return content.ToArray();
        }

        public DateTime ReadGeneralizedTime()
        {
            var tlv = ReadExpected(Asn1Writer.TagGeneralizedTime);
            var s = Encoding.ASCII.GetString(tlv.Content);
            return ParseGeneralizedTime(s);
        }

        public string ReadAnyString()
        {
            var tlv = ReadAny();
            return Encoding.UTF8.GetString(tlv.Content);
        }

        // ---- helpers ---------------------------------------------------------
        public static string DecodeOidContent(ReadOnlySpan<byte> content)
        {
            if (content.Length == 0) throw new InvalidDataException("Empty OID.");
            var sb = new StringBuilder();
            int i = 0;

            ulong firstSubIdentifier = ReadBase128(content, ref i);
            ulong a;
            ulong b;
            if (firstSubIdentifier < 40)
            {
                a = 0;
                b = firstSubIdentifier;
            }
            else if (firstSubIdentifier < 80)
            {
                a = 1;
                b = firstSubIdentifier - 40;
            }
            else
            {
                a = 2;
                b = firstSubIdentifier - 80;
            }

            sb.Append(a).Append('.').Append(b);

            while (i < content.Length)
            {
                var arc = ReadBase128(content, ref i);
                sb.Append('.').Append(arc.ToString(CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }

        private static ulong ReadBase128(ReadOnlySpan<byte> content, ref int pos)
        {
            ulong value = 0;
            var sawByte = false;

            while (pos < content.Length)
            {
                var b = content[pos++];
                sawByte = true;

                if (value > (ulong.MaxValue >> 7))
                    throw new InvalidDataException("OID arc overflow.");

                value = (value << 7) | (uint)(b & 0x7F);
                if ((b & 0x80) == 0)
                    return value;
            }

            if (!sawByte)
                throw new InvalidDataException("Empty OID arc.");

            throw new InvalidDataException("OID arc is not terminated.");
        }

        private static void ValidateIntegerContent(ReadOnlySpan<byte> content)
        {
            if (content.Length == 0)
                throw new InvalidDataException("INTEGER has empty content.");

            if (content.Length > 1 &&
                ((content[0] == 0x00 && (content[1] & 0x80) == 0) ||
                 (content[0] == 0xFF && (content[1] & 0x80) != 0)))
            {
                throw new InvalidDataException("DER INTEGER is not minimally encoded.");
            }
        }

        public static DateTime ParseGeneralizedTime(string s)
        {
            // accept YYYYMMDDHHMMSS[.fffffff]Z and normalize to UTC.
            if (!s.EndsWith('Z'))
                throw new InvalidDataException($"GeneralizedTime not in UTC: '{s}'.");
            if (s.Contains(','))
                throw new InvalidDataException($"GeneralizedTime must use '.' as fraction separator: '{s}'.");

            string[] formats = ["yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.FFFFFFF'Z'"];
            var dt = DateTime.ParseExact(s, formats, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
        }
    }

    /// <summary>One ASN.1 TLV triple (tag + content slice).</summary>
    public readonly ref struct Asn1Tlv
    {
        public byte Tag { get; }
        public ReadOnlySpan<byte> Content { get; }
        public Asn1Tlv(byte tag, ReadOnlySpan<byte> content) { Tag = tag; Content = content; }

        public bool IsConstructed => (Tag & 0x20) != 0;
        public int  TagClass      => (Tag >> 6) & 0x03;
        public int  TagNumber     => Tag & 0x1F;

    }

}
