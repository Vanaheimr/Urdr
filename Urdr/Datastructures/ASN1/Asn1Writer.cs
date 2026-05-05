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

    //  Implements the subset needed for RFC 3161 + RFC 5652 (CMS) + RFC 5816.


    /// <summary>
    /// Streaming DER writer.  Constructed types are opened with <c>PushXxx()</c>
    /// and closed by disposing the returned scope; the writer fixes up tag &amp;
    /// length automatically.  All primitive writers append a single TLV.
    /// </summary>
    public sealed class Asn1Writer
    {
        // ---- tag constants -----------------------------------------------------
        public const byte TagBoolean         = 0x01;
        public const byte TagInteger         = 0x02;
        public const byte TagBitString       = 0x03;
        public const byte TagOctetString     = 0x04;
        public const byte TagNull            = 0x05;
        public const byte TagOid             = 0x06;
        public const byte TagUtf8String      = 0x0C;
        public const byte TagPrintableString = 0x13;
        public const byte TagIA5String       = 0x16;
        public const byte TagUtcTime         = 0x17;
        public const byte TagGeneralizedTime = 0x18;
        public const byte TagSequence        = 0x30; // constructed
        public const byte TagSet             = 0x31; // constructed

        private readonly Stack<(byte Tag, List<byte> Buffer)> _stack = new();
        private List<byte> _current = new();

        // ---- output -----------------------------------------------------------
        public byte[] ToArray()
        {
            if (_stack.Count != 0)
                throw new InvalidOperationException(
                    $"Asn1Writer: {_stack.Count} unclosed constructed scope(s).");
            return [.. _current];
        }

        public int CurrentLength => _current.Count;

        // ---- raw / low level --------------------------------------------------
        public void WriteRawTlv(byte tag, ReadOnlySpan<byte> content)
        {
            _current.Add(tag);
            WriteLength(_current, content.Length);
            foreach (var b in content) _current.Add(b);
        }

        /// <summary>Append already-encoded DER bytes verbatim.</summary>
        public void WriteEncoded(ReadOnlySpan<byte> derBytes)
        {
            foreach (var b in derBytes) _current.Add(b);
        }

        private static void WriteLength(List<byte> dst, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            if (length < 0x80) { dst.Add((byte)length); return; }

            Span<byte> tmp = stackalloc byte[5];
            int n = 0;
            for (int v = length; v > 0; v >>= 8) tmp[n++] = (byte)(v & 0xFF);
            dst.Add((byte)(0x80 | n));
            for (int i = n - 1; i >= 0; i--) dst.Add(tmp[i]);
        }

        // ---- constructed scopes ----------------------------------------------
        public Scope PushSequence() => Push(TagSequence);
        public Scope PushSet()      => Push(TagSet);

        /// <summary>EXPLICIT [n] context-specific (constructed).</summary>
        public Scope PushExplicit(int tagNumber)
            => Push((byte)(0xA0 | (tagNumber & 0x1F)));

        /// <summary>IMPLICIT [n] context-specific, constructed primitive bit set.</summary>
        public Scope PushImplicitConstructed(int tagNumber)
            => Push((byte)(0xA0 | (tagNumber & 0x1F)));

        /// <summary>Generic constructed scope with arbitrary tag.</summary>
        public Scope PushTag(byte tag) => Push(tag);

        private Scope Push(byte tag)
        {
            _stack.Push((tag, _current));
            _current = new List<byte>();
            return new Scope(this);
        }

        private void Pop()
        {
            var (tag, parent) = _stack.Pop();
            var content = _current;
            parent.Add(tag);
            WriteLength(parent, content.Count);
            parent.AddRange(content);
            _current = parent;
        }

        public readonly struct Scope : IDisposable
        {
            private readonly Asn1Writer _w;
            public Scope(Asn1Writer w) { _w = w; }
            public void Dispose() => _w.Pop();
        }

        // ---- primitives -------------------------------------------------------
        public void WriteBoolean(bool v)
            => WriteRawTlv(TagBoolean, [v ? (byte)0xFF : (byte)0x00]);

        public void WriteNull() => WriteRawTlv(TagNull, []);

        public void WriteOctetString(ReadOnlySpan<byte> data) => WriteRawTlv(TagOctetString, data);

        public void WriteBitString(ReadOnlySpan<byte> data, int unusedBits = 0)
        {
            if (unusedBits is < 0 or > 7) throw new ArgumentOutOfRangeException(nameof(unusedBits));
            var buf = new byte[data.Length + 1];
            buf[0] = (byte)unusedBits;
            data.CopyTo(buf.AsSpan(1));
            WriteRawTlv(TagBitString, buf);
        }

        public void WriteUtf8String(string s)
            => WriteRawTlv(TagUtf8String, Encoding.UTF8.GetBytes(s));

        public void WritePrintableString(string s)
            => WriteRawTlv(TagPrintableString, Encoding.ASCII.GetBytes(s));

        public void WriteIA5String(string s)
            => WriteRawTlv(TagIA5String, Encoding.ASCII.GetBytes(s));

        /// <summary>RFC 5280: GeneralizedTime, "YYYYMMDDHHMMSS[.fffffff]Z".</summary>
        public void WriteGeneralizedTime(DateTime utc)
        {
            if (utc.Kind != DateTimeKind.Utc) utc = utc.ToUniversalTime();
            var s = utc.Ticks % TimeSpan.TicksPerSecond == 0
                ? utc.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"
                : utc.ToString("yyyyMMddHHmmss.FFFFFFF", CultureInfo.InvariantCulture) + "Z";
            WriteRawTlv(TagGeneralizedTime, Encoding.ASCII.GetBytes(s));
        }

        public void WriteUtcTime(DateTime utc)
        {
            if (utc.Kind != DateTimeKind.Utc) utc = utc.ToUniversalTime();
            var s = utc.ToString("yyMMddHHmmss", CultureInfo.InvariantCulture) + "Z";
            WriteRawTlv(TagUtcTime, Encoding.ASCII.GetBytes(s));
        }

        // ---- INTEGER ----------------------------------------------------------
        public void WriteInteger(long value)
        {
            // minimal two's-complement big-endian
            Span<byte> tmp = stackalloc byte[9];
            int n = 0;
            if (value >= 0)
            {
                do { tmp[n++] = (byte)(value & 0xFF); value >>= 8; } while (value != 0);
                if ((tmp[n - 1] & 0x80) != 0) tmp[n++] = 0x00; // pad to keep sign positive
            }
            else
            {
                do { tmp[n++] = (byte)(value & 0xFF); value >>= 8; } while (value != -1 || (tmp[n - 1] & 0x80) == 0);
            }
            Span<byte> reversed = stackalloc byte[n];
            for (int i = 0; i < n; i++) reversed[i] = tmp[n - 1 - i];
            WriteRawTlv(TagInteger, reversed);
        }

        /// <summary>Big-endian unsigned magnitude (e.g. cert serial number, RSA modulus).</summary>
        public void WriteIntegerUnsigned(ReadOnlySpan<byte> bigEndianMagnitude)
        {
            // strip leading zeros
            int start = 0;
            while (start < bigEndianMagnitude.Length - 1 && bigEndianMagnitude[start] == 0) start++;
            var trimmed = bigEndianMagnitude[start..];
            if (trimmed.Length == 0)
            {
                WriteRawTlv(TagInteger, [0x00]);
                return;
            }
            if ((trimmed[0] & 0x80) != 0)
            {
                // need leading 0x00 to keep value positive
                var buf = new byte[trimmed.Length + 1];
                buf[0] = 0x00;
                trimmed.CopyTo(buf.AsSpan(1));
                WriteRawTlv(TagInteger, buf);
            }
            else
            {
                WriteRawTlv(TagInteger, trimmed);
            }
        }

        public void WriteIntegerUnsigned(BigInteger value)
        {
            if (value.Sign < 0) throw new ArgumentOutOfRangeException(nameof(value));
            var be = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            WriteIntegerUnsigned(be);
        }

        // ---- OBJECT IDENTIFIER -----------------------------------------------
        public void WriteOid(string oid) => WriteRawTlv(TagOid, EncodeOidContent(oid));

        public static byte[] EncodeOidContent(string oid)
        {
            var parts = oid.Split('.');
            if (parts.Length < 2) throw new FormatException($"Invalid OID '{oid}'.");
            var arcs = new uint[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                if (!uint.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out arcs[i]))
                    throw new FormatException($"Invalid OID arc '{parts[i]}'.");
            }
            if (arcs[0] > 2) throw new FormatException("First OID arc must be 0, 1, or 2.");
            if (arcs[0] < 2 && arcs[1] >= 40) throw new FormatException("Second OID arc out of range.");

            var bytes = new List<byte>(parts.Length + 4);
            bytes.AddRange(EncodeBase128(arcs[0] * 40 + arcs[1]));
            for (int i = 2; i < arcs.Length; i++)
                bytes.AddRange(EncodeBase128(arcs[i]));
            return [.. bytes];
        }

        private static IEnumerable<byte> EncodeBase128(uint v)
        {
            Span<byte> tmp = stackalloc byte[5];
            int n = 0;
            do { tmp[n++] = (byte)(v & 0x7F); v >>= 7; } while (v != 0);
            var result = new byte[n];
            for (int i = 0; i < n; i++)
                result[i] = (byte)(tmp[n - 1 - i] | (i == n - 1 ? 0x00 : 0x80));
            return result;
        }

    }

}
