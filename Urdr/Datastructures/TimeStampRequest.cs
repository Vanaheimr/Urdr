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
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    /// <summary>
    /// A TimeStampRequest (RFC 3161 §2.4.1) is sent by a client to a TimeStamp
    /// Authority (TSA) to request a time-stamp token for a specific piece of data.
    /// 
    ///  TimeStampReq ::= SEQUENCE {
    ///      version          INTEGER  { v1(1) },
    ///      messageImprint   MessageImprint,
    ///      reqPolicy        TSAPolicyId               OPTIONAL,
    ///      nonce            INTEGER                   OPTIONAL,
    ///      certReq          BOOLEAN                   DEFAULT FALSE,
    ///      extensions   [0] IMPLICIT Extensions       OPTIONAL
    ///  }
    ///
    ///  TSAPolicyId ::= OBJECT IDENTIFIER
    /// </summary>
    public sealed class TimeStampRequest
    {
        public int             Version           { get; }
        public MessageImprint  MessageImprint    { get; }
        public string?         ReqPolicy         { get; }
        public BigInteger?     Nonce             { get; }
        public bool            CertReq           { get; }
        public IReadOnlyList<TSP_Extension> Extensions { get; }

        public TimeStampRequest(
            MessageImprint messageImprint,
            string?        reqPolicy = null,
            BigInteger?    nonce     = null,
            bool           certReq   = true,
            int            version   = 1,
            IEnumerable<TSP_Extension>? extensions = null)
        {
            Version        = version;
            MessageImprint = messageImprint;
            ReqPolicy      = reqPolicy;
            Nonce          = nonce;
            CertReq        = certReq;
            Extensions     = extensions?.ToArray() ?? [];
        }


        public static TimeStampRequest ForData(ReadOnlySpan<Byte>    Payload,
                                               AlgorithmIdentifier?  HashAlgorithm   = null,
                                               Boolean               certReq         = true,
                                               String?               policy          = null)
        {

            HashAlgorithm ??= AlgorithmIdentifier.Sha256;

            var hash   = ComputeHash(Payload, HashAlgorithm);
            var mi     = new MessageImprint(HashAlgorithm, hash);
            var nonce  = NewNonce();

            return new TimeStampRequest(
                       mi,
                       policy,
                       nonce,
                       certReq
                   );

        }

        private static Byte[] ComputeHash(ReadOnlySpan<Byte>   Payload,
                                          AlgorithmIdentifier  HashAlgorithm)

            => HashAlgorithm.Algorithm switch {
                   OIDMap.Sha256  => SHA256.HashData(Payload),
                   OIDMap.Sha384  => SHA384.HashData(Payload),
                   OIDMap.Sha512  => SHA512.HashData(Payload),
                   _            => throw new NotSupportedException($"Hash algorithm {HashAlgorithm.Algorithm} is not supported!")
               };


        public static BigInteger NewNonce()
        {
            Span<byte> buf = stackalloc byte[16];
            RandomNumberGenerator.Fill(buf);
            buf[0] &= 0x7F;
            return new BigInteger(buf, isUnsigned: false, isBigEndian: true);
        }

        public byte[] Encode()
        {
            var w = new Asn1Writer();
            using (w.PushSequence())
            {
                w.WriteInteger(Version);
                MessageImprint.Encode(w);
                if (ReqPolicy is not null) w.WriteOid(ReqPolicy);
                if (Nonce is BigInteger n) w.WriteIntegerUnsigned(n);
                if (CertReq) w.WriteBoolean(true);
                TSP_Extension.EncodeImplicit(w, 0, Extensions);
            }
            return w.ToArray();
        }

        public static TimeStampRequest Decode(ReadOnlySpan<byte> der)
        {

            var r        = new Asn1Reader(der);
            var seq      = r.ReadSequence();
            if (r.HasMore)
                throw new InvalidDataException("Trailing data after TimeStampReq.");

            int version  = (Int32) seq.ReadInteger();
            var mi       = MessageImprint.Decode(ref seq);

            string? policy = null;
            BigInteger? nonce = null;
            bool certReq = false;
            IReadOnlyList<TSP_Extension> extensions = [];

            while (seq.HasMore)
            {

                var tag = seq.PeekTag();

                switch (tag)
                {

                    case Asn1Writer.TagOid:
                        policy   = seq.ReadOid();
                        break;

                    case Asn1Writer.TagInteger:
                        nonce    = seq.ReadInteger();
                        break;

                    case Asn1Writer.TagBoolean:
                        certReq  = seq.ReadBoolean();
                        break;

                    default:

                        if (tag == 0xA0) {
                            extensions = TSP_Extension.DecodeImplicit(ref seq, 0);
                            break;
                        }
                        throw new InvalidDataException($"Unexpected tag 0x{tag:X2} in TimeStampReq.");

                }

            }

            return new TimeStampRequest(
                       mi,
                       policy,
                       nonce,
                       certReq,
                       version,
                       extensions
                    );

        }

    }

}
