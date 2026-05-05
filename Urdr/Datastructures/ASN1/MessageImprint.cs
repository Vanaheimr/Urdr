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

    /// <summary>
    /// The MessageImprint field (RFC 3161 §2.4.1) contains
    /// the hash of the data being time-stamped.
    /// 
    ///   MessageImprint ::= SEQUENCE {
    ///       hashAlgorithm  AlgorithmIdentifier,
    ///       hashedMessage  OCTET STRING
    ///   }
    /// </summary>
    public sealed class MessageImprint
    {
        public AlgorithmIdentifier HashAlgorithm { get; }
        public byte[] HashedMessage { get; }

        public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage)
        {
            HashAlgorithm = hashAlgorithm;
            HashedMessage = hashedMessage;
        }

        public void Encode(Asn1Writer w)
        {
            using (w.PushSequence())
            {
                HashAlgorithm.Encode(w);
                w.WriteOctetString(HashedMessage);
            }
        }

        public static MessageImprint Decode(ref Asn1Reader r)
        {
            var inner  = r.ReadSequence();
            var alg    = AlgorithmIdentifier.Decode(ref inner);
            var hash   = inner.ReadOctetString();
            if (inner.HasMore)
                throw new InvalidDataException("Trailing data after MessageImprint.");

            return new MessageImprint(alg, hash);
        }

    }

}
