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
using System.Security.Cryptography.X509Certificates;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    /// <summary>
    /// A TimeStampResult represents the result of a successful
    /// time-stamp token verification.
    /// </summary>
    public sealed class TimeStampResult
    {
        /// <summary>Das verifizierte TSTInfo mit allen Zeitstempel-Metadaten.</summary>
        public TSTInfo TstInfo { get; }

        /// <summary>Die vollständige (und bereits verifizierte) TimeStampResponse.</summary>
        public TimeStampResponse Response { get; }

        /// <summary>Der originale TimeStampRequest (für Debugging / Nonce-Überprüfung).</summary>
        public TimeStampRequest OriginalRequest { get; }

        /// <summary>Das Zertifikat, mit dem tatsächlich signiert wurde (aus dem CMS-Token).</summary>
        public X509Certificate2 SignerCertificate { get; }

        /// <summary>Die rohen DER-Bytes des TimeStampTokens (CMS SignedData).</summary>
        public byte[] TimeStampTokenBytes => Response.TimeStampToken!;

        /// <summary>Zeitstempel als DateTimeOffset (für einfachere Nutzung).</summary>
        public DateTimeOffset Timestamp => new DateTimeOffset(TstInfo.GenTime, TimeSpan.Zero);

        public TimeStampResult(
            TSTInfo tstInfo,
            TimeStampResponse response,
            TimeStampRequest originalRequest,
            X509Certificate2 signerCertificate)
        {
            TstInfo = tstInfo;
            Response = response;
            OriginalRequest = originalRequest;
            SignerCertificate = signerCertificate;
        }

        public override string ToString()
        {

            var sb = new StringBuilder();

            sb.Append("TimeStampResult [")
              .Append(Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"))
              .Append(" UTC]");

            // Seriennummer
            sb.Append(" | Serial: ").Append(TstInfo.SerialNumber);

            // Hash-Algorithmus + kurzer Hash
            var hashAlgo = TstInfo.MessageImprint.HashAlgorithm.Algorithm.Split('.').LastOrDefault() ?? "sha256";
            var hashHex = Convert.ToHexString(TstInfo.MessageImprint.HashedMessage.AsSpan(0, Math.Min(8, TstInfo.MessageImprint.HashedMessage.Length)));
            sb.Append(" | Hash: ").Append(hashAlgo).Append('(').Append(hashHex).Append("...)");

            // Accuracy (nutzt die neue schöne ToString() von Accuracy)
            if (TstInfo.Accuracy is not null)
                sb.Append(" | ").Append(TstInfo.Accuracy);

            // Ordering
            if (TstInfo.Ordering)
                sb.Append(" | Ordering: true");

            // Nonce (falls vorhanden)
            if (TstInfo.Nonce is BigInteger nonce)
                sb.Append(" | Nonce: ").Append(nonce);

            // Signer-Zertifikat
            sb.Append(" | Signed by: ")
              .Append(SignerCertificate.SubjectName.Name ?? SignerCertificate.Subject);

            // TSA-Name (falls vorhanden)
            if (TstInfo.TsaGeneralName is not null && TstInfo.TsaGeneralName.Length > 0)
                sb.Append(" | TSA: [present]");

            return sb.ToString();

        }

    }

}
