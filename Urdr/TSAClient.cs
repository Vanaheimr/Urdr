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

using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    public sealed class TSAClient : IDisposable
    {

        public const String DefaultTsaUrl = "http://localhost:8080/";

        private readonly HttpClient        _httpClient;
        private readonly Boolean           _ownsHttpClient;
        private readonly X509Certificate2  _trustedTsaCertificate;
        private readonly String            _tsaUrl;
        private          Boolean           _disposed;

        public TSAClient(X509Certificate2 trustedTsaCertificate)
            : this(DefaultTsaUrl, trustedTsaCertificate)
        { }

        public TSAClient(String tsaUrl, X509Certificate2 trustedTsaCertificate)
        {
            _httpClient = new HttpClient();
            _ownsHttpClient = true;
            _tsaUrl = tsaUrl ?? throw new ArgumentNullException(nameof(tsaUrl));
            _trustedTsaCertificate = trustedTsaCertificate ?? throw new ArgumentNullException(nameof(trustedTsaCertificate));
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Urdr-Client/2.0");
        }

        public TSAClient(HttpClient httpClient, String tsaUrl, X509Certificate2 trustedTsaCertificate)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _ownsHttpClient = false;
            _tsaUrl = tsaUrl ?? throw new ArgumentNullException(nameof(tsaUrl));
            _trustedTsaCertificate = trustedTsaCertificate ?? throw new ArgumentNullException(nameof(trustedTsaCertificate));

            if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
            {
                _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Urdr-Client/2.0");
            }
        }




        /// <summary>
        /// Fordert einen Zeitstempel an (Standard: SHA-256).
        /// </summary>
        public async Task<TimeStampResult> GetTimestamp(
            byte[] data,
            string? policy = null,
            CancellationToken cancellationToken = default)
        {
            return await GetTimestamp(data, AlgorithmIdentifier.Sha256, policy, cancellationToken)
                       .ConfigureAwait(false);
        }

        /// <summary>
        /// Fordert einen Zeitstempel mit explizitem Hash-Algorithmus an.
        /// </summary>
        public async Task<TimeStampResult> GetTimestamp(
            byte[] data,
            AlgorithmIdentifier hashAlgorithm,
            string? policy = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentNullException.ThrowIfNull(hashAlgorithm);

            var request = TimeStampRequest.ForData(data, hashAlgorithm, certReq: true, policy: policy);
            return await SendAndVerify(request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Fordert einen Zeitstempel für eine Datei an.
        /// </summary>
        public async Task<TimeStampResult> GetFileTimestamp(
            string filePath,
            AlgorithmIdentifier? hashAlgorithm = null,
            string? policy = null,
            int bufferSize = 64 * 1024,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(filePath);

            hashAlgorithm ??= AlgorithmIdentifier.Sha256;

            await using var stream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            return await GetStreamTimestamp(stream, hashAlgorithm, policy, bufferSize, cancellationToken)
                             .ConfigureAwait(false);
        }


        /// <summary>
        /// Fordert einen Zeitstempel für einen Stream an, ohne den vollständigen Inhalt in den RAM zu laden.
        /// </summary>
        public async Task<TimeStampResult> GetStreamTimestamp(
            Stream data,
            AlgorithmIdentifier? hashAlgorithm = null,
            string? policy = null,
            int bufferSize = 64 * 1024,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(data);
            if (bufferSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(bufferSize));

            hashAlgorithm ??= AlgorithmIdentifier.Sha256;

            var digest  = await ComputeHash(data, hashAlgorithm, bufferSize, cancellationToken)
                                .ConfigureAwait(false);
            var request = new TimeStampRequest(
                              new MessageImprint(hashAlgorithm, digest),
                              policy,
                              TimeStampRequest.NewNonce(),
                              certReq: true);

            return await SendAndVerify(request, cancellationToken).ConfigureAwait(false);
        }






        /// <summary>
        /// Low-Level-Methode: Benutzerdefinierter Request + vollständiges Ergebnis.
        /// </summary>
        public async Task<TimeStampResult> SendAndVerify(
            TimeStampRequest request,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(request);

            byte[] requestBytes = request.Encode();

            using var content = new ByteArrayContent(requestBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

            var httpResponse = await _httpClient.PostAsync(_tsaUrl, content, cancellationToken)
                                                .ConfigureAwait(false);

            httpResponse.EnsureSuccessStatusCode();

            byte[] responseBytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken)
                                                             .ConfigureAwait(false);

            var tsResponse = TimeStampResponse.Decode(responseBytes);

            // Vollständige Verifikation (RSA + ECDSA)
            var tstInfo = tsResponse.Verify(_trustedTsaCertificate);
            ValidateResponseMatchesRequest(request, tstInfo);

            // Signer-Zertifikat aus dem CMS-Token extrahieren
            var signedCms = new SignedCms();
            signedCms.Decode(tsResponse.TimeStampToken!);
            var signerCert = signedCms.SignerInfos[0].Certificate
                             ?? throw new InvalidDataException("Kein Signer-Zertifikat im Token gefunden.");

            return new TimeStampResult(tstInfo, tsResponse, request, signerCert);
        }





        private static void ValidateResponseMatchesRequest(TimeStampRequest request, TSTInfo tstInfo)
        {
            if (tstInfo.MessageImprint.HashAlgorithm.Algorithm != request.MessageImprint.HashAlgorithm.Algorithm ||
                !tstInfo.MessageImprint.HashedMessage.SequenceEqual(request.MessageImprint.HashedMessage))
            {
                throw new InvalidDataException("TimeStampResponse passt nicht zum MessageImprint der Anfrage.");
            }

            if (request.Nonce != tstInfo.Nonce)
                throw new InvalidDataException("TimeStampResponse passt nicht zur Nonce der Anfrage.");

            if (request.ReqPolicy is not null && request.ReqPolicy != tstInfo.Policy)
                throw new InvalidDataException("TimeStampResponse passt nicht zur angefragten Policy.");

        }


        private static async Task<Byte[]> ComputeHash(
            Stream data,
            AlgorithmIdentifier hashAlgorithm,
            Int32 bufferSize,
            CancellationToken cancellationToken)
        {
            using var hash = IncrementalHash.CreateHash(GetHashAlgorithmName(hashAlgorithm));
            var buffer = ArrayPool<Byte>.Shared.Rent(bufferSize);

            try
            {
                while (true)
                {
                    var read = await data.ReadAsync(buffer.AsMemory(0, bufferSize), cancellationToken)
                                         .ConfigureAwait(false);

                    if (read == 0)
                        return hash.GetHashAndReset();

                    hash.AppendData(buffer, 0, read);
                }
            }
            finally
            {
                ArrayPool<Byte>.Shared.Return(buffer);
            }
        }


        private static HashAlgorithmName GetHashAlgorithmName(AlgorithmIdentifier hashAlgorithm)

            => hashAlgorithm.Algorithm switch {
                   OIDMap.Sha256  => HashAlgorithmName.SHA256,
                   OIDMap.Sha384  => HashAlgorithmName.SHA384,
                   OIDMap.Sha512  => HashAlgorithmName.SHA512,
                   _              => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Algorithm} is not supported!")
               };


        public void Dispose()
        {

            if (_disposed)
                return;

            if (_ownsHttpClient)
                _httpClient.Dispose();

            _trustedTsaCertificate.Dispose();

            _disposed = true;

        }

    }

}
