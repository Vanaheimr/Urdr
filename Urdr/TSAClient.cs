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
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Urdr.Asn1;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    /// <summary>
    /// The TSAClient requests and verifies timestamps from a Time Stamp Authority (TSA)
    /// using the Time-Stamp Protocol (TSP, RFC 3161).
    /// </summary>
    /// <remarks>
    /// The requests go through Hermod's HTTP client, which resolves the TSA's host name with
    /// the DNS client it is given - never with the resolver of the operating system, as the
    /// runtime's HttpClient did: an application that resolves its names securely, with name
    /// servers of its own, DNS over TLS or HTTPS and DNSSEC, must not be dialled around them.
    /// Without a DNS client, Hermod's client makes one of its own, which asks the name servers
    /// of the network configuration itself.
    /// </remarks>
    public class TSAClient : IDisposable
    {

        #region Data

        private readonly  HTTPClient        httpClient;
        private readonly  URL               remoteURL;
        private           Boolean           disposed;

        public const      String            DefaultHTTPUserAgent  = "Vanaheimr Urdr-Client/1.0";

        /// <summary>
        /// The media type of a time-stamp request (RFC 3161 §3.4).
        /// </summary>
        public static readonly HTTPContentType  TimeStampQuery  = HTTPContentType.TryParse("application/timestamp-query", out var contentType)
                                                                      ? contentType
                                                                      : throw new InvalidOperationException("application/timestamp-query is no media type?");

        #endregion

        #region Properties

        /// <summary>
        /// The URL of the Time Stamp Authority service endpoint.
        /// </summary>
        public String            RemoteURL                { get; }

        /// <summary>
        /// The trusted certificate of the Time Stamp Authority for verifying responses.
        /// </summary>
        public X509Certificate2  TrustedTSACertificate    { get; }

        /// <summary>
        /// The HTTP User-Agent to use.
        /// </summary>
        public String            HTTPUserAgent            { get; }

        /// <summary>
        /// The DNS client the TSA's host name is resolved with.
        /// </summary>
        public IDNSClient?       DNSClient                { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Time Stamp Authority client.
        /// </summary>
        /// <param name="RemoteURL">The URL of the Time Stamp Authority service endpoint (http:// or https://).</param>
        /// <param name="TrustedTSACertificate">The trusted certificate of the Time Stamp Authority for verifying responses.</param>
        /// <param name="DNSClient">The DNS client the TSA's host name is resolved with. Null makes Hermod's HTTP client use one of its own; the resolver of the operating system is never asked.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the TLS certificate of an https:// TSA; by default the system's chain validation.</param>
        /// <param name="HTTPUserAgent">An optional HTTP User-Agent.</param>
        public TSAClient(String                                                     RemoteURL,
                         X509Certificate2                                           TrustedTSACertificate,
                         IDNSClient?                                                DNSClient,
                         RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                         String                                                     HTTPUserAgent                = DefaultHTTPUserAgent)
        {

            this.RemoteURL              = RemoteURL;
            this.TrustedTSACertificate  = TrustedTSACertificate;
            this.HTTPUserAgent          = HTTPUserAgent;
            this.DNSClient              = DNSClient;

            this.remoteURL              = URL.TryParse(RemoteURL) ?? throw new ArgumentException($"'{RemoteURL}' is not a URL.", nameof(RemoteURL));

            this.httpClient             = new HTTPClient(
                                              this.remoteURL,
                                              HTTPUserAgent:               HTTPUserAgent,
                                              RemoteCertificateValidator:  RemoteCertificateValidator,
                                              DNSClient:                   DNSClient
                                          );

        }

        #endregion


        #region GetTimestamp       (Data,   HashAlgorithm = null, Policy = null, ...)

        /// <summary>
        /// Timestamp the given data.
        /// </summary>
        /// <param name="Data">The data to be timestamped.</param>
        /// <param name="HashAlgorithm">An optional hash algorithm to use (default: SHA-256).</param>
        /// <param name="Policy">An optional policy OID to include in the request.</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public async Task<TimeStampResult>

            GetTimestamp(Byte[]                Data,
                         AlgorithmIdentifier?  HashAlgorithm       = null,
                         String?               Policy              = null,
                         CancellationToken     CancellationToken   = default)

                => await SendAndVerify(
                             TimeStampRequest.ForData(
                                 Data,
                                 HashAlgorithm,
                                 certReq: true,
                                 policy:  Policy
                             ),
                             CancellationToken
                         ).ConfigureAwait(false);

        #endregion

        #region GetFileTimestamp   (Data,   HashAlgorithm = null, Policy = null, ...)

        /// <summary>
        /// Get a timestamp for a file, without loading the entire content into RAM.
        /// </summary>
        /// <param name="FilePath">The path to the file to be timestamped.</param>
        /// <param name="HashAlgorithm">An optional hash algorithm to use (default: SHA-256).</param>
        /// <param name="Policy">An optional policy OID to include in the request.</param>
        /// <param name="BufferSize">An optional buffer size for reading the file (default: 64 KB).</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public async Task<TimeStampResult>

            GetFileTimestamp(String                FilePath,
                             AlgorithmIdentifier?  HashAlgorithm       = null,
                             String?               Policy              = null,
                             UInt32                BufferSize          = 64 * 1024,
                             CancellationToken     CancellationToken   = default)

        {

            ArgumentException.ThrowIfNullOrEmpty(FilePath);

            HashAlgorithm ??= AlgorithmIdentifier.Sha256;

            await using var stream = new FileStream(
                                         FilePath,
                                         FileMode.Open,
                                         FileAccess.Read,
                                         FileShare.Read,
                                         (Int32) BufferSize,
                                         FileOptions.Asynchronous | FileOptions.SequentialScan
                                     );

            return await GetStreamTimestamp(
                             stream,
                             HashAlgorithm,
                             Policy,
                             BufferSize,
                             CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion

        #region GetStreamTimestamp (Stream, HashAlgorithm = null, Policy = null, ...)

        /// <summary>
        /// Fordert einen Zeitstempel für einen Stream an, ohne den vollständigen Inhalt in den RAM zu laden.
        /// </summary>
        public async Task<TimeStampResult>

            GetStreamTimestamp(Stream                Stream,
                               AlgorithmIdentifier?  HashAlgorithm       = null,
                               String?               Policy              = null,
                               UInt32                BufferSize          = 64 * 1024,
                               CancellationToken     CancellationToken   = default)

        {

            ArgumentOutOfRangeException.ThrowIfLessThan(BufferSize, 1024U);

            HashAlgorithm ??= AlgorithmIdentifier.Sha256;

            var digest   = await ComputeHash(
                                     Stream,
                                     HashAlgorithm,
                                     (Int32) BufferSize,
                                     CancellationToken
                                 ).ConfigureAwait(false);

            var request  = new TimeStampRequest(
                               new MessageImprint(
                                   HashAlgorithm,
                                   digest
                               ),
                               Policy,
                               TimeStampRequest.NewNonce(),
                               certReq: true
                           );

            return await SendAndVerify(
                             request,
                             CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion


        #region SendAndVerify      (TimeStampRequest, CancellationToken)

        /// <summary>
        /// Low-Level-Methode: Benutzerdefinierter Request + vollständiges Ergebnis.
        /// </summary>
        public async Task<TimeStampResult>

            SendAndVerify(TimeStampRequest   TimeStampRequest,
                          CancellationToken  CancellationToken   = default)

        {

            var httpResponse             = await httpClient.POST(
                                                     remoteURL.Path,
                                                     TimeStampRequest.Encode(),
                                                     TimeStampQuery,
                                                     QueryString:        remoteURL.QueryString,
                                                     CancellationToken:  CancellationToken
                                                 ).ConfigureAwait(false);

            if (httpResponse.HTTPStatusCode.Code is < 200 or > 299)
                throw new HttpRequestException($"The Time Stamp Authority answered {httpResponse.HTTPStatusCode}.");

            var responseBytes            = httpResponse.HTTPBody ?? [];

            var timeStampResponse        = TimeStampResponse.Decode(responseBytes);

            var tstInfo                  = timeStampResponse.Verify(TrustedTSACertificate);

            if (tstInfo.MessageImprint.HashAlgorithm.Algorithm != TimeStampRequest.MessageImprint.HashAlgorithm.Algorithm ||
               !tstInfo.MessageImprint.HashedMessage.SequenceEqual(TimeStampRequest.MessageImprint.HashedMessage))
            {
                throw new InvalidDataException("TimeStampResponse does not match the MessageImprint of the request.");
            }

            if (TimeStampRequest.Nonce != tstInfo.Nonce)
                throw new InvalidDataException("TimeStampResponse does not match the Nonce of the request.");

            if (TimeStampRequest.ReqPolicy is not null && TimeStampRequest.ReqPolicy != tstInfo.Policy)
                throw new InvalidDataException("TimeStampResponse does not match the requested policy.");


            var signedCms                = new SignedCms();
            signedCms.Decode(timeStampResponse.TimeStampToken!);

            var signerCert               = signedCms.SignerInfos[0].Certificate
                                               ?? throw new InvalidDataException("No signer certificate found in TimeStampToken!");

            return new TimeStampResult(
                       tstInfo,
                       timeStampResponse,
                       TimeStampRequest,
                       signerCert
                   );

        }

        #endregion



        #region (private) ComputeHash(Stream, HashAlgorithm, BufferSize, CancellationToken)

        private static async Task<Byte[]>

            ComputeHash(Stream               Stream,
                        AlgorithmIdentifier  HashAlgorithm,
                        Int32                BufferSize,
                        CancellationToken    CancellationToken)

        {

            using var hash    = IncrementalHash.CreateHash(
                                    GetHashAlgorithmName(HashAlgorithm)
                                );

                  var buffer  = ArrayPool<Byte>.Shared.Rent(
                                    BufferSize
                                );

            try
            {
                while (true)
                {

                    var read = await Stream.ReadAsync(
                                         buffer.AsMemory(0, BufferSize),
                                         CancellationToken
                                     ).ConfigureAwait(false);

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

        #endregion

        #region (private) GetHashAlgorithmName(HashAlgorithm)

        private static HashAlgorithmName GetHashAlgorithmName(AlgorithmIdentifier HashAlgorithm)

            => HashAlgorithm.Algorithm switch {
                   OIDMap.Sha256  => HashAlgorithmName.SHA256,
                   OIDMap.Sha384  => HashAlgorithmName.SHA384,
                   OIDMap.Sha512  => HashAlgorithmName.SHA512,
                   _              => throw new NotSupportedException($"Hash algorithm {HashAlgorithm.Algorithm} is not supported!")
               };

        #endregion


        #region Dispose()

        public void Dispose()
        {

            if (disposed)
                return;

            httpClient.Dispose();

            TrustedTSACertificate.Dispose();

            disposed = true;

        }

        #endregion

    }

}
