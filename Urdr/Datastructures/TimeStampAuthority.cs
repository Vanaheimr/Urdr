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
using org.GraphDefined.Vanaheimr.Urdr.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr
{

    public sealed class TimeStampAuthority
    {
        private readonly CertificateInfo _cert;
        private readonly AsymmetricAlgorithm _key;
        private readonly string _defaultPolicyOid;
        private readonly HashSet<string> _acceptedPolicyOids;
        private readonly Accuracy? _accuracy;
        private readonly AlgorithmIdentifier _digestAlgorithm;
        private readonly byte[]? _tsaGeneralName;
        private readonly bool _ordering;
        private readonly bool _useRandomSerials;
        private readonly object _genTimeLock = new();
        private DateTime _lastGenTime = DateTime.MinValue;
        private long _serialCounter;

        public TimeStampAuthority(
            CertificateInfo cert,
            AsymmetricAlgorithm key,
            string? policyOid = null,
            IEnumerable<string>? acceptedPolicyOids = null,
            Accuracy? accuracy = null,
            AlgorithmIdentifier? digestAlgorithm = null,
            long initialSerial = 0,
            TSA_NameMode tsaNameMode = TSA_NameMode.SubjectDirectoryName,
            bool includeAccuracy = true,
            bool ordering = false)
        {
            _cert = cert;
            _key = key;
            _defaultPolicyOid = policyOid ?? OIDMap.DefaultTsaPolicy;
            _acceptedPolicyOids = new HashSet<string>(
                acceptedPolicyOids ?? [_defaultPolicyOid],
                StringComparer.Ordinal);
            _acceptedPolicyOids.Add(_defaultPolicyOid);
            _accuracy = includeAccuracy ? accuracy ?? new Accuracy(Seconds: 1) : null;
            _digestAlgorithm = digestAlgorithm ?? AlgorithmIdentifier.Sha256;
            _tsaGeneralName = CreateTsaGeneralName(cert, tsaNameMode);
            _ordering = ordering;
            _useRandomSerials = initialSerial <= 0;
            _serialCounter = initialSerial - 1;
        }

        public byte[] Process(byte[] requestDer)
        {
            TimeStampRequest req;
            try
            {
                req = TimeStampRequest.Decode(requestDer);
            }
            catch
            {
                return new TimeStampResponse(
                    new PKI_StatusInfo(PKI_Status.Rejection, "malformed request", PKI_FailureInfo.BadDataFormat))
                    .Encode();
            }

            if (req.MessageImprint.HashAlgorithm.Algorithm != _digestAlgorithm.Algorithm ||
                req.MessageImprint.HashedMessage.Length != GetHashSize(_digestAlgorithm))
            {
                return new TimeStampResponse(
                    new PKI_StatusInfo(PKI_Status.Rejection, "unsupported hash algorithm", PKI_FailureInfo.BadAlg))
                    .Encode();
            }

            var responsePolicyOid = req.ReqPolicy ?? _defaultPolicyOid;
            if (!_acceptedPolicyOids.Contains(responsePolicyOid))
            {
                return new TimeStampResponse(
                    new PKI_StatusInfo(PKI_Status.Rejection, "unaccepted policy", PKI_FailureInfo.UnacceptedPolicy))
                    .Encode();
            }

            if (req.Extensions.Count > 0)
            {
                return new TimeStampResponse(
                    new PKI_StatusInfo(PKI_Status.Rejection, "unaccepted extension", PKI_FailureInfo.UnacceptedExtension))
                    .Encode();
            }

            var serial = _useRandomSerials
                ? NewSerialNumber()
                : new BigInteger(Interlocked.Increment(ref _serialCounter));

            var info = new TSTInfo(
                policy: responsePolicyOid,
                messageImprint: req.MessageImprint,
                serialNumber: serial,
                genTime: GetGenTime(),
                accuracy: _accuracy,
                ordering: _ordering,
                nonce: req.Nonce,
                tsaGeneralName: _tsaGeneralName);

            var tstInfoDer = info.Encode();

            var builder = new CmsSignedDataBuilder(_cert, _key, _digestAlgorithm);
            var token = builder.Build(tstInfoDer, includeCert: req.CertReq);

            return new TimeStampResponse(new PKI_StatusInfo(PKI_Status.Granted), token).Encode();
        }

        private static int GetHashSize(AlgorithmIdentifier algo)
            => algo.Algorithm switch {
                OIDMap.Sha256 => 32,
                OIDMap.Sha384 => 48,
                OIDMap.Sha512 => 64,
                _ => 32
            };

        private static BigInteger NewSerialNumber()
        {
            Span<byte> serial = stackalloc byte[20];

            do
            {
                RandomNumberGenerator.Fill(serial);
                serial[0] &= 0x7F;
            }
            while (IsAllZero(serial));

            return new BigInteger(serial, isUnsigned: true, isBigEndian: true);
        }

        private static byte[]? CreateTsaGeneralName(CertificateInfo cert, TSA_NameMode mode)
        {
            if (mode == TSA_NameMode.None)
                return null;

            if (mode != TSA_NameMode.SubjectDirectoryName)
                throw new ArgumentOutOfRangeException(nameof(mode));

            var w = new Asn1Writer();
            using (w.PushExplicit(4))
                w.WriteEncoded(cert.SubjectDerSeq);

            return w.ToArray();
        }

        private DateTime GetGenTime()
        {
            var now = DateTime.UtcNow;
            if (!_ordering)
                return now;

            lock (_genTimeLock)
            {
                if (now <= _lastGenTime)
                    now = _lastGenTime.AddTicks(1);

                _lastGenTime = now;
                return now;
            }
        }

        private static bool IsAllZero(ReadOnlySpan<byte> bytes)
        {
            foreach (var b in bytes)
            {
                if (b != 0) return false;
            }

            return true;
        }

    }

}
