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
    /// Object identifiers used in RFC 3161 + RFC 5652 + RFC 5816
    /// </summary>
    public static class OIDMap
    {

        // ---- hash algorithms (NIST) ----
        public const String Sha256                      = "2.16.840.1.101.3.4.2.1";
        public const String Sha384                      = "2.16.840.1.101.3.4.2.2";
        public const String Sha512                      = "2.16.840.1.101.3.4.2.3";

        // ---- PKCS#1 ----
        public const String RsaEncryption               = "1.2.840.113549.1.1.1";
        public const String Sha256WithRsa               = "1.2.840.113549.1.1.11";
        public const String Sha384WithRsa               = "1.2.840.113549.1.1.12";
        public const String Sha512WithRsa               = "1.2.840.113549.1.1.13";

        // ---- ECDSA (RFC 5480 / RFC 5758) ----
        public const String IdEcPublicKey               = "1.2.840.10045.2.1";
        public const String Secp256r1                   = "1.2.840.10045.3.1.7";   // NIST P-256
        public const String Secp384r1                   = "1.3.132.0.34";          // NIST P-384
        public const String Secp521r1                   = "1.3.132.0.35";          // NIST P-521
        public const String EcdsaWithSha256             = "1.2.840.10045.4.3.2";
        public const String EcdsaWithSha384             = "1.2.840.10045.4.3.3";
        public const String EcdsaWithSha512             = "1.2.840.10045.4.3.4";

        // ---- EdDSA (RFC 8410) ----
        public const String Ed25519                     = "1.3.101.112";
        public const String Ed448                       = "1.3.101.113";

        // ---- PKCS#9 / CMS / TSP ----
        public const String ContentType                 = "1.2.840.113549.1.9.3";
        public const String MessageDigest               = "1.2.840.113549.1.9.4";
        public const String IdSignedData                = "1.2.840.113549.1.7.2";
        public const String IdCtTstInfo                 = "1.2.840.113549.1.9.16.1.4";
        public const String IdAaSigningCertificateV2    = "1.2.840.113549.1.9.16.2.47";

        // ---- TSA policy (default) ----
        public const String DefaultTsaPolicy            = "1.3.6.1.4.1.99999.1.1";

        // ---- X.509 extensions / EKU ----
        public const String EkuTimeStamping             = "1.3.6.1.5.5.7.3.8";




        // ---- PKCS#9 attributes ----
        public const String SigningTime                 = "1.2.840.113549.1.9.5";

        // ---- CMS ----
        public const String IdData                      = "1.2.840.113549.1.7.1";



        // ---- RFC 2634 - signingCertificate (legacy, SHA-1 only) ----
        //public const String IdAaSigningCertificate   = "1.2.840.113549.1.9.16.2.12";

        // ---- X.500 attribute types ----
        public const String AtCommonName                = "2.5.4.3";
        public const String AtCountryName               = "2.5.4.6";
        public const String AtOrganizationName          = "2.5.4.10";
        public const String AtOrgUnitName               = "2.5.4.11";

        // ---- X.509 extensions ----
        public const String ExtKeyUsage                 = "2.5.29.15";
        public const String ExtExtKeyUsage              = "2.5.29.37";
        public const String ExtBasicConstraints         = "2.5.29.19";
        public const String ExtSubjectKeyId             = "2.5.29.14";
        public const String ExtAuthKeyId                = "2.5.29.35";

    }

}
