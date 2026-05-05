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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Urdr.Asn1;

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

#endregion

[TestFixture]
public sealed class PkiStatusInfoTests
{

    [Test]
    public void EncodeDecode_RoundTrips_FailureInfoBits()
    {
        var status = new PKI_StatusInfo(
            PKI_Status.Rejection,
            "policy rejected",
            PKI_FailureInfo.BadAlg | PKI_FailureInfo.UnacceptedPolicy | PKI_FailureInfo.SystemFailure);

        var writer = new Asn1.Asn1Writer();
        status.Encode(writer);
        var reader = new Asn1.Asn1Reader(writer.ToArray());

        var decoded = PKI_StatusInfo.Decode(ref reader);

        Assert.Multiple(() =>
        {
            Assert.That(decoded.Status, Is.EqualTo(PKI_Status.Rejection));
            Assert.That(decoded.StatusText, Is.EqualTo("policy rejected"));
            Assert.That(decoded.FailureInfo, Is.EqualTo(status.FailureInfo));
        });

    }

}
