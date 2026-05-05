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

namespace org.GraphDefined.Vanaheimr.Urdr
{

//  PKIFailureInfo bit positions (RFC 3161 §2.4.2):
//      badAlg              (0)
//      badRequest          (2)
//      badDataFormat       (5)
//      timeNotAvailable    (14)
//      unacceptedPolicy    (15)
//      unacceptedExtension (16)
//      addInfoNotAvailable (17)
//      systemFailure       (25)

    [Flags]
    public enum PKI_FailureInfo
    {
        None                = 0,
        BadAlg              = 1 <<  0,
        BadRequest          = 1 <<  2,
        BadDataFormat       = 1 <<  5,
        TimeNotAvailable    = 1 << 14,
        UnacceptedPolicy    = 1 << 15,
        UnacceptedExtension = 1 << 16,
        AddInfoNotAvailable = 1 << 17,
        SystemFailure       = 1 << 25,
    }

}
