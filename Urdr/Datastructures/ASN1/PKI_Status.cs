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

//  PKIStatus ::= INTEGER {
//      granted                (0),
//      grantedWithMods        (1),
//      rejection              (2),
//      waiting                (3),
//      revocationWarning      (4),
//      revocationNotification (5)
//  }

    public enum PKI_Status
    {
        Granted                = 0,
        GrantedWithMods        = 1,
        Rejection              = 2,
        Waiting                = 3,
        RevocationWarning      = 4,
        RevocationNotification = 5,
    }

}
