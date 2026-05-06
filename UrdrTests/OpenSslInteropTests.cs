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

using System.Diagnostics;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Urdr;
using org.GraphDefined.Vanaheimr.Urdr.Asn1;
using org.GraphDefined.Vanaheimr.Urdr.Tests;

#endregion

namespace org.GraphDefined.Vanaheimr.Urdr.Tests;

[TestFixture]
public sealed class OpenSslInteropTests
{
    [Test]
    public void OpenSslBuildsRequest_CSharpTimestamps_OpenSslVerifiesResponse()
    {
        RequireOpenSsl();
        using var workspace = TempWorkspace.Create();
        using var cert = TestCertificate.CreateRsa();
        var tsa = new TimeStampAuthority(cert.Info, cert.PrivateKey);

        var payloadPath = workspace.PathOf("payload.bin");
        var requestPath = workspace.PathOf("request.tsq");
        var responsePath = workspace.PathOf("response.tsr");
        var certPath = workspace.PathOf("tsa-cert.pem");

        File.WriteAllBytes(payloadPath, CreatePayload());
        File.WriteAllText(certPath, cert.Certificate.ExportCertificatePem());

        RunOpenSsl("ts", "-query", "-data", payloadPath, "-sha256", "-cert", "-out", requestPath);

        var responseDer = tsa.Process(File.ReadAllBytes(requestPath));
        File.WriteAllBytes(responsePath, responseDer);

        RunOpenSsl("ts", "-reply", "-in", responsePath, "-text");
        RunOpenSsl(
            "ts",
            "-verify",
            "-in", responsePath,
            "-queryfile", requestPath,
            "-CAfile", certPath,
            "-untrusted", certPath);

        var response = TimeStampResponse.Decode(responseDer);
        var tstInfo = response.Verify(cert.Certificate);

        Assert.Multiple(() =>
        {
            Assert.That(response.Status.Status, Is.EqualTo(PKI_Status.Granted));
            Assert.That(tstInfo.MessageImprint.HashAlgorithm.Algorithm, Is.EqualTo(OIDMap.Sha256));
            Assert.That(tstInfo.MessageImprint.HashedMessage, Is.EqualTo(SHA256.HashData(File.ReadAllBytes(payloadPath))));
        });
    }

    [Test]
    public void CSharpBuildsRequest_OpenSslTimestamps_CSharpVerifiesResponse()
    {
        RequireOpenSsl();
        using var workspace = TempWorkspace.Create();
        using var cert = TestCertificate.CreateRsa();
        var rsa = (RSA)cert.PrivateKey;

        var payload = CreatePayload();
        var request = TimeStampRequest.ForData(payload, certReq: true, policy: OIDMap.DefaultTsaPolicy);
        var requestPath = workspace.PathOf("request.tsq");
        var responsePath = workspace.PathOf("response.tsr");
        var certPath = workspace.PathOf("tsa-cert.pem");
        var keyPath = workspace.PathOf("tsa-key.pem");
        var configPath = workspace.PathOf("openssl-tsa.cnf");
        var serialPath = workspace.PathOf("serial.txt");

        File.WriteAllBytes(requestPath, request.Encode());
        File.WriteAllText(certPath, cert.Certificate.ExportCertificatePem());
        File.WriteAllText(keyPath, rsa.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(serialPath, "01" + Environment.NewLine);
        File.WriteAllText(configPath, CreateOpenSslTsaConfig(workspace.DirectoryPath, certPath, keyPath, serialPath));

        RunOpenSsl(
            "ts",
            "-reply",
            "-config", configPath,
            "-section", "tsa_config",
            "-queryfile", requestPath,
            "-out", responsePath);

        var response = TimeStampResponse.Decode(File.ReadAllBytes(responsePath));
        var tstInfo = response.Verify(cert.Certificate);

        Assert.Multiple(() =>
        {
            Assert.That(response.Status.Status, Is.EqualTo(PKI_Status.Granted));
            Assert.That(tstInfo.MessageImprint.HashAlgorithm.Algorithm, Is.EqualTo(OIDMap.Sha256));
            Assert.That(tstInfo.MessageImprint.HashedMessage, Is.EqualTo(request.MessageImprint.HashedMessage));
            Assert.That(tstInfo.Nonce, Is.EqualTo(request.Nonce));
            Assert.That(tstInfo.Policy, Is.EqualTo(OIDMap.DefaultTsaPolicy));
        });
    }

    private static void RequireOpenSsl()
    {
        try
        {
            RunOpenSsl("version");
        }
        catch (InvalidOperationException ex)
        {
            Assert.Ignore($"OpenSSL ist nicht verfügbar: {ex.Message}");
        }
    }

    private static byte[] CreatePayload()
        => Enumerable.Range(0, 2048)
            .Select(i => (byte)((i * 23 + 11) & 0xFF))
            .ToArray();

    private static string CreateOpenSslTsaConfig(
        string directoryPath,
        string certPath,
        string keyPath,
        string serialPath)
        => $$"""
            [tsa]
            default_tsa = tsa_config

            [tsa_config]
            dir = {{OpenSslPath(directoryPath)}}
            serial = {{OpenSslPath(serialPath)}}
            signer_cert = {{OpenSslPath(certPath)}}
            signer_key = {{OpenSslPath(keyPath)}}
            signer_digest = sha256
            default_policy = {{OIDMap.DefaultTsaPolicy}}
            other_policies = {{OIDMap.DefaultTsaPolicy}}
            digests = sha256, sha384, sha512
            accuracy = secs:1
            ordering = no
            tsa_name = no
            ess_cert_id_chain = no
            ess_cert_id_alg = sha256
            """;

    private static string OpenSslPath(string path)
        => path.Replace('\\', '/');

    private static string RunOpenSsl(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "openssl",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("OpenSSL-Prozess konnte nicht gestartet werden.");

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
                throw new InvalidOperationException(stderr.Length > 0 ? stderr : stdout);

            return stdout;
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException(ex.Message, ex);
        }
    }

    private sealed class TempWorkspace : IDisposable
    {
        public string DirectoryPath { get; }

        private TempWorkspace(string directoryPath)
        {
            DirectoryPath = directoryPath;
        }

        public static TempWorkspace Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "tsa-openssl-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TempWorkspace(path);
        }

        public string PathOf(string fileName)
            => Path.Combine(DirectoryPath, fileName);

        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath))
                Directory.Delete(DirectoryPath, recursive: true);
        }
    }
}
