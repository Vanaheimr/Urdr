# Time-Stamp Protocol / Time Stamp Authority (RFC 3161)

This project implements the *Time-Stamp Protocol* and a *Time Stamping Authority* in C# .NET 10.
RSA + ECDSA (P-256/P-384/P-521) + SHA-256/384/512 can be used for signing.

Komplett handgeschriebene ASN.1-DER-Kodierung. Kein
`System.Formats.Asn1`, kein BouncyCastle für Protokoll-Strukturen.
Krypto-Primitive (RSA, SHA-256) kommen aus `System.Security.Cryptography`,
Self-Signed-Cert-Erzeugung aus `System.Security.Cryptography.X509Certificates`
(`CertificateRequest`).

## Lokale Verwendung

Server starten. Beim ersten Start erzeugt der Server standardmäßig `tsa.pfx` im
aktuellen Arbeitsverzeichnis:

```bash
dotnet run --project TSAServer -- serve
```

Eine Datei gegen den lokalen Server timestampen. Der Client nutzt per Default
`http://localhost:8080/` und vertraut `tsa.pfx`:

```bash
dotnet run --project TSAClient -- --in README.md --out README.tsr
```

Mit expliziter URL, Zertifikat, Hash-Algorithmus und Policy:

```bash
dotnet run --project TSAClient -- \
  --url http://localhost:8080/ \
  --cert tsa.pfx \
  --hash sha384 \
  --policy 1.3.6.1.4.1.99999.1.1 \
  --in README.md \
  --out README.tsr
```

Ohne `--in` timestamped der Client einen kleinen eingebauten Bytehaufen. Das ist
praktisch für einen schnellen Smoke-Test:

```bash
dotnet run --project TSAClient
```

Die gespeicherte `.tsr` ist die vollständige RFC-3161 `TimeStampResp` und kann
mit OpenSSL angesehen werden:

```bash
openssl ts -reply -in README.tsr -text
```


## Interop-Test mit OpenSSL

Der erzeugte Token ist ein vollständiger CMS SignedData, den OpenSSL
parsen kann:

### Lokale TSA-Response gegenprüfen

```bash
# 1. Testdaten und OpenSSL-Request erzeugen
printf "hello timestamp\n" > probe.txt
openssl ts -query \
  -data probe.txt \
  -sha256 \
  -cert \
  -out probe.tsq

# 2. TSAServer in einem zweiten Terminal starten
#    Hinweis: Der Server erzeugt tsa.pfx beim ersten Start selbst.
dotnet run --project TSAServer -- serve --port 8080 --pfx tsa.pfx

# 3. Timestamp-Response beim Server holen
curl -sS \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @probe.tsq \
  http://localhost:8080/ \
  -o probe.tsr

# 4. Response lesbar anzeigen
openssl ts -reply -in probe.tsr -text

# 5. TSA-Zertifikat aus dem PFX exportieren und Response verifizieren
openssl pkcs12 \
  -in tsa.pfx \
  -nokeys \
  -out tsa-cert.pem \
  -passin pass:

openssl ts -verify \
  -in probe.tsr \
  -data probe.txt \
  -CAfile tsa-cert.pem \
  -untrusted tsa-cert.pem
```

Für eine rein strukturelle Analyse ohne Trust-Prüfung:

```bash
# Reply hexdump
openssl ts -reply -in probe.tsr -text

# Vollständige CMS-Struktur dumpen
openssl asn1parse -inform DER -in probe.tsr -i
```

### Interop-Richtung: C# Request, OpenSSL Response

Der Test `CSharpBuildsRequest_OpenSslTimestamps_CSharpVerifiesResponse` erzeugt
den RFC-3161-Request mit dem C#-Encoder, lässt OpenSSL signieren und verifiziert
die Response wieder mit `TimeStampResponse.Verify(...)`. Manuell entspricht das:

```bash
# request.tsq kommt z. B. aus TimeStampRequest.ForData(...).Encode()
# tsa-key.pem und tsa-cert.pem sind ein TSA-Keypair mit kritischer
# Extended-Key-Usage id-kp-timeStamping.

cat > openssl-tsa.cnf <<'EOF'
[tsa]
default_tsa = tsa_config

[tsa_config]
serial = serial.txt
signer_cert = tsa-cert.pem
signer_key = tsa-key.pem
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1.1
other_policies = 1.3.6.1.4.1.99999.1.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF

printf "01\n" > serial.txt

openssl ts -reply \
  -config openssl-tsa.cnf \
  -section tsa_config \
  -queryfile request.tsq \
  -out openssl-response.tsr
```

# Token gegen TSA-Cert verifizieren
openssl pkcs12 -in tsa.pfx -nokeys -out tsa.pem -passin pass:
openssl ts -verify -in probe.tsr -data probe.txt -CAfile tsa.pem -untrusted tsa.pem


# 1. Timestamp-Request erzeugen
openssl ts -query \
  -data file.pdf \
  -no_nonce \
  -sha256 \
  -cert \
  -out request1.tsq

openssl ts -query \
  -digest $(sha256sum file.pdf | cut -d' ' -f1) \
  -sha256 \
  -cert \
  -out request2.tsq


# 2a. Timestamp-Response erzeugen (hier läuft der "Server")
openssl ts -reply \
  -config /etc/tsa/tsa.cnf \
  -queryfile request.tsq \
  -inkey /etc/tsa/private/tsa.key \
  -passin file:/etc/tsa/tsa.pass \
  -out response.tsr

# 2b. Timestamp-Response von einem öffentlichen TSA-Service anfordern

curl -H "Content-Type: application/timestamp-query" \
     --data-binary @request1.tsq \
     https://freetsa.org/tsr \
     -o response1.tsr


# 3. Antwort ansehen

openssl ts -reply -in response1.tsr -text


# 4. Verifizieren

# https://www.freetsa.org/ → tsa.crt and rootCA!
openssl ts -verify \
  -data file.pdf \
  -in response.tsr \
  -CAfile freetsa-ca.crt \
  -untrusted freetsa-tsa.crt

```

## Was bewusst weggelassen wurde

- `extensions [0] IMPLICIT` in `TimeStampReq` und `[1] IMPLICIT` in `TstInfo`
  werden beim Decodieren überlesen; beim Encodieren nicht emittiert.

## TSA-Name im TSTInfo

Der Server setzt standardmäßig `tsa [0] GeneralName` im `TSTInfo`. Der Wert wird
aus dem Subject-DN des TSA-Zertifikats abgeleitet und als
`directoryName [4] Name` kodiert. Das Feld ist kein Trust-Anker, aber nützlich
für Debugging, Auditing und OpenSSL-Ausgaben.

Wer das Feld weglassen möchte, kann die Authority so erzeugen:

```csharp
var tsa = new TimeStampAuthority(cert, key, tsaNameMode: TsaNameMode.None);
```

## Request/Response Extensions

`TimeStampReq.extensions [0]` und `TSTInfo.extensions [1]` werden als
RFC-5280-`Extensions` modelliert:

```csharp
new TspExtension("1.2.3.4.5.6", critical: true, value: extensionValueDer)
```

Aktuell unterstützt die TSA noch keine semantische Request-Extension. Deshalb
werden Requests mit Extensions RFC-3161-konform abgelehnt:
`PkiStatus.Rejection` mit `PkiFailureInfo.UnacceptedExtension`. Das ist
absichtlich strenger als Ignorieren.

## Accuracy konfigurieren

`Accuracy` ist die signierte Aussage, wie genau die TSA ihre `genTime` versteht.
Der Default ist `Accuracy(seconds: 1)`. Im Server kann der Wert über CLI gesetzt
oder komplett weggelassen werden:

```bash
dotnet run --project TSAServer -- serve --accuracy-seconds 1
dotnet run --project TSAServer -- serve --accuracy-millis 500
dotnet run --project TSAServer -- serve --accuracy-seconds 2 --accuracy-millis 500 --accuracy-micros 250
dotnet run --project TSAServer -- serve --no-accuracy
```

Im Core entspricht das:

```csharp
new TimeStampAuthority(cert, key, accuracy: new Accuracy(millis: 500));
new TimeStampAuthority(cert, key, includeAccuracy: false);
```

## Ordering konfigurieren

`ordering = true` bedeutet, dass `genTime`-Werte derselben TSA-Instanz streng
monoton steigen. Damit kann ein Verifier Tokens anhand ihrer `genTime` sortieren,
auch wenn mehrere Requests sehr dicht beieinander liegen.

Default ist `ordering = false`. Aktivieren:

```bash
dotnet run --project TSAServer -- serve --ordering
```

Im Core:

```csharp
new TimeStampAuthority(cert, key, ordering: true);
```

Die Garantie gilt für diese Authority-Instanz im Prozess. Für mehrere Server-
Instanzen wäre ein gemeinsamer Sequencer oder persistenter State nötig.

## Policies konfigurieren

Eine TSA kann mehrere Policy-OIDs akzeptieren. Requests ohne `reqPolicy`
bekommen die Default-Policy. Requests mit bekannter `reqPolicy` bekommen genau
diese Policy im `TSTInfo`. Unbekannte Policies werden mit
`PkiFailureInfo.UnacceptedPolicy` abgelehnt.

```bash
dotnet run --project TSAServer -- serve \
  --policy 1.3.6.1.4.1.99999.1.10 \
  --accept-policy 1.3.6.1.4.1.99999.1.11,1.3.6.1.4.1.99999.1.12
```

Im Core:

```csharp
new TimeStampAuthority(
    cert,
    key,
    policyOid: "1.3.6.1.4.1.99999.1.10",
    acceptedPolicyOids:
    [
        "1.3.6.1.4.1.99999.1.10",
        "1.3.6.1.4.1.99999.1.11"
    ]);
```


## ASN.1-Fallen, die hier explizit adressiert sind

1. **SignedAttributes Tag-Wechsel** zwischen `SET` (zum Signieren) und
   `[0] IMPLICIT` (zum Emittieren): Wir kodieren als `SET` (`0x31`),
   speichern, signieren, und ersetzen vor dem Emittieren das erste Tag-Byte
   mit `0xA0` — DER-Längen und -Inhalt bleiben byte-identisch.

2. **`PKIFailureInfo` BIT STRING**: Bit n der RFC-Definition entspricht
   `byte[n/8]` Bit `7 - (n % 8)`, mit korrekt berechneten `unusedBits`.
   Standard-`BitConverter` o.ä. tut hier nicht das Richtige.

3. **`signingCertificateV2`**: `IssuerSerial.issuer` ist `GeneralNames`
   (eine `SEQUENCE OF GeneralName`), das einzelne `directoryName` ist
   `[4] EXPLICIT Name`. Häufiger Fehler: `Name` direkt einzubetten.

4. **`SET OF` DER-Sortierung**: Attribute werden lexikographisch nach ihrer
   vollen DER-Codierung sortiert (`CompareDer`).

5. **`IMPLICIT` auf primitive INTEGER** in `Accuracy.millis`/`micros`:
   Tag wird `0x80`/`0x81`, *nicht* `0xA0`/`0xA1`. Wir kodieren erst
   `INTEGER`, extrahieren den Content und emittieren ihn unter dem
   Implicit-Tag.

6. **Cert-Serial als INTEGER-Inhalt**: Wir nehmen die DER-INTEGER-Octets
   aus dem Originalzertifikat (inkl. ggf. führendem `0x00` für Vorzeichen)
   und emittieren sie 1:1 — nicht aus `X509Certificate.GetSerialNumber()`
   konstruieren (das ist little-endian und ohne Sign-Padding).
