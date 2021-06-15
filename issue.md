# Luca Auffaellikeiten / Issues

Liste von Auffälligkeiten/Problemen mit potentieller Sicherheitsrelevanz in der "Luca"-Fachanwendung.

Versionen zum Betrachtungszeitpunkt

- Backend/Web Services aus `Web` Repository: v1.1.15
- AndroidApp: v1.7.4

Die Ausführungen **haben keinen Anspruch auf Vollständigkeit** und werden ggf. nach Veröffentlichung ergänzt. Das Dokument unternimmt keine Anstregungen Termini, prozessuale oder funktionale Sachverhalte zu erläutern, die sich aus dem veröffentlichten Material zu "Luca" ergeben (Dokumentaion, Quellcode). Das Dokument nimmt an, dass LeserInnen mit dem System vertraut sind.

# Referenzmaterial

1. [Kurzanalyse Netzwerkverkehr (Erstellung Bewegungsprofile)](https://github.com/mame82/misc/blob/master/luca_traceIds.md)
2. [Youtube Playlist mit Erlaeuterungen zu diversen Problemstellungen](https://www.youtube.com/playlist?list=PLKuX6iczGb3kuDsm2RFgbmRkTugkR9-UE)
3. [Demo Video "CSV Injection" Gesundheitsamt (Download-Link, da Youtube Video entfernt)](www.cyberawareness.de/public/luca_attack5.mp4)

# 1. Erläuterungen zu Nutzerdaten im Backend (Auszug)

## 1.1 Verschlüsselte Kontaktdaten "Encrypted User Data"

Die Kontaktdaten des Nutzers werden als JSON-String serialisiert und mit AES128 (Counter Mode) verschlüsselt dauerhaft auf dem Server abgelegt, sie umfassen:

- numerische Version der Kontaktdaten (2 für App-Nutzer, 2 für Schlüsselanhänger)
- Vorname
- Nachname
- Telefonnummer
- Email
- Straße
- Hausnummer
- Postleitzahl
- Stadt
- Verification Secret (nur für Schlüsselanhänger)

Der Schlüssel zu den Kontaktdaten (`data secret`) ist für App-Nutzer nur Lokal bekannt, wird aber in der "verschlüsselten Kontaktdaten Referenz" bei jedem Location Check-In übermittelt (vergleiche Abschnitt "Check-In-Traces"; erlaubt dem Gesundheitsamt die Entschlüsselung von Kontaktdaten nach Zustimmung eines Location-Operators).

Neben der Möglichkeit, das `data secret` aus Location Check-Ins zu generieren (nach Zustimmung des Location-Operators), kann ein berechtigtes Gesundheitsamt den Schlüssel direkt vom Nutzer erhalten, wenn dieser ihn bereitstellt (im Rahmen des gesonderten Verfahrens zur Bereitstellung der Nutzer Location Historie an das Gesundheitsamt).

**Das `data secret` für Schlüsselanhänger leitet sich aus der Seriennummer des Anhängers ab. Die Offenlegung einer Seriennummer ist also gleichbedeutend mit der Offenlegung des Crypto-Schlüssels zu den zentral gespeicherten Kontakdaten. Die Seriennummern der bisher produzierten Schlüsselanhänger, wurden durch das gleiche Unternehmen vergeben, welches auch das Luca-System entwickelt (Nexenio). Es ist daher davon auszugehen, dass diese bekannt sind.**

Die verschlüsselten Kontaktdaten werden als Base64-String mit maximaler Länge von 1024 Zeichen gespeichert. Es lassen sich hier also **beliebige Sequenzenzen** aus 768 Bytes AES verschlüsselte Daten speichern, die vollständig vom Nutzer kontrolliert werden (input). Eine Validierung dieser Eingabedaten, kann (und muss) nur im "Health Department Frontend" erfolgen, da die Daten im Normalfall erst beim Gesundheitsamt entschlüsselt werden.

Zu den verschlüsselten Kontaktdaten wird eine Signatur angelegt. **Diese Signatur wird nicht über validierte Kontaktdaten gebildet, sondern über die "rohen" Binärdaten, welche verschlüsselt werden (also 768 Bytes, die beliebig wählbar sind)**

## 1.2 Check-In-Traces

Ein `Trace` bildet im Luca-System den Besuch eines Nutzers in einer Location ab, er umfasst u.a.

- Check-In Zeitpunkt
- Check-Out Zeitpunkt (wenn bereits erfolgt)
- `TraceID` (zur eindeutigen Identifikation eines Traces; Nutzer-pseudonym, da mittels Einwegfunktion aus einzigartigem `tracing secret` des Nutzers und minutengenauem Zeitstempel generiert)
- Geräte-Typ (iOS App, Android App oder Schluesselanhänger)
- Location ID (verweist auf Datensatz mit **unverschlüsselten** Daten der Location)
- **verschlüsselte** "Kontaktdatenreferenz" (`encrypted contact data reference`)
  - setzt sich zusammen aus `UserID` eines registrierten Nutzers und dem `data secret` des Nutzers (der symmetrische Schlüssel zur Entschlüsselung der Kontakdaten des Nutzers, welche bei Registrierung persistent in der Backend-Datenbank abgelegt werden)
  - zweifach AES128 verschlüsselt
  - der innere Schlüssel wird aus dem asymmetrischem `Daily Key Pair` der Gesundheitsämter (gleich **für alle Gesundheitsämter**) mittels DLIES abgeleitet
  - für Schlüsselanhänger (Badges) kommt bei der inneren Verschlüsselung nicht der `Daily Key Pair` der Gesundheitsämter zum Einsatz, sondern das sogenannte `Badge Key Pair` (ein Schlüsselpaar, welches **nicht täglich rotiert**, aber durch die Gesundheitsämter erstellt wird)
  - der äußere Schlüssel wird aus dem asymmetrischem Schlüsselpaar des jeweiligen `Location-Operators` mittels DLIES abgeleitet (Wichtig: Dieses asymmetrische Schlüsselpaar existiert nicht je Location, sondern es ist **für alle LocationGroups und Locations, welche der Location-Operator verwaltet, gleich**)
- "additional Trace Data" (optional, durch Location-Operator entschlüsselbar)
  - AES128 verschlüsselt
  - der Schlüssel wird aus dem asymmetrischem Schlüsselpaar des jeweiligen `Location-Operators` mittels DLIES abgeleitet (Wichtig: Dieses asymmetrische Schlüsselpaar existiert nicht je Location, sondern es ist **für alle LocationGroups und Locations welche der Location-Operator verwaltet gleich**)
  - "additional Data" können von Location-Betreibern zusätzlich optional erhoben und entschlüsselt werden. Diese Daten gehen aber auch in die Ergebnisse der Location-Abfragen durch Gesundheitsämter ein (z.B. in die Datenexporte). Darüber hinaus kommt dieser Datenansatz für sogennante `Private Treffen` zum Einsatz, bei denen der Vor- und Nachname des Gastes als "additional Data" zum Check-In codiert wird und so vom Gastgeber entschlüsselt und dargestellt werden kann.
  - Ob und welche Zusatzdaten von einer Location erhoben werden sollen, wird für jede Location in einem Schema festgehalten (API Endpunkt `api/v3/locations/additionalDataSchema/{locationId}`).

### 1.2.1 Ergänzungen zu "additional Trace Data" für Location Betreiber (Bestandteil der Checkin-Traces)

Die "additional Trace Data" werden als Base64-String mit einer maximalen Länge von 4096 Zeichen gespeichert. Es lassen sich hier also **beliebige Byte-Sequenzenzen** von bis zu 3072 Bytes AES verschlüsselte Daten speichern, welche vollständig vom eincheckenden Nutzer kontrolliert werden (Input). Eine Validierung dieser Eingabedaten kann (und muss) an jeder Stelle erfolgen, an der die Daten entschlüsselt werden (Input) und in der Folge verarbeitet und ausgegeben werden (Output). Solche Stellen sind beispielsweise:

1. Frontend für Location-Betreiber (bisher werden hier "additional Data" nicht angezeigt, es wurde aber eine Funktionalität hinzugefügt, welche Tischnummern als "additional Data" führt und im Location-Frontend verarbeitet und darstellt.)
2. App, bei privaten Treffen (für private Treffen werden Ersteller des Treffens Vor- und Nachname der Gäste in der App angezeigt. Die dargestellten Daten basieren auf den "additional Data" welche der Gast - in Form eines 3072 Byte großen Blocks beliebiger Daten - beim Einchecken bereitstellt)
3. **Health Department Frontend** (hier werden neben den Kontaktdaten der Gäste einer Location auch alle "additional Data", welche die Gäste bereitgestellt haben, verarbeitet)

# 2. Problemstellungen

## 2.1 [Backend] - IP Protokollierung

Das Backend verwendet als Schutzmechanismus u.a. IP-basiertes Rate-Limiting. Der Ansatz bietet ein niedrigschwelliges Hindernis für AngreiferInnen mit durchschnittlichen Fähigkeiten (limitiert u.a. maximale Check-Ins, maximale Anzahl Nutzerregistreirungen usw., welche jeweils von der gleichen IP-Adresse ausgehen). Dem gegenüber stehen die Risiken, die durch die **flüchtige** Speicherung der Request-IPs (nicht pseudonymisiert/gehasht) - in Verbindung mit dem genauen angefragten Endpunkt und Zeitpunkt des jeweils letzten Zugriffs auf diesen Endpunkt (ableitbar aus "expiry time") - in einer Redis DB einhergehen.

Entstehende Privacy-Risiken könnten bereits durch ein Hashing der IP-Adresse gemildert werden.
Entstehende Möglichkeiten zur zeitlichen Korrelation der Redis-Datensätze (IP-Adressen, Endpunkt, Timestamp als Expiry Time), zu weiteren mit Zeitstempeln versehenen Informationen (beispielsweise pseudonymisierte Check-Ins), wären durch ein "künstliches Bias" in den "Expiry Times" machbar.

### Hinweis:

Analog zum IP-basierten Rate-Limiting Code, existiert Code zum Telefonnummern-basierten Rate Limiting (jeweils Mobil und Festnetz).
Die Funktionalität kommt (bisher) nur für Festnetznummern zum Einsatz, im Gegensatz zu IP-Adressen werden Telefonnummern vor Speicherung gehasht (SHA256).

1. [Code Refernz: IP-Logging](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L19)
2. [Code Referenz: **einer** Datenspeicherung in Redis](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L74)
3. [Code Referenz: Speicherung gehashter Telefonnummern (Keying)](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L26)
4. [Code Referenz: Speicherung gehashter Telefonnummern (Speicherung)](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L95)
5. [Code Referenz: Speicherung gehashter Telefonnummern (Anwendung)](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/routes/v3/sms.js#L53)

### Auswirkungen

Es wurden bereits anderweitig Möglichkeiten aufgezeigt, die es einem Backend-Beobachter (z.B. berechtigtes Betriebspersonal oder Threat-Actor mit Zugriff) ermöglichen, durch längere Beobachtung der Kommunikation folgende Ableitungen zu treffen:

- Zuordnung aller Check-Ins/Check-Outs zu einzelnen Mobilgeräten
- Zuordnung der Telefonnummer zu den Mobilgeräten
- Zuordnung von Abfragen der Gesundheitsämter zu den jeweiligen Mobilgeräten

(Vergleiche dazu Referenzmaterial 1 und 2)

Durch die Speicherung von IP-Adressen mit ableitbaren Zugriffszeiten ergeben sich ähnliche Möglichkeiten auch **ohne längerfristige Beobachtung des Backends bei einmaligem Datenzugriff**. Dies ist insbesondere möglich, da die Datenlage zu einer Vielzahl an logischen Ereignissen (Nutzer-Registrierungen, Nutzer-Check-In/-Check-Out, Location-Registrierung etc.) ebenfalls mit unverschlüsselten Zeitstempeln gespeichert wird.

## 2.2 [Backend API] Unauthenticated access EP `/v3/locations/traces/{accessId}`

- Der Endpunkt erlaubt Abfrage von Traces einer Location ohne Authentifizierung als Operator
- Benötigt wird zur Abfrage die `AccessID` der Location
  - Diese wird bei der Registrierung der Location automatisch generiert (durch PostgresDB, beim Anlegen des Datensatzes)
  - Die Verwendung der `AccessId` als Query-Parameter (ohne weitere Authentifizierung), birgt das Risiko der ihrer Offenlegung (bspw. bei Person-in-the-Middle-Angriffe im WiFi-Netzwerk einer Location oder beim Logging des Query-Path an Intermediaries in komplexeren Enterprise IT-Netzen/ggf. Übermittlung von Queries an externe Security Services, etc.)
- Abfragbare Informationen für Locations mit bekannter gewordener `AccessId`
  - individuelle Check-In- / Check-Out-Zeitpunkte
  - Typ des Checkins (Android-App / iOS-App / Schlüsselanhänger)
  - verwendete TraceID; die **TraceID ist Nutzerpseudonym**, verschiedene Nutzer können nie gleiche TraceIDs generieren (vgl. Referenzmaterial 1 und 2). Für Schlüsselanhänger (Badges), zu denen der QR-Code (Tracing Seed) oder die Seriennummer (erlaubt Ableitung aller geheimen Nutzerschlüssel) bekannt geworden ist, **ist eine direkte Nutzer-Zuordnung der TraceIDs möglich**.

## 2.3 [Backend, Health Department Frontend] Fehlende Plausibilitätsprüfungen (exemplarisch)

Eine Plausibilitätsprüfung der durch Nutzer und Location-Betreiber eingebrachten Daten kann technisch bedingt oft nicht zentral, sondern nur nach Entschlüsselung von Daten erfolgen. Das heißt:

- Für "encrypted user data" (vgl. Abschnitt 1.1) kann die Plausibilitätsprüfung erst im Frontend des Gesundheitsamtes erfolgen (Anteil des Luca-Systems, ausgelegt als Web-App, Datenentschlüsselung erfolgt lokal im Browser)
- Für "additional Trace Data" (vgl. Abschnitt 1.2.1), ist eine Plausibilitätsprüfung möglich:
  - im Frontend des Gesundheitsamtes (nach Abruf der Daten von einer Location)
  - im Frontend des Location-Betreibers (z.B. beim Auswerten von Tischnummern, welche als "Additional Data" geführt werden; auch hier handelt es sich um einen Anteil des Luca-Systems, ausgelegt als WebApp, Datenentschlüsselung erfolgt lokal im Browser)
  - in der App, für private Treffen (Vor- und Nachname der Gäste werden als "additional data" geführt)

Weiter bestehen bis heute Probleme bei der Verifizierung der Telefonnummern von Nutzern. Diese wird clientseitig beim Nutzer durchgeführt und kann daher umgangen/übersprungen werden. Die weiteren Kontaktdaten (Name, Adresse, etc.) werden ohnenhin nicht auf Plausibilität geprüft.

Hieraus ergeben sich folgende Probleme, welche die Sicherheit und Nutzbarkeit des Systems schwächen können:

1. Durch Einzelpersonen können beliebig viele Luca-Nutzer registriert werden. Falsche, aber auch bereits vorhandene, Kontaktdaten können mehrfach registriert und die so registrierten Nutzer dann in beliebige Locations eingecheckt werden. Da die Telefonnummer nicht verifiziert wird, ist es auch möglich, plausible Kontaktdaten fremder Personen über Check-Ins in (beliebige Locations) Infektionsketten einzubringen. Das einzige Datum, für das seitens Luca garantiert wird, dass es verifiziert sei, ist dabei die Telefonnummer, welche daher auch durch die Gesundheitsämter zur Kontaktaufnahme herangezogen werden muss. Angesichts der Tatsache, dass beliebige Telefonnummern mehrfach registriert werden können, leidet nicht nur die System-Sicherheit erheblich, sondern auch dessen Funktionalität.
2. Der gleiche Nutzer kann in mehreren Locations gleichzeitig eingecheckt werden. Festgestellt werden könnte dies (aus vorgenannten Gründen) nur im Gesundheitsamt, wenn genau dieser Nutzer "getracet" wird, also der Nutzer seine vollständige Location-Historie bereitstellt. Solche unplausiblen "Mehrfach-Check-Ins" könnten im Gesundheitsamt **nicht** festgestellt werden, wenn die Kontaktdaten des Nutzers im Rahmen der Abfrage einer Location entschlüsselt werden (= Location-Betreiber stellt Gästeliste bereit) - sofern nicht zufällig mehrere Locations abgefragt werden, in denen sich der Nutzer zeitgleich befand. Hieraus ergibt sich, dass Schwachstellen, die darauf aufbauen, dass manipulierte Kontaktdaten eines Nutzers (bspw. Schadcode) durch ein Gesundheitsamt verarbeitet werden, beliebig skalieren. Ein solches Angriffsszenario würde nur zum Erfolg führen, wenn das Gesundheitsamt eine Location abfragt, in der sich im Abfrage-relevanten Zeitraum ein solcher "Schadnutzer" befunden hat. Die Möglichkeit redundanter Check-Ins, erlaubt es Angreifern allerdings, bereits einen einzelnen Schadnutzer beliebig oft in beliebig vielen Locations einzuchecken, um die Erfolgschancen eines Angriffsversuchs zu steigern.
3. Aus Punkt 1 und 2 ergibt sich, dass Locations mit Check-Ins "geflutet" werden können (sowohl mehrfache Check-Ins des gleichen Nutzers, als auch durch verschiedene Nutzer, die - mangels funktionierender Telefonnummernverifikation - in beliebiger Anzahl durch einen Angreifer registriert werden können). Es wird behauptet, dass solche "ungültigen" Check-Ins vor Auswertung im Gesundheitsamt herausgefiltert werden. Tests haben gezeigt, dass diese Filterung auf Signaturen der Kontaktdaten der registrierten Nutzer basiert, d.h. **sie greift ausschließlich, wenn die bei Registrierung des Nutzers verwendeten Daten nicht im vorgesehenen technischen Prozess verschlüsselt und signiert wurden. Die Signatur wird dabei nicht über validierte Kontaktdaten gebildet, sondern über Binärdaten, welche beliebigen Inhalt transportieren können (vgl. 1.1, letzter Absatz)**. Darüber hinaus ist es in vielen Angriffsszenarien unerheblich, ob die beworbene Datenfilterung überhaupt funktional ist, denn: Zur Umsetzung der Filterung selbst müssen (unter Umständen schadhafte) Kontaktdaten im Gesundheitsamt verarbeitet werden.

## 2.3.1 Ergänzung Plausibilität: Locations, die keine verwertbaren Daten produzieren (Ergänzung)

Es häufen sich Berichte über Locations, welche Luca als Check-In-System anbieten, aber im Zuständigkeitsbereich von Gesundheitsämtern liegen, welche nicht oder noch nicht an Luca angebunden sind.

Die Luca-Webseite bietet einen [Postleitzahlen-basierten Verfügbarkeitstest (link)](https://www.luca-app.de/nutzeluca/) an. **Dennoch wird beim Erstellen/Registrieren von Locations im Luca-System nicht geprüft, ob zu der für die Location angegebenen Postleitzahl ein zuständiges Gesundheitsamt an das System angebunden ist.** Die Unterlassung dieser Plausibilitätsprüfung führt offenbar dazu, dass gehäuft Location-Betreiber Luca als **einzige** digitale Checkin-Lösung anbieten, obwohl das zuständige Gesundheitsamt die Gästelisten nie abrufen könnte (mangels Anbindung). Werden die Gästedaten durch den Location-Betreiber nicht zusätzlich in anderer Form erfasst, kommt dieser in der Regel seiner Verpflichtung gemäß geltender CoronaSchVO nicht nach. Der Erhebungszweck der Daten durch Luca dürfte dabei ebenfalls in Frage gestellt sein.

## 2.4 [Location Frontend] Permanentes Vorhalten des Privaten Schlüssels des Location Operators in der Browser Session

Beim Registrieren eines "Location Operators" (Betreiber einer oder mehrerer Locations), wird ein asymmetrisches Schlüsselpaar erstellt, für welches der private Schlüsselanteil im Registrierungsprozess einmalig zum Download angeboten wird. Dieser private Schlüssel ist nochmals mit AES128 umschlüsselt (encrypted private key). Der zugehörige Entschlüsselungsschlüssel (`private key secret`) ist im Backend gespeichert und kann nur mittels authentifizierter Session des `Location Operators` abgerufen werden.

Der private Schlüssel des Location-Betreibers kann u.a. dazu genutzt werden, die "additional Trace Data" eingecheckter Gäste zu entschlüsseln (vgl. Abschnitt 1.2 und 1.2.1) oder die äußere Verschlüsselung der "encrypted contact data reference" (vgl. Unterpunkt in Abschnitt 1.2) aufzuheben.

Die Möglichkeit, diese Entschlüsselungen vorzunehmen besteht für einen authorisierten "Location-Operator" ohnehin, allerdings nicht für Angreifer, die in der Lage wären, durch die Asunutzung von Sicherheitslücken die Browser-Session zu übernehmen. Dies begründet sich darin, dass das "Location Frontend" - auch wenn kompromittiert - in einer Browser-Sandbox läuft, aus welcher heraus ein Zugriff auf den (als lokale Datei gespeicherten) privaten Schlüssel des Location Operators nicht ohne weiteres möglich ist.

Bisher wurde der private Schlüssel des "Location-Operators" nur im Bedarfsfall in den Browser geladen, nämlich dann, wenn eine Abfrage der Gäste-Check-Ins durch ein Gesundheitsamt erfolgt ist und der Location-Operator dieser Anfrage nachkommt. Das Risiko hierbei ist überschaubar, da der private Schlüssel nur temporär im Browser-Kontext verfügbar war.

Mit einem Update der Web-Services Anfang Mai (v1.1.8), wurde die Funktionalität des Location-Frontends allerdings so angepasst, dass der Location-Operator beim Login aufgefordert wird, seinen privaten Schlüssel in die Browser-Session zu laden.

Dies schwächt die Schlüssel-Sicherheit im Kontext möglicher Angriffe auf den Browser immens. Als Grund für diese Maßnahme wurde angeführt, dass der Location-Operator nur so die Tischnummern der Gäste-Checkins entschlüsseln kann (diese werden als "additional data" im Check-In Trace hinterlegt).

### Bewertung:

Die Funktionalität, Tischnummern auf Basis des permanent in den Browser geladenen **privaten Schlüssels** des Location-Operators anzuzeigen, steht im Missverhältniss zu den entstehenden technischen Risiken. Zunächst hat der private Schlüssel nicht nur Bezug zu einer Einzel-Location, sondern gilt global für alle Locations des Location-Operators. Darüber hinaus wäre die Segmentierung eines Veranstaltungsortes in Zonen (wie "Tische") auch ohne die Verwendung des "additional data"-Konstruktes möglich: Das System verwaltet bereits LocationGroups, welche mehrere Locations zusammenfassen; im Frontend sind LocationGrous als "Location" benannt, wobei die eigentlichen Locations als "Area" benannt werden.

Die Funktionalität der "additional data", welche durch Location-Betreiber ohne das Zutun des Gesundheitsamts entschlüsselt werden können, ist ohnehin höchst fragwürdig und bietet Missbrauchspotential. Eines der möglichen Angriffsszenarien auf "additional trace data" wird im nächsten Abschnitt dargestellt.

## 2.5 [App, Backend] Ausnutzung "additional Trace Data", Erschleichen von Nutzerdaten durch Location-Provider

Die Abschnitte 1.2 und 1.2.1 sprechen "additional Trace Data" als Konstrukt an, welches es ermöglicht, an **jeden Nutzer-Check-In** weitere beliebige Daten zu koppeln, welche nicht für das Gesundheitsamt verschlüsselt werden, sondern bereits durch den Location-Betreiber entschlüsselt werden können (ohne Zutun eines Gesundheitsamtes).

Es ist vorgesehen, dass der Location-Betreiber beim Erstellen von Locations festlegt, welche Daten er zusätzlich erhebt. Die Daten sollen aus Key-Value-Paaren bestehen. Über die Struktur der für eine Location zusätzlich zu erhebenden Daten wird ein Schema angelegt (vgl. Abschnitt 1.2).

Aus funktionaler Sicht werden die vom Betreiber vorgesehenen Zusatzdaten ("additional data") nur abgefragt, wenn der Locationbetreiber selbst seine Gäste mittels des Kontaktformulares erfasst, welches das Luca-System als zusätzliche Check-In-Möglichkeit bereitstellt. Ein Self-Check-In mit der App führt derzeit bspw. nicht zu einer Abfrage dieser Daten (dies könnte anndernfalls durch den Location-Betreiber missbraucht werden, um zusätzliche persönliche Daten von eincheckenden Gästen zu "erschleichen").

Dennoch kommt das angelegte Schema nicht zur Plausibilitätsprüfung der "additional data", die ein Gast beim Einchecken bereitstellt, zum Einsatz. So ist es z.B. möglich, als Gast "additional data" an einen Check-In anzuhängen, obwohl dies von der Location gar nicht vorgesehen ist. Überall, wo diese Zusatzdaten ungefiltert verarbeitet werden, entsteht daher zusätzliche Angriffsfläche (wird in anderen Abschnitten behandelt).

Eine riskante Konstelation ergibt sich im Zusammenhang mit den sogenannten "private Meetings". Es handelt sich dabei um Treffen, welche von Luca-App Nutzern geöffnet werden können. Gäste können dann durch Scannen des QR-Codes des Gastgebers bei dem "private Meeting" einchecken. Das private Meeting unterscheidet sich (Backend-seitig) in der technischen Gestaltung nur in einem Punkt von einer regulären Location: Der Datensatz der Location hat das Attribut `isPrivate` als `true` hinterlegt (siehe [link](https://gitlab.com/lucaapp/web/-/blob/af4bdb2a3af8d2b5d46ef8f27d69eff59516710a/services/backend/src/database/models/location.js#L87)).

Für eincheckende Gäste unterscheidet die App zwischen "private Meetings" und "echten Locations" wiederum anhand des **Aufbaus der Location URL** im QR-Code des Meetings/der Location. Der eigentliche Check-In-Prozess und die damit einhergehende Datenverschlüsselung läuft für "private Meetings" und Self-Check-Ins in "echten Locations" analog. Es existiert nur ein entscheidender Unterschied: Für **alle Locations, deren QR-Code den Aufbau eines privaten Meetings hat, sendet die App den Vor- und Nachnamen des Gastes als "additional data" mit (d.h. für Locationbetreiber entschlüsselbar)**. Der Übermittlung der Daten geht ein kurzer Informationsdialog voran, in dem darauf hingewiesen wird, dass für private Meetings Vor- und Nachname übermittelt werden.

Aufbau der Checkin-URL für eine reguläre Location:

```
https://app.luca-app.de/webapp/{scannerID}#...
```

Aufbau der Checkin-URL für ein privates Meeting:

```
https://app.luca-app.de/webapp/meeting/{scannerID}#...
```

**Da die App an keiner Stelle überprüft, ob es sich bei der Ziellocation tatsächlich um ein "privates Meeting" handelt, erfolgt die übermittlung von Vor- und Nachnamen des Gastes als "additional data" auch an Locations, welche zwar kein privates Meeting sind, dies aber in ihrem QR-Code so angeben.** Mehr noch: Der Check-In-Trace (welcher nun Vor- und Nachname des Nutzers als "additional data" enthält) wird vom Backend-Server selbst dann gespeichert, wenn das für die Location laut Schema gar keine "additional data" anfallen dürften. Der Server könnte bei Speicherung zwar nicht auf Plausibilität der "additional data" gegenüber dem Schema prüfen (Daten sind nur durch Locationbetreiber zu entschlüsseln), aber sehr wohl feststellen, dass für ein Schema, welches keine zusätzlichen Daten fordert, auch keine zusätzlichen verschlüsselten Daten zu speichern sind.

Mit einer minimalen Veränderung am QR-Code für Self-Check-Ins kann ein Location-Betreiber also die automatisierte Übermittlung von Vor- und Nachnamen eincheckender Gäste auslösen. Die Gäste werden zwar mit einem Informationsdialog konfrontiert, der aussagt, dass für "Private Meetings Vor- und Nachnamen an den **Meeting Gastgeber** übermittelt werden". Der Hinweis macht im Kontext einer Location wenig Sinn, dürfte aber ohnehin von vielen Nutzern ignoriert werden, die einchecken möchten.

Der Angriff wurde hier demonstriert: [Youtube-Link](https://youtu.be/jWyDfEB0m08).

Die Problemstellung ist dem Hersteller [bekannt](https://twitter.com/patrick_hennig/status/1387738281757061125).

Die Problemstellung wird von [CVE-2021-33839 (link)](https://github.com/mame82/misc/blob/master/cve-luca/cve-2021-33839.md) erfasst.

## 2.6 [Backend, App] Durch Beobachtung von Netzwerkverkehr können Bewegungsprofile erstellt und mit Nutzerdaten verknüpft werden

Durch **reine Beobachtung des Netzwerkverkehrs am Backend**, lassen sich **ohne Kenntnis des Schlüsselmaterials für Kontaktdaten oder für Check-In-Traces** folgende Ableitungen treffen:

- Check-In-Historie für das Mobilgerät von teilnehmenden App-Nutzern lässt sich rekonstruieren
- für rekonstruierte Check-In-Historien lässt sich die Telefonnummer als persönliches Identifikationsmerkmal zuordnen
- für rekonstruierte Check-In-Historien lässt sich zuordnen, ob Check-Ins durch ein Gesundheitsamt im Rahmen der Nachverfolgung einer Infektionskette abgefragt wurden (in der Regel ist die entsprechende Check-In-Historie damit infektionsrelevant).

Ursächlich sind hier:

1. Hohe Abfragefrequenz von Check-Ins durch die App am Backend (bis zu 20-mal pro Minute), unter wiederholter Verwendung gleicher `TraceIDs` welche **nur von einem Gerät im System stammen können (pseudonym)**. Hierdurch wird die Korrelation verschiedener Check-Ins zum gleichen Gerät möglich, selbst wenn das Gerät die IP-Adresse wechselt oder die Nutzung der App unterbrochen wird (auch über einen Geräteneustart hinweg werden `TraceIDs` wiederholt abgefragt).
2. Die zusätzlich erzwungene Übermittlung von weiteren Meta-Informationen für **jeden** Request der App zum Backend (Gerätehersteller, Gerätemodell, Betriebssystemversion). Im Grunde genügen die wiederholt verwendeten TraceIDs, um Requests zu einem Gerät zu korrelieren. Die ergänzenden Metadaten geben allerdings weitere Korrelationsmöglichkeiten für Requests der App, welche selbst keine TraceIDs enthalten (u.a. lässt sich der Request zur Übermittlung der Telefonnummer bei der Registrierung so korrelieren). Für mobile Datenverbindungen ist es häufig der Fall, dass der Mobilfunkanbieter mehrer Geräte hinter einer IP-Adresse "kaskadiert". Die Übermittlung ergänzender Gerätedaten genügt allerdings, um diese Kaskadierung mit hoher Genauigkeit wieder zu Einzelgeräten aufzulösen (es existieren 3 Classifier mit hoher Entropie, während nur wenige Geräte hinter einer IP-Adresse kaskadiert werden).

Das Problem ist seit langem bekannt und wurde mehrfach kommuniziert. Bestrebungen zur Mängelbeseitgung waren bisher nicht erkennbar.
Ausführliche Beschreibungen, siehe: "Referenzmaterial Nr. 1" und "Referenzmaterial Nr. 2".

Die Problemstellung wird von [CVE-2021-33838 (link)](https://github.com/mame82/misc/blob/master/cve-luca/cve-2021-33838.md) erfasst.

## 2.7 Keine verifizierten Kontaktdaten für Gesundheitsamt (Umgehen der Telefonnummern-Verifikation)

Die Kontakdaten der Luca-Nutzer werden weitestgehend **nicht verifiziert**. Die Ausnahme bildet hierbei die Telefonnummer, die bei der Registrierung durch den Nutzer angegeben wird. Die Telefonnummer stellt damit das einzige verlässliche Datum im Falle einer nötigen Kontaktaufnahme durch ein Gesundheitsamt dar.

Die Telefonnummer-Verifizierung lässt sich jedoch umgehen, da deren erfolgreiche Durchführung keine Voraussetzung für die Registrierung eines Nutzers ist. Die Registrierung eines **gültigen Nutzers** kann nicht nur unabhängig von der SMS-TAN-Verifizierung erfolgen, sondern es sind auch beliebige Telefonnummern verwendbar.

Die Problemstellung wird von [CVE-2021-33840 (link)](https://github.com/mame82/misc/blob/master/cve-luca/cve-2021-33840.md) erfasst.

## 2.8 Schlüsselanhänger (Badges)

Es existieren derzeit zwei Versionen von Badges, welche sich im Umlauf befinden (V3 und V4).

Es ist öffentlich nicht bekannt, wie viele der Badges der Version 3 im Umlauf sind. Aus Betreiber-Sicht ist dies allerdings auf mehreren Wegen feststellbar (z.B. sind die `UserIDs` der Version 3-Badges für das fünfte Byte wie folgt maskiert: `BadgeUserID[4] = BadgeUserID[4] & 0xf0`, siehe auch [Code link](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/locations/src/components/RegisterBadge/RegisterForm/SerialCode/SerialCode.helper.js#L64)).

Die Unterscheidung in Badges der jeweiligen Versionen ist in sofern relevant, als dass die Badges der Version 3 das gesammte Schlüsselmaterial mit vergleichsweise schwachen kryptografischen Hash-Funktionen erstellen. Dies soll kurz erläutert werden:

Die Badges repräsentieren Nutzer (analog zu Nutzern, welche sich per Luca-App registrieren). Im Gegensatz zu App-Nutzern, können geheime Schlüssel nicht sicher auf dem Gerät eines Nutzers gespeichert werden, sondern werden in den Badges kodiert. Geheime Schlüssel sind unter anderem:

- `tracingSeed`: Basis zur Ableitung des `tracing secret`. Aus dem `tracing secret` können **alle** `TraceIDs` generiert werden, welche für Check-Ins eines Schlüsselanhängers verwendet werden. Ist dieses Secret bekannt, können damit alle Locations, bei denen der Schlüsselanhänger eingecheckt war, abgeleitet werden (`TraceIDs` für Check-Ins und zugeordnete Locations werden im Backend unverschlüsselt gespeichert). Beliebige `TraceIDs` waren zeitweise ohne Authentifizierung von außen abfragbar, sodass Check-In-Historien für Schlüsselanhänger wiederhergestellt werden konnten (["LucaTrack"](http://lucatrack.de)). Mittlerweile werden API-Anfragen für Check-In-Daten zu `TraceIDs`, welche Schlüsselanhängern zugeordnet sind, nicht mehr beantwortet (vergleiche [code link 1](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/traces.js#L137), [code link 2](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/traces.js#L168)), dennoch liegen die entsprechenden Daten unverschlüsselt in der Postgres-Datenbank des Backends. **Das `TracingSeed`, welches zur Zuordnung der Check-In-Historie benötigt wird, leitet sich aus der Seriennummer eines Badges ab, ist aber auch Bestandteil des QR-Codes (welcher naturgemäß für Check-Ins gezeigt werden muss)**
- `user data secret`: Der symmetrische AES128-Schlüssel zu den verschlüsselten Kontaktdaten des Nutzers, welche in der Datenbank des Luca-Backends gespeichert sind (`encrypted contact data`, vergleiche Abschnit 1.1). **Das `user data secret` leitet sich aus der Badge-Seriennummer ab und ist nicht Bestandteil des QR-Codes. Die Seriennummer ist aber auf Vorder- oder Rückseite des Badges aufgedruckt.**
- `user key pair`: Aus der Seriennummer eines Badges leitet sich auch ein asymmetrisches Schlüsselpaar ab. Der öffentliche Schlüssel, der sich darazs ergibt, wird (neben der UserID) vom Backend als Auswahlkriterium für Nutzerdatensätze herangezogen.  
  So war es beispielsweise möglich, für Badges der Version 3 mit bekannter Seriennummern die Kontaktdaten der Badge-Nutzer zu überschreiben, sofern ein Datensatz für den Public Key des `user key pair` vorhanden war (für existierende Badges ist dieser Datensatz immer vorhanden, für Badges der Version 4 war dies nicht durchführbar, da der komprimierte public key - also ein anderes Format - als Identifier in der Postgres-Datenbank diente). Die gemeldete Sicherheitslücke wurde in einem Gitlab Issue dokumentiert ([link](https://gitlab.com/lucaapp/web/-/issues/16)) und zum "error report" umdeklariert (betroffen war hier das IT-Sicherheits-Schutzziel "Integrität").  
  Aufgrund des abweichenden Public Key Formates lässt sich durch den Betreiber auch feststellen, wie viele Badges der Version 4 im Einsatz sind (für die Datensätze von App-Nutzern, Nutzern die über Kontaktformulare angelegt wurden und Nutzern von Badges der Version 3 werden **unkomprimierte** public keys verwendet).  
  **Das `user key pais` leitet sich aus der Badge-Seriennummer ab und ist nicht Bestandteil des QR-Codes. Die Seriennummer ist aber auf Vorder- oder Rückseite des Badges aufgedruckt.**

Zusammenfassend kann man sagen: Das gesamte Schlüsselmaterial für Badges leitet sich aus der Seriennummer ab. Die Seriennummer selbst repräsentiert dabei die Base32-Crockford-kodierte Form eines 56Bit Zufallswertes (vom sogenannten "Badge Generator" festgelegt). Die Funktion des "Badge Generators" entfällt derzeit auf "neXenio" (also die Firma, die auch das Luca-System selbst entwickelt und Security-Issues handhabt), wie in einem weiteren Gitlab Issue dokumentiert wurde ([link](https://gitlab.com/lucaapp/web/-/issues/15)):

```
... Currently, there are 29,000 badges in use, we [neXenio] do not have a distinction in
V3/V4 here. These are currently created by a member of the security team of neXenio on
behalf of culture4life and luca and are directly transferred to the producer in NRW without
any detours. ...
```

Technische Maßnahmen, die eine missbräuchliche Nutzung - der beim "Badge Generator" bekannten Seriennummern aller Schlüsselanhänger - verhindern, sind derzeit nicht aus dem Quellcode ableitbar.

Ungeachtet dessen wird **jedem**, dem der QR-Code eines Schlüsselanhängers zur Kenntnis kommt, die `TracingSeed` bekannt gemacht.

Für Badges der Version 3 werden alle geheimen Schlüssel, ausgehend von der 56Bit-Seriennummer, auf Basis von SHA256-Hashes generiert. Erst für Badges der Version 4, kommt hier das wesentlich ressourcenaufwendigere `argon2` Hash-Verfahren zum Einsatz. Im Resultat sind **QR-Codes von Schlüsselanhängern der Version 3 anfällig für Brute-Force-Angriffe**.

Der im QR-Code enthaltene `TracingSeed` leitet sich wie folgt aus der Seriennummer ab (`SerialBytes` als 56Bit Byte-Sequenz, also nicht Base32 codierte Form).

```
// Die 7 Byte Seriennummer wird um das byte 0x02 ergänzt und mit SHA256 gehasht.
// Vom resultierenden SHA256 Hash, werden die ersten 16 Byte als TracingSeed verwendet
TracingSeed = SHA256(SerialBytes + (byte) 0x02).slice(0, 16)
```

Nimmt man an `0x3f0ab086a8246e397ba2e202ee4bbd4a` repräsentiert das `TracingSeed`, welches aus dem offengelegten QR-Code eines Schlüsselanhängers der Version 3 extrahiert wurde, liese sich bereits mit Standard-Tools ein Angriff durch Laien starten, auch wenn nur 16 Bytes des SHA256-Hashes verwendet werden. Als Beispiel soll hier John-The-Ripper (JtR) dienen (in der Praxis würde man einen performanteren Ansatz wählen, der auch alle "Matches" für den gekürzten SHA256-Hash zurückliefert).

**haslist.txt:**

```
tracingseed1:3f0ab086a8246e397ba2e202ee4bbd4a
```

**JtR Aufruf zum Bruteforce des partiellen SHA256-Hashes (liefert bei Erfolg nur ersten Treffer, verwendet nur die ersten 16 Byte des Hashes als Match-Kriterium):**

```
john --mask='?b?b?b?b?b?b?b\x02' --fork=8 --format=dynamic_1029 hashlist.txt
```

Führt ein solcher Bruteforce-Angriff zum Erfolg, ist das Ergebnis die Seriennummer des Schlüsselanhängers, aus der sich das gesammte Schlüsselmaterial ableiten lässt.

Ein Bruteforce-Angriff wäre ebenfalls denkbar, indem man für "geratene" Seriennummern NutzerIDs ableitet und dann prüft, ob diese Nutzer existieren (API-Endpunkt `api/v3/users/{userId}`). Für Badges der Version 3 bleibt der Bruteforce-Aufwand dabei vertretbar (zeimaliges Hashen mit SHA256), erst Badges der Version 4 bauen hier Hürden durch Verwendung von `argon2` als Hash-Funktion auf. Das [IP-basierte Rate-Limit zur Abfrage von `userIDs`](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/users.js) stellt für Bruteforce-Angriffe kaum ein Hindernis dar (vgl. Abschnitt 2.1)

## 2.8.1 Plausibilität beim Schlüsselanhänger-Check-In wird unzureichend geprüft

Ein QR-Code eines Schlüsselanhängers beinhaltet zusätzlich eine `Attestation Signature`, welche im Grunde eine Signatur der im QR-Code enthaltenen Daten darstellt. Diese Signatur basiert auf dem privaten Schlüssel des "Badge Generators" (Entität, welche die Schlüsselanhänger erstellt). Ein Angreifer, welcher die Seriennummer eines Schlüsselanhängers kennt, kann zwar (ohne Kenntnis des QR-Codes) das gesammte Schlüsselmaterial zu diesem Badge ableiten, nicht aber die `Attestation Signature`. Theoretisch könnte damit verhindert werden, dass ein Akteur, der die Badge-Seriennummner kennt, nicht aber den QR-Code (und die beinhaltete `Attestation Signature`), den Schlüsselanhänger wahllos in Locations eincheckt. In der Praxis wird die `Attestation Signature` aber **nur vom "Scanner-Frontend"** (also einem aktiven QR-Code-Scanner, den der Location Owner betreibt) **geprüft**, bevor das "Scanner-Frontend" den eigentlichen Check-In am entsprechenden API-Endpunkt vollführt. Der Backend-API-Endpunkt für Check-Ins nimmt keine weitere Signatur-Prüfung vor (und kann es technisch auch nicht). Ein Angreifer kann deshalb Badges, zu denen die Seriennnummer bekannt ist, ohne Probleme in beliebige Locations einchecken - ohne Kenntnis der `Attestation Signature`.

Bemerkenswert an dieser Stelle:

Die `Attestation Signature` ist unterschiedlich aufgebaut für Badges der Version 3 ([Link: V3 Signature check - Variante 1](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/scanner/src/utils/qr.js#L53), [Link: V3 Signature check - Variante 2](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/scanner/src/utils/qr.js#L59)) und der Version 4 ([Link: V4 Signature check](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/scanner/src/utils/qr.js#L140)). Der Quellcode, welcher Entitäten in der Rolle eines "Badge Genrators" erlaubt hat, Badges der Version 3 zu generieren, ist allerdings nie veröffentlicht worden. Der API-Endpunkt zur Badge Generierung lässt in allen veröffentlichten Quellcode-Varianten ausschließlich Signaturen für V4 Badges zu (Signatur über `userId + encrypted contact data reference`, siehe auch [Link: Signature Check bei Badge Erstellung](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/users.js#L117)).  
Ebenso wurde der Source Code zur Badge-Erstellung durch "Badge Generator"-Entitäten nur für Badges der Version 4 veröffentlicht. Es lässt sich daher nicht sagen, ob der PRNG, der zur Generierung der Seriennummern von V3 Badges zum Einsatz kam, ggf. Mängel aufwies (die z.B. erlauben würden, gültige Seriennummern zu "erraten").

## 2.8.2 Schlüsselanhänger Designfehler (persönliche Bemerkung)

Das Konzept der Schlüsselanhänger (oder "static badges") vereint - nach meiner persönlichen Meinung - mehr Designfehler allein auf sich, als der verbleibende ["Security Overview"](https://luca-app.de/securityoverview/intro/landing.html) abbildet.

Allem voran ist hier die **Ableitung aller kryptologischen Geheimnisse aus einem 56 Bit Zufallswert - welcher durch den Nutzer nicht veränderbar ist und als Seriennummer auf den Schlüsselanhänger gedruckt wird -** zu nennen. Bedenkt man, wie die Schlüsselanhänger zu nutzen sind (Vorzeigen zum Scannen), ist diese Seriennummer kaum geheim zu halten.

Eine bekannte gewordene Seriennummer erlaubt es, die mit dem Schlüsselanhänger verknüpften Kontaktdaten beliebig zu ändern (rückwirkend, da Kontaktdaten bei Änderungen systemweit überschrieben werden) und die Anhänger an beliebigen Orten einzuchecken (ein bekanntgewordener Badge-QR-Code genügt dafür auch). Da die "allmächtige" Seriennummer der Schlüsselanhänger durch den Nutzer nicht veränderbar ist, wird insbesondere dem ersten Problem (Änderung der Kontaktdaten), auf fragwürdige Art und Weise begegnet:

- Das System verhindert das Lesen der hinterlegten Kontaktdaten durch die Besitzer der Schlüsselanhänger vollständig
- Das Schreiben der Kontaktdaten ist nur **einmal** erlaubt (Registrierung des Anhängers durch Nutzer). Eine Fehlerbehebung oder die Aktualisierung der Kontaktdaten ist seitens Besitzer des Schlüsselanhängers nachträglich nicht mehr möglich.

Es gab aber bereits einen Fehler, der die nachträgliche Veränderung der Kontaktdaten zu Schlüsselanhängern ermöglicht hat, hier haben die "Absicherungsmaßnahmen" dazu geführt, dass der tatsächliche Besitzer des Anhängers von dieser Änderung nichts bemerken konnte ([Demo Video, Youtube](https://youtu.be/WjV0nCAojg4), [Gitlab Issue/fix](https://gitlab.com/lucaapp/web/-/issues/16)).

Kurz vor der Meldung des vorgenannten Sicherheitsproblems wurde außerdem festgestellt, dass mit Schlüsselanhängern vorgenommene Check-Ins durch Gesundheitsämter nicht auswertbar waren. Ursächlich war ein "kleiner" Programmierfehler: Für die Schlüsselanhänger-Erstellung und -Registrierung wurden Seriennummern anders dekodiert, als im Frontend des Gesundheitsamtes (Base32 vs. Base32-Crockford). Im Resultat wurde für Abfragen durch das Gesundheitsamt nicht nur ungültiges Schlüsselmaterial erzeugt, sondern auch ungültige NutzerIDs und TraceIDs. Für diese TraceIDs konnten im System gar keine Check-Ins abgefragt werden.

Aus meiner Sicht erneut bemerkenswert: Wie der gemeldete Security-Issue (hier war erneut das Schutzziel der "Integrität", aber auch der "Verfügbarkeit" betroffen, [vergl. Kurzauszug aus der Meldung - Twitterlink](https://twitter.com/mame82/status/1392209069352574983)) abgearbeitet wurde:

Auch hier wurde ein gemeldeter Security-Issue zu einem "Error Report" umdeklariert ([vgl. Gitlab Issue](https://gitlab.com/lucaapp/web/-/issues/15)). Da das Problem klar umrissen wurde, konnte es auch schnell behoben werden ([Update - Link Gitlab](https://gitlab.com/lucaapp/web/-/commit/2eb0c4687e65d0c1f095803cf1c21b9fcc5bd68e)). Allerdings fiel auch auf, dass der angepasste Code verzugsfrei am Produktionssystem integriert wurde - kein Rollout auf einem Referenzsystem, kein Staging, vor allem **keine Tests**. Dies mag für eine überschaubare Änderung vertretbar sein, dass eine solche Kernfunktion allerdings wochenlang unbemerkt ohne Funktion war, hat auch gezeigt: **Es gab hier nie funktionale Tests**.

In dem zugehörigen [Gitlab Issue](https://gitlab.com/lucaapp/web/-/issues/15) wurde dazu folgende Bemerkung veröffentlicht:

```
We followed up on this issue. We were able to determine that history retrieval via serial
number was no longer possible due to the incorrect renaming of the Base32 Crockford function
in one of the latest luca releases.
```

Aus der Commit-Historie war ein solches `"...incorrect renaming of the Base32 Crockford function..."` nicht ersichtlich (zwischen dem Initial Release und diesem Patch lagen mittlerweile **10 Version-Patches**, davon 1 Minor Release Update, über eine Zeit von einem Monat Codeanpassungen). Der fehlerhafte Patch, der dieses Problem verursacht haben soll, ist vor dem Initial-Commit der Version `v1.0.0` für mich bis heute nicht erkennbar. Aus meiner persönlichen Sicht heißt dies: Es fehlt nicht nur an Tests für Patch-Deployments, sondern es finden auch **keine hinreichenden funktionalen Tests für Kernfuntionalitäten des Systems statt**. Das Kommunikationsverhalten bzw. "Acknowledgment" des Herstellers zu gemeldeten Problemen erscheint im Vergleich zu anderen Vendoren höchst fragwürdig. Ich selbst würde sogar soweit gehen zu sagen, dass das **Herstellerverhalten nicht nahelegt, dass man an der Verantwortung geachsen ist, die sich aus der Gestaltung des Luca-Systems (bezogen auf die Systemteilnehmer) ergibt**.

# 3. Input filtering / Output filtering

## 3.1 Allgemeines

Dieser Abschnitt bildet den Kernteil dieser Notizen, da hier aus meiner Sicht die offensichtlichsten und eklatantesten Mängel bestehen. Ich möchte diese exemplarisch am Beispiel des "Health Department Frontends" anhand der Kontaktdaten von Nutzern des Systems darstellen (Kontaktdaten sind nutzerkontrollierter Input). Es existieren auch an anderen Stellen Eingabedaten (Input), welche nach Verarbeitung im System wieder zu Ausgabedaten werden. Ob diese Ausgabedaten dann über definierte Schnittstellen an nachgeordnete Systeme weitergegeben werden (Export, Anbindung an externer APIs) oder vom Luca-System selbst verwendet werden (z.B. zur visuellen Darstellung oder System-internen Weiterverarbeitung) spielt keine Rolle, sofern man folgenden "common sense" Maßstab anlegt:

1. **Eingabedaten (Input) ist zu validieren**
2. **Ausgabedaten (Output) sind entsprechend des Kontextes, in dem sie verwendet werden, zu kodieren oder zu "escapen", um ungewünschte Interpretation im Ziel-Kontext zu vermeiden**

Vor der Erläuterung dieser Methodik und deren Abgrenzung gegen Sanitization, möchte ich einige Beispiele für Input im Luca-System und die entsprechenden Output-Kontexte darstellen.

Geht man davon aus, dass die Kernfuntionalität des Luca-Systems die digitale Abbildung von Kontaktlisten (gefüllt mit Gästedaten), welche (auf Anfrage) an ein berechtigtes Gesundheitsamt übermittelt werden sollen, darstellt, erscheint die Untergliederung in Input/Output zunächst einfach:

1. Ein Gast stellt seine Kontaktdaten als Input für eine Location bereit (Output Kontext ist ein einzelner Datensatz für eine Gästeliste, z.B. in Form eines Datenbankeintrages für eine Tabelle)
2. Aus Sicht der Location ist jeder Gästedatensatz ein Tabelleneintrag für die Gästeliste, welcher als solcher validiert werden muss (z.B. Spaltenanzahl, Typ und Länge der Spaltenwerte). Bevor dieser Datensatz in die Datenbank eingetragen wird, muss er im Kontext der Datenbank codiert werden.
3. Nach Abfrage durch das Gesundheitsamt, wird eine solche Gästeliste zum Input (der validiert werden muss), der Output-Kontext könnte hier beispielsweise HTML zur Darstellung im Browser sein, aber eben auch ein proprietäres Format zur Weiterverarbeitung in nachgeordneten Fachanwendungen.

In der technischen Umsetzung gestaltet sich diese Untergliederung weitaus komplexer. Dies soll im nächsten Abschnitt (auszugsweise) aufgezeigt werden.

## 3.2 Einige Beispiele für Input und zugehörige Output-Kontexte (exemplarischer Auszug, abstrakt)

1. Input: Datensatz aus Kontaktdaten von Nutzern (Name, Adresse, Telefonnummer etc)  
   1.1 Output Kontext 1: Visuelle Darstellung im Web-Frontend eines Gesundheitsamtes (Healt-Department Frontend)  
   1.2 Output Kontext 2: Werte zur Einbindung in Datenbankabfragen im Health-Department Fronetnd (z.B. Abgleich ob die angegebene Telefonnummer bereits eine TAN-Verifizierung ausgelöst hat)  
   1.3 Output Kontext 3: Nutzung in Exportformat im Health-Department Frontend (z.B. Konvertierung zu CSV)  
   1.4 Output Kontext 4: Nutzung als Input für Schnittstelle aus dem Health-Department Frontend (z.B. externe API)
2. Input: Checkin Traces mit "additional data"  
   2.1 Output Kontext 1: Visuelle Darstellung im Healt-Department Frontend  
   2.2 Output Kontext 1: Visuelle Darstellung der "additional data" im Location Frontend (Tischnummer, sonstige Zusatzdaten die für Gäste erhoben worden)  
   2.3 Output Kontext 3: Visuelle Darstellung der "additional data" in der App eines Gastgebers für ein "Private Meeting" (Vor- und Nachname des Gastes)  
   2.4 Output Kontext 4: Nutzung als Input für Requests gegen die Luca Backend API (z.B. Auschecken des traces, mit `TraceID` des Inputs)

Diese Darstellung von Input und Output ist noch immer zu abstrakt, um eine korrekte Filterung anzusetzen. Darüber hinaus wurde der Input hier Kontext-frei betrachtet. Der "additional data" Anteil von traces (vergleiche Abschnitte 1.2 und 1.2.1) kann zum Beispiel Input für das "Location Frontend", für das "Health Department Frontend" als auch für die App des Gastgebers eines "Private Meetings" sein.

Dennoch sollte bereits hier klar sein, dass das Output Encoding, je nach Kontext, schnell komplex werden kann:

So wäre z.B. im Kontext der Browser-Darstellung Input der als HTML interpretiert werden könnte, so zu codieren oder zu escapen, dass er eben nicht als HTML interpretiert wird (ein String wie `<img>..` müsste zu `&lt;img&gt;...` werden) und auch Sub-Kontexte (wie eingebettetes JavaScript) wären zu beachten. Wird die Darstellung von externen UI-Frameworks übernommen (Luca verwendet `React`) ist ggf. auch der Kontext von Templatesprachen zu beachten (um z.B. Angriffe durch "Template Injection" zu verhindern).

Im Kontext von Datenbankabfragen wäre der Output wiederum so zu kodieren, dass keine unerwünschten Abfragen ausgelöst werden. Einen als String in einer Datenbank zu speichernde Location Name kann durchaus `Hipster Bar'; DROP TABLE users; --'` lauten, wenn man ihn vor Speicherung in der Datenbank z.B. mit Base64 kodiert.

Setzt man eine saubere Input-Validierung an, kann man bereits viele Problemstellungen ausschließen. Idealer Weise nimmt man eine solche Validierung in zwei Schritten vor, als Beispiel soll hier eine Postleitzahl dienen. Zur Validierung könnten hier die beiden folgende Schritte vorgenommen werden (Luca verarbeitet Postleitzahlen als Zeichenketten, nicht als Integer):

1. Validierung der Struktur, z.B. für deutsche Postleitzahlen: Die Postleitzahl besteht nur aus Ziffern, sie überschreitet nicht die maximale Länge von 5 Zeichen
2. Validierung Semantik/Plausibilität (Kontextabhängige Prüfung): Für Locations sind nur Postleitzahl aus dem Zuständigkeitsereich registrierter Gesundheitsämter zulässig, für Postleitzahlen aus Nutzerkontaktdaten sind nur Postleitzahlen aus den vorgesehenen Regionen zulässig

Entscheidend für die Input-Validierung ist auch, wo diese ansetzt. Unter funktionalen Gesichtspunkten kann die Validierung dort erfolgen, wo bspw. ein Nutzer Daten bereitstellt (z.B. innerhalb der App). Unter dem Aspekt der Sicherheit, muss eine Validierung von Eingabedaten dort erfolgen, wo eine schadhafte Manipulation weitestgehend ausgeschlossen ist.

Konkret heißt das, für Nutzerkontaktdaten die erst im Web-Frontend des Gesundheitsamtes entschlüsselt werden, dass die Input Validierung in diesem Frontend, unmittelbar nach der Entschlüsselung vorgenommen werden muss. Luca zeigt kaum Ansätze dies zu tun. Der Großteil der verschlüsselten Daten wird Client-seitig (vor Verschlüsselung validiert). Unter dem Sicherheits-Aspekt kann eine solche Validierung vernachlässigt werden, da Angreifer Daten unter Umgehung des Clients einbringen können. Für unverschlüsselte gespeicherte Daten (z.B. Kontaktdaten iner Location), wird hier für die meisten API Endpunkte des Backends zumindest eine Validierung gegen das Datenbankschema angesetzt (korrekte Datentypen, korrekte Größe/Länge der Daten).

Für verschlüsselte Daten findet kaum Input Validation oder Output Encoding statt, wenn überhaupt kommt irgendwo in der Verarbeitungskette der Daten "Sanitization" zum Einsatz. Demgegenüber stehen zahlreiche Kontextwechsel im Datenfluss, welche - jeder für sich - Angriffsfläche bieten. Für Angreifer mit durchschnittlichen Kenntnissen, wird dieses Problem auch mit einem kurzen Blick in den Quellcode klar. Auf Entwickler-Seite sollte diese Problem ohnehin offensichtlich sein. Selbst wenn "security-by-design" kein Paradigma ist, müssen Mängel in der Input Validation und im Output Encoding im Testing auffallen. Offensichtlich werden entsprechende Tests aber nur äußerst zaghaft etabliert. Warum entsprechende Fehler in den beworbenen Penetration Tests mit **Whitebox Ansatz** nicht auffallen, lässt sich nicht mehr logisch erklären.

Die nächsten Abschnitte behandeln **einen** Input-Kontext und **einen** Output-Kontext im Zusammenhang der jüngst öffentlich gemachten "CSV Injection" Schwachstelle, um Fehler im Input/Output Filtering aufzuzeigen, welche auch an anderen Stellen zu finden sind, aber nicht bis zur Demonstration eines funktionierenden Angriffes ausgearbeitet wurden.

Die Betrachtung beschränkt sich zur Vereinfachung daher zunächst auf "Nutzerkontaktdaten im Health-Department Frontend" als Input und auf "CSV Exporte aus dem Health-Department Frontend" als Output.

## 3.3 Vorbemerkung: Öffentliche Darstellung der Sicherheitsmechanismen des Luca-Systems vs Realität

Der nächst folgende Abschnitt soll exemplarisch darstellen, wie das Luca-System mit Eingabe- und Ausgabefilterung umgeht. Als Beispiel dienen die Kontakdaten von Luca-Nutzern, welche als Input ihren Weg in verschiedene Output-Kontexte **direkt im Applikationsanteil des Luca-Systems, welchen die Gesundheitsämter nutzen, finden (das "Health Department Frontend")**.

Dennoch erlaube ich mir zunächst einige Vorbemerkungen zur Chronologie der Ereignisse um die jüngst demonstrierte Schwachstelle, denn ich halte diese persönlich für entscheidend, bei der Frage: **"Ist der Hersteller des Luca-Systems vertrauenswürdig?"**

Diese Frage ist nicht technisch-objektive zu beantworten, aber dennoch essenziell, denn: **Das technische Design des Luca-Systems setzt, in weiten Teilen, einen vertrauenswürdigen Hersteller und Betreiber voraus!**

Als Ausgangspunkt für die Erläuterungen soll zunächst der Versions-Stand des Luca-Systems in der damaligen Version [v1.1.11 vom 25. Mai 2021 (link)](https://gitlab.com/lucaapp/web/-/tree/v1.1.11) dienen. Es handelt sich dabei um die Version, die im Einsatz war als die [CSV Injection Schwachstelle (Video Link)](https://vid.wildeboer.net/videos/watch/8aba8997-6dd0-45b2-9e14-d1eb1f259f3e) demonstriert wurde, über die das "Health Department Frontend" durch manipulierte Kontaktdaten von Luca-Nutzern angegriffen werden konnte.

Entscheidend bei der Wahl dieser Version: Bereits am 04. Mai 2021 erschien ein ["Zeit" Artikel (link)](https://www.zeit.de/digital/datenschutz/2021-04/luca-app-gesundheitsaemter-corona-kontaktverfolgung-hackerangriff-risiko), in dem das Risiko von "CSV Injections" durch manipulierte Nutzer-Kontaktdaten thematisiert wurde. Der Artikel hatte eine technische Tiefe, bei der sogar von einzelnen Zeichen gesprochen wurde, die einen solchen Angriff auslösen können:

```
... Das ist der Grund, warum CSV-Dateien beispielsweise keine Sonderzeichen wie "=", "@" oder ";" enthalten sollten und vor dem Import validiert oder gefiltert werden müssen, damit sie beim Einlesen keinen Schaden anrichten ...
```

Der CEO des Luca-Herstellers kam in dem selben Artikel zu Wort und stellte klar:

```
"Eine Code Injection über den Namen ist bei Luca im Gesundheitsamt nicht möglich." Sollte im Namen Schadcode enthalten sein, werde dieser von React – der dahinterliegenden Software-Bibliothek, die Luca nutze – entsprechend behandelt und "sichergestellt, dass hier kein Schaden entsteht".  Auch in Sormas selbst werde das Thema "sicherlich auch nach etablierten Standards umgesetzt".
```

In einer öffentlichen Diskussion zum Thema, knokretisierte der CEO sein Statement via [Twitter(link)](https://twitter.com/patrick_hennig/status/1389613832742612994) noch am Tag des Artikels und legt dar, dass bezüglich CSV Injections "... beim Entschlüsseln der Daten die OWASP Empfehlungen ..." zu CSV Injections umgesetzt werden:

```
Das war aber nur ein Teil meiner Antwort. Der zweite Teil, dass sowohl SORMAS beim Import als auch wir beim Entschlüsseln der Daten die OWASP Empfehlungen zu CSV Injections umsetzen, steht leider nicht da.
```

Dieser Austausch entstand, aufgrund meiner kritischen Äußerungen gegenüber der Argumentation, dass man versucht Code Injections mittels "ReactJS" zu verhindern (React wäre für Output-Kontexte wie JavaScript oder HTML relevant - zur Verhinderung von Cross-Site-Scripting, aber nicht für Code Injections in Kontexten wie CSV). Aus dem Twitter-Statement war außerdem ableitbar, dass die zitierten OWASP Empfehlungen "beim Entschlüsseln der Daten" angelegt werden (also an den Input), nicht etwa an die resultierenden CSV-Daten (also Output Encoding/Escaping). Dies erschien **nicht schlüssig**. Sollte die Filterung tatsächlich direkt an Eingabedaten vorgenommen werden, würde dies zu technischen Problemen führen (Missachtung andere Output-Kontexte, Encoding für den CSV-Kontext würde sich beispielsweise auf den Output-Kontext für Web-basierte Browserdarstellung auswirken usw.).

Bis zum erscheinen des "Zeit" Artikels vom 04. Mai 2021 war ich zwar mit verschiedenen Aspekten des Luca-Systems befasst, aber nicht mit dem konkreten Szenario von "CSV Injections". Nur einen Tag später, am 05. Mai 2021, wurde ich erneut via Twitter auf das Problem aufmerksam.  
Ein Tweet unter dem handle "@gnirbel" stellte fest, dass die beworbenen OWASP Mitigationsmaßnahmen gegen "CSV Injection" erst wenige Stunden vor Veröffentlichung des "Zeit" Artikels - am 03. Mai 2021 - in den Quellcode gepatcht wurden ([Link zum Tweet](https://twitter.com/gnirbel/status/1389949006000934915)).

Hier wurde nicht nur erneut so schnell am Live-System gepatcht, dass Tests offensichtlich gar nicht durchfühbar waren. Dabei ging hier um ein Sicherheitsfeature, welches wenige Stunden nach dem Patch als umgesetzt beworben wurde (Beachtet man die Vorlaufzeit zur Veröffentlichung eines solchen Artikels, muss man sogar davon ausgehen, dass der Patch eingepflegt wurde, nachdem gegenüber der "Zeit" erklärt wurde, dass OWASP Vorgaben zur Mitigation von CSV Injections umgesetzt waren).

Aufgrund dieses Tweets wurde auch sehr schnell klar - was vorher unklar war:

Setzt das Output-Encoding für den CSV-Kontext wirklich direkt "beim Entschlüsseln der Daten" (am Input) an?

Der "Filter" aus besagtem Patch befand sich hier: [Code link](https://gitlab.com/lucaapp/web/-/commit/2f878ef9e624224722aa073ee71cb8703f6728f1?page=7#7691cd5a586200d7401cc54324010eae3f559fdc)

Angwendet wurde er [hier](https://gitlab.com/lucaapp/web/-/commit/2f878ef9e624224722aa073ee71cb8703f6728f1?page=7#18895b77c1e5c724c891e09f24ab44236d617e56_20_51) und angewendet wurde er [hier](https://gitlab.com/lucaapp/web/-/blob/2f878ef9e624224722aa073ee71cb8703f6728f1/services/health-department/src/utils/decryption.js#L90) und [hier](https://gitlab.com/lucaapp/web/-/blob/2f878ef9e624224722aa073ee71cb8703f6728f1/services/health-department/src/utils/decryption.js#L162).

Ein sehr kurzer Blick in diesen "schnell nachgeschobenen" Patch genügt, um festzustellen:

- Filterung wird tatsächlich unmittelbar nach der Entschlüsselung von Rohdaten angesetzt (nach einem Kontext-Wechsel zu JavaScript, denn die entschlüsselten Daten wurden "noch schnell" als JSON geparst)
- Auch ohne umfassende Kenntnis des Luca-Codes wird damit klar: **Eine Filterung an dieser Stelle kann sich nicht auf einen CSV Output-Kontext beziehen, denn es gibt hier noch keinen CSV-Output**
- Es handelt sich auch nicht um eine Input Validierung, denn die Funktionalität validiert kaum Annahmen, die über den Input getroffen werden müssen
- statt Eingabe-Validierung und Ausgabe-Kodierung kommt eine Art "Sanitization" zum Einsatz, die offensichtlich an einer Stelle platziert wurde, an denen nicht allen relevanten Ausgabe-Kontexten Rechnung getragen werden kann, welche aus Sicherheitsgründen gefiltert werden müssten (man könnte hier seitens Entwickler allerdings entgegen halten, dass man "maliziösen Input" ausschließlich für den Sonderfall "CSV Injection" behandeln wollte)

Nach dieser (sehr ausführlichen) Einleitung soll nun zunächst betrachtet werden, welche Kontextwechsel der User-Input im "Health Department Frontend" durchläuft (beschränkt auf verschlüsselte Kontaktdaten)

## 3.4 Verarbeitungskette von Nutzer-Input zu resultierenden Output-Kontexten im "Health Department Frontend" (Rückblick auf v1.1.11)

Betrachtet werden hier (stellvertretend) nur die Kontaktdaten der Luca-Nutzer als Input, es sei aber nochmals darauf hingewiesen, dass es verschiedene weitere Eingabedaten gibt, die der Kontrolle von externen Teilnehmern unterliegen.

Die Kontaktdaten sind ab dem Moment, in dem sie im Luca-Applikationsanteil der Gesundheitsämter verarbeitet werden (im "Health Department Frontend"), als **unvalidierter Input** zu sehen. Eine vorherige, Client-seitige Validierung der Kontaktdaten hat keinen relevanten Effekt, da diese immer durch den Nutzer umgangen werden kann. Vielmehr, laufen die besagten Kontaktdaten verschlüsselt im Gesundheitsamt aus, so dass auch eine Vorab-Validierung durch das Luca-Backend ausgeschlossen ist. Die Validierung der Daten und die Kontext-agnostische Kodierung kann deshalb erst im Gesundheitsamt erfolgen.

Funtionale Prozesse, die den Abruf, die Entschlüsselung und weitere Verarbeitung der Daten auslösen, werden nicht mitbetrachtet.

### Schritt 1: Entschlüsselung der Kontaktdaten

Zunächst werden die bereits auf dem Server hinterlegten `encrypted contact data` des Nutzers abgerufen: [Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L70).

Die verschlüsselten Daten liegen zunäschst als Base64 codierter String mit einer maximalen Länge von 1024 Byte vor ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/backend/src/database/models/users.js#L15)) und werden zunächst dekodiert ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L80)). Ein ungültiger Base64 String würde hier eine Exception auslösen, ob diese zu einem "crash" des "Health Department Frontend" oder zum "Übergehen" des Datensatzes führt, wurde nicht geprüft. Nach der Base64-Dekodierung ergeben sich bis zu 768 Bytes an Binär-Daten, die durch externe Nutzer **beliebig gestaltet werden können** (werden als Hex-kodierter String repräsentiert).

Nach der Entschlüsselung der Kontaktdaten (AES128 CTR), wird der Klartext als UTF-8 String dekodiert ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L77)). Ergäbe sich hier kein gültiges UTF-8, würde dies erneut eine Exception auslösen.

Es kann also festgehalten werden, dass an diesem Punkt ein UTF-8 String, mit einer Länge bis zu 768 Bytes vorliegt, welcher durch Systemnutzer beliebig gestaltet werden kann.

### Schritt 2a: Überführen der Kontakten in ein JavaScript Objekt (Kontext Wechsel)

Der UTF-8 String aus Schritt 1 durchläuft nun den ersten Kontext-Wechsel und wird mittels `JSON.parse()` in ein JavaScript Objekt überführt ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L87)). Die Input Validation entfällt hier auf den JSON Parser, ein ungültiger JSON String würde ebenfalls eine Exception auslösen.

An dieser Stelle ist festzuhalten, dass das **erwartete** Objekt folgendes Schema haben sollte (Pseudocode):

```
{
  "v":  Typ Integer/Number          // 3 für App-Nutzer, 2 für Badges
  "fn": Typ String, Länge beliebig  // Vorname
  "ln": Typ String, Länge beliebig  // Nachname
  "pn": Typ String, Länge beliebig  // Telefonnummer
  "e":  Typ String, Länge beliebig  // Email
  "st": Typ String, Länge beliebig  // Strasse
  "hn": Typ String, Länge beliebig  // Hausnummer
  "pc": Typ String, Länge beliebig  // Postleitzahl
  "c":  Typ String, Länge beliebig  // Stadt
  "vs": Typ String, Länge beliebig  // nur für Badges, userVerificationSecret (Base64 kodiert)
}
```

Als Input Validation erfolgt durch die Funktion `assertStringOrNumericValues` eine Typen-Überprpfung des Kontaktdaten-Objektes ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L88)). Die Funktion löst eine Exception aus, wenn eine der `properties` des Objektes einen Wert enthält der nicht dem Typ `number` oder `string` entspricht ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/typeAssertions.js#L3)).

**Diese rudimentäre Eingabe Validierung ist unzureichend**:

- Es findet keine vollständige Validierung der Struktur statt. Ein Vorname darf hier beispielsweise durchaus vom Typ `number` sein oder die Objekt-Property `"v"` wird mit einem Wert des Typs `string` belegt. Dies kann nicht vorhersehbare Folgen auf den Programmfluss der Applikation im Gesundheitsamt haben, wie z.B. einen "Crash" beim Verarbeiten eines manipulierten Datensatzes.
- Da hier (noch) nicht geprüft wird, ob ausschließlich Objekt-Properties vorhanden sind, welche genäß der erwarteten Struktur vorgesehen sind, kann der Weg für Angriffe im JavaScript-Kontext geebnet werden. Als Beispiel sei hier die Vobereitung einer "Prototype Pollution" genannt (Objekt-Schlüssel wie `__proto__` oder `constructor` werden nicht unterbunden). Eine diesbezügliche Eingabe Validierung erfolgt erst später.
- Es findet keinerlei semantische Validierung statt. Eine Postleitzahl kann beispielsweise eine Zeichenkette beliebiger Länge, ohne weitere Beschränkung der zulässigen Zeichen, darstellen, welche (je nach Output Kontext) vollkommen anders interpretiert werden kann.

**Das diese Unter-Sektion "Schritt 2a" und nicht "Schritt 2" heißt, ist der überwiegend schlechten Code Qualität des Systems geschuldet. Zur Erläuterung ist nun doch ein Exkurs in die Prozess-Gestaltung des Luca-Systemes nötig. Der hier beschriebene Ablauf trifft nur für Kontaktdaten zu, die durch das Gesundheitsamt direkt bei NutzerInnen abgerufen werden, im Rahmen der Abfrage ihrer Location Historie (Infektionsfall, vergleiche hierzu [Luca Security Overview "Tracing the Check-In History of an Infected Guest"](https://luca-app.de/securityoverview/processes/tracing_access_to_history.html)). Dass ein Nutzer der direkt vom Gesundheitsamt kontaktiert wird, versucht einen Angriff mit manipulierten Kontaktdaten durchzuführen, ist ohnehin eher unwahrscheinlich.**

**Es gibt allerdings weitere Prozesse, in denen manipulierbare Kontaktdaten als Input verarbeitet werden, nämlich dann wenn das Gesundheitsamt die Kontakte einer Infizierten Person bei den Locations abfragt, welche von dieser Person besucht wurden (Gästelisten). Der funtionale Prozess wird hier beschrieben: [Luca Security Overview "Finding Potential Contact Persons"](https://luca-app.de/securityoverview/processes/tracing_find_contacts.html). Wesentlich hierbei: Ein Angriff auf diesen Prozess ist viel wahrscheinlicher, da Angreifer beliebig viele Nutzer mit Schadhaften Kontaktdaten anlegen und in belieibig viele Locations einchecken können (vergleiche Abschnitt 2.3 und 2.7). Die Datenverarbeitung im Gesundheitsamt erfolgt, sobald eine Location die "Gästelisten" bereitstellt (die Kontaktdaten sind dabei durch LocationbetreiberInnen nicht einsehbar/validierbar).**

**Was heißt "schlechte Code Qualität"? Ganz einfach: Der Code zur Entschlüsselung der Kontakdaten ist redundant vorhanden, nimmt aber an anderen Stellen keine Filterung mehr vor. Dies ist nur ein Beispiel für eine durchgängig unsaubere, überkomplizierte, Wartungs-intensive und Fehler-anfällige Code-Struktur. Für durchschnittliche Entwickler dürfte die Fehleranalyse und -beseitigung am statischen Code extrem aufwendig sein. Man müsste hier schon mindestens mit dynamischer Analyse ansetzen und dabei riskieren Angriffs-relevante Code-Pfade nicht zu erkennen. Automatisierte und manuelle Tests werden zwar beworben, aber unter dem Stichwort "Code Coverage" im Hinterkopf, wird man diesbezüglich kaum fündig werden. "Threat Actors" dürfen sich hier freuen, denn diese werden Angriffs-Vektoren eher über "Fuzzing", automatisierte "Control-flow Analysis" oder "Instrumentation" ausfindig machen, und dabei sicher schneller fündig als der Code angepasst werden kann.**

**Aus "Schritt 2a" wird also im nächsten Abschnitt der eigentliche "Schritt 2".**

#### Randbemerkung zur JSON Input Validierung:

_An anderen Stellen des Luca-Systems wird ähnlich verfahren (keine vollständige Eingabe Validierung), allerdings kommen andere JSON-Parser zum Einsatz. So nutzt die Android App zum Beispiel `Gson` als Parser, welcher für Gleitkomma-Typen auch Werte wie `NaN` (Not-a-Number)oder `INF` (Infinity) zulässt. Insbesondere eine ungefilterte Nutzung eines des Wertes `NaN` im Java-Kontext der Android App, würde dazu führen, dass die Ergebnisse aller in der Verarbeitung vorkommenden Operationen ebenfalls `NaN` werden (Stichwort "NaN Poisoning")._

### Schritt 2: Überführen aller Kontakten einer "Gästeliste" in JavaScript Objekte (Kontext Wechsel)

Wie erläutert, existiert die bereits beschriebene Funktionalität zum entschlüsseln von Kontaktdaten auch an anderen Stellen im Code:

- für Kontaktdaten von Location-Gästen mit App: [Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/decryption.js#L124)
- für Kontaktdaten von Location-Gästen mit Schlüsselanhängern: [Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/decryption.js#L58)

**In keinem der beiden Code-Pfade findet die in "Schritt 2a" beschriebene (rudimentäre) Validierung der JavaScript Objekte die sich aus beliebig wählbaren Kontakdaten ergeben noch statt.**

Die beiden vorgenannten Code-Pfade werden in der Funktion `decryptTrace` zusammengefasst, welche neben anderen Daten (nicht im Scope dieses Dokumentes), auch das JavaScript Objekt - welches aus den entschlüsselten Kontaktdaten entsteht - als `userData` zurück gibt ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L92)).

An dieser Stelle kann man festhalten, dass das resultierende `userData` Objekt beliebige Properties, Werten beliebiger Typen abbilden kann, die durch Luca-Nutzer frei wählbar sind.

Die beinhaltet auch "nested objects", die z.B. genutzt werden können, um bei einem weiteren Kontext-Wechsel zu Frameworks wie `React` eine "Client-side Template Injection" zu provozieren, wenn die Daten als unvalidierter Input für eine unsichere `React Component` dienen (diesbezüglich wurden keine Betrachtungen unternommen). Als Nachlese sei hier auf folgenden Artikel verwiesen: [Link](https://medium.com/dailyjs/exploiting-script-injection-flaws-in-reactjs-883fb1fe36c1). Eine Objekt wie das im Artikel erwähnte, wäre als `userData` problemlos platzierbar:

```
// result in userData, after decryption and JSON parsing
{
 _isReactElement: true,
 _store: {},
 type: "body",
 props: {
   dangerouslySetInnerHTML: {
     __html:
     "<h1>Arbitrary HTML</h1>
     <script>alert(‘No CSP Support :(')</script>
     <a href='http://danlec.com'>link</a>"
    }
  }
}
```

#### Randbemerkung

_Im Kontext des Angriffsvektors "Prototype Pollution" genügt dies allein nicht, da `JSON.parse()` Objekt-Schlüssel wie `__proto__` als reine Property bedient (statt einen `Setter` zu verwenden). Die relevanten Properties, müssten in der weiteren Verarbeitung noch unter Nutzung eines `Setters` in einem JavaScript-Objekt platziert werden._
**Bemerkenswert ist allerdings, dass der Backend Code (auch in der aktuellsten Version, `v1.1.16` at time of this writing) Nutzer-Input in einer Form verarbeitet, die hierzu als "door opener" dienen kann.** [Link zu Code Beispiel: Durch Location Betreiber frei wählbare Namen für "addititional data" Felder.](https://gitlab.com/lucaapp/web/-/blob/44e9db888015c8188900dc861f5fc69939ed6aab/services/contact-form/src/components/hooks/useRegister.js#L30) _Hier hier wären z.B. Input wie `additionalData-constructor` als Object-key möglich._

### Schritt 3: Abruf der Daten als state von `React` Komponenten (erneuter Kontext-Wechsel)

Für "Schritt 2" wurde festgehalten, dass unvaldierte Nutzerdaten durch die Funktion [decryptTrace (link)](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/utils/cryptoOperations.js#L92) als JavaScript Objekte bereitgestellt werden (nach mehreren Kontextwechseln). Abgesehen vom hoffentlich vorhandenen Exception-Handling beim Dekodieren der Daten, findet hierbei so gut wie keine Filterung statt. **Es sei daran erinnert, dass die Eingabe-Validierung unterlassen wird, obwohl sehr genaue Informationen über die erwartete Struktur und Semantik dieser Daten vorliegen.**

Diese Daten werden aber nicht einfach in die jeweiligen Ausgabe-Kontexte "gepusht", sondern die Funktion `decryptTrace` muss aufgerufen werden ("pull" Prinzip). Da es sich beim "Health Department Frontend" um eine JavaScript-basierte Web-Applikation handelt, deren Logik weitestgehend "lokal" (im Browser des Gesundheitsamtes) läuft, könnte man annehmen, dass die Daten zur Verarbeitung keinen weiteren Kontext-Wechsel durchlaufen, bevor sie den vorgesehenen Ausgabe-Kontexten zugeführt werden. Die Implementierung spricht hier allerdings eine andere Sprache.

Die besagte `decryptTrace` Funktion wird [hier (Code Link)](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L57) aufgerufen. Sie wird auf ein ganzes Array von Kontaktdaten angewendet (die Daten die der "Gästeliste" einer Location zu einem definierten Zeitpunkt entsprechen). Weniger entscheidend ist dabei die Funktion die unmittelbar im Anschluss invalide Datensätze herausfiltern soll ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L61)), denn hier wird lediglich geprüft, ob die "Check-ins" zu denen die Kontaktdaten entschlüsselt wurden, über eine gültige Signatur verfügt haben. (Dies kann eine AngreiferIn ohne Probleme sicherstellen. Auch können schadhafte Kontakdaten problemlos mit gültigen Signaturen versehen werden).

Entscheidend ist, wo dieser Code-Anteil ausgeführt wird. Denn, die `ecryptTrace` Funktion wird in einer anonymen JavaScript Funktion ausgeführt, welche als Argument an eine `useEffect` Funktion übergeben wird ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L44)).

Die `useEffect` Funktion ist allerdings nicht mehr Bestandteil des Applikationscodes des Luca-Systems, sondern gehört zu dem bereits erwähnten `React` Framework. Es handelt sich dabei um eine (gängige) Drittanbieter-Library, deren Kernzweck die Erstellung von JavaScript-basierten Benutzerinterfaces ist ("Web UI"). `React` ist weder keine Komponente zur sicheren Verwaltung, Verarbeitung oder Modellierung von Daten. Sie geht sehr wohl mit Daten um ("state" des User Intefaces) und platziert auch einige Sicherheitsmaßnahmen - aber eben nur für den Ausgabe-Kontext eine Web-basierten User Interfaces (z.B. Mitigation von Cross-Site-Scripting beim Darstellen von Nutzerkontrollierten Inhalten). `React` behandelt explizit nicht andere Ausgabekontexte. Die `useEffect` Funktion, bildet beispielsweise einen sogenannten "hook" ab, die den **"state" des User Interfaces** aktualisiert, wenn sich Daten ändern, welche in einer `React` Komponente dargestellt werden (vergleiche [React Dokumentation (Link)](https://reactjs.org/docs/hooks-effect.html)). Im Konkreten Fall heißt das, die Daten werden wie beschrieben verarbeitet, sobald im User Interface des Gesundheitsamtes, die Darstellung für "Gästelisten (Kontaktlisten)" einer Person geladen werden.

Dies mag zunächst sinnvoll erscheinen, wenn denn dise Darstellung der einzige Ausgabe-Kontext wäre. In einem solchen Fall könnte man es sogar riskieren, das Output-Encoding für den Kontext der Web-Basierten Darstellung zu unterlassen, und sich allein auf die Schutzmaßnahmen des `React` Frameworks zu verlassen (und dabei hoffen, dass nie ein anderes UI Framework verwendet werden muss). **Allerdings handelt es sich nicht um den einzigen Ausgabe-Kontext! Die unvalidierten Kontaktdaten Objekte, welche nun zentral im "React state" hinterlegt sind, sind "Single Source of Truth" für weitere Ausgabe-Kontexte. Neben Export-Formaten wie SORMAS, Excel und CSV, dient dieser "User Interface State" auch als Input für Anfragen and die SORMAS REST API.**

Der "data flow" innerhalb des React-Kontextes wird noch konfuser:

Der `useEffekt` hook, welcher die Daten verarbeitet, ist Bestandteil der "React Komponente" `ContactPersonViewRaw` ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L22)), welche wiederum in eine `React.memo` Komponente mit dem Namen `ContactPersonView` eingebettet wird ([Code Link](https://gitlab.com/lucaapp/web/-/blob/76c4978425133286a6a72f02643e0c2207d04f46/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L108)). Liest sich kompliziert? Ist es auch! Von sauberer, nachvollziehbarer und gut dokumentierter Code-Struktur kann hier nicht mehr die Rede sein. Mit Blick auf die Daten, die hier verarbeitet werden, und das - mangels Filterung - bestehende Risikopotential, erscheint der Code nicht nur unprofessionell, sondern gefährlich. Das Stichwort "Client Side Template Injection", welches im `React Kontext` schlagartig an Relevanz gewinnt, wurde schon genannt. Man kann nur hoffen, dass alle React Komponenten, die diese Daten verwenden, entsprechend getestet und abgesichert sind.

Zur Erinnerung: Bisher gab es **für keinen Kontextwechsel, den die (beliebig gestaltbaren) Nutzerdaten durchliefen, eine ausreichende Input Validierung**. Es gab sie weder syntaktisch, noch strukturell, noch semantisch!

Der behandelte Code gehört, wie ausgeführt, zu einer `React` Komponente. Dies wird auch am Dateinamen `ContactPersonView.react.js` ersichtlich ([Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js)). Nochmals unterstreichen möchte ich dies, um den Kontext-Wechsel herauszustellen. Es findet hier nicht nur ein funktionaler Kontextwechsel der Daten statt (in das User Interface), sondern auch ein syntaktischer Kontextwechsel: `React` bietet als Template-Library Sprachfunktionen, die über die Syntax von HTML oder JavaScript hinaus gehen - eine sogenannte Templatesprache ([ersichtlich am verlinkten Code-Abschnitt, der weder gültiges HTML noch JavaScript darstellen würde](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L86)).

Auch in diesem Kontext von React-Templates existieren Sprach-Konstrukte, die bei fehlender Input Validierung oder ungenügendem Output Encoding als Angriffs-Verktoren nutzbar gemacht werden können ("Template Injection" wurde hier bereits als Beispiel genannt).

Als wäre der Weg der Daten bis zu den Ausgabe-Kontexten nicht schon verworren genug, ist man hier offensichtlich bemüht die Dinge noch komplizierter, **und damit noch Fehler-anfälliger**, zu machen. Ich beschreibe dies nur noch in Stichpunkten:

- Die React Komponente `Header.react.js` übernimmt das `traces` Argument ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L19))
- Die Komponente wird unter dem Namen `Header` exportiert ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L83)) und in die (bereits vorgestellte) Komponente [ContactPersonView.react.js (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L92) eingebettet. Die `Header` Komponente übernimmt dabei das als Argument `traces` ein Array namens `selectedTraces`, welches **für jeden Eintrag** eines der `userData` Objekte enthält (welche nicht validiert Eingabedaten enthalten).  
  Erläuterungen über den Weg der [hier)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L57) erstellten `traces` (jeweils mit ungefilterten `userData` Objekten), zum `selectedTraces` Array welches [hier (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L92) verwendet wird, erspare ich mir.  
  Grund: Die "Filterung" hat nur funktionalen Charakter (Ausschluss von Kontaktdaten-Einträgen aus der Gästeliste, die eine ausgewählte minimal-Kontaktzeit unterschreiten. "Per default" werden hier zunächst alle Kontakte gelistet).
- Die React Komponente `Header.react.js` bettet weitere React Komponenten ein, welche verschiedene Ausgabe-Konexte bedienen sollen. **Diese Sub-Komponenten haben keine Relevanz in der Darstellung des User Interfaces!** Der relevante Anteil für die (dynamische) Darstellung im User Interface, ist hier lediglich ein Download-Button ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L76))
- Das eigentliche Data-Processing(und das **je Ausgabe-Kontext** benötigte Output-Encoding, wird auf weitere (zweckentfremdete) User Interface Komponenten deligiert, an die das `traces` Array mit `userData` Objekten weitergereicht wird, im einzelnen:
  - an eine React Komponente für den CSV Export ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L50)), welche hier implementiert wird: [CSVDownload (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.helper.js#L313)
  - an eine React Komponente für den Excel Export ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L53)), welche hier implementiert wird: [ExcelDownload (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.helper.js#L84)
  - an eine React Komponente für den **CSV-basierten SORMAS Export** ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L56)), welche hier implementiert wird: [SormasDownload (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.helper.js#L508)
  - (wenn aktiviert) an eine React Komponente für den Export über **die SORMAS Rest API** ([Code Link 1](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L60), [Code Link 2](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L38)), welche hier implementiert wird: [SormasModal (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/SormasModal/SormasModal.react.js).
    - die `SormasModal` Komponente erweitert jeden Eintrag `traces` Array um eine `uuid` property und speichert das neue Array in `newTraces`. Das ungefilterte `userData` Objekt wird dabei für jeden Eintrag (mit allen weiteren Properties eines `trace`) übernommen ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/SormasModal/SormasModal.react.js#L49)).
    - Unmittelbar im Anschluss wird das `newTraces` array (mit den ungefilterten `userData` Objekten) an den `sormasClient.personPush()` Funktion weitergegeben ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/SormasModal/SormasModal.react.js#L52)). Die Funktion ist hier implementiert und nimmt für die Properties der `userData` **noch immer keine Input Validierung vor**: [Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/network/sormas.js#L35)

## 3.5 Zwischenfazit

Bisher wurde ausschließlich die `v1.1.11` des Luca "Health Department Frontends" betrachtet. Die Betrachtung dieser Version wurde auf einen sehr konkreten Fokus reduziert, nämlich die Frage:

**Sind Gesundheitsämter durch den Angriffsvektor "CSV Injection" gefährdet?**

Auslöser der Betrachtung war ein eilig nachgereichter Patch, der in diese Luca-Version - **im engen zeitlichen Zusammenhang zu einer Presse anfrage zum Thema "CSV Injections"** - einfloss. Im gleichen Zuge wurde durch die Luca-Entwickler kommuniziert, dass das System entlang der OWASP Emfehlungen gegen diesen Angriffs-Vektor abgesichert sei.

Weiter wurde die Betrachtung von Nutzer-kontrollierten Eingabedaten, welche im Luca-System verarbeitet werden, auf "Kontaktdaten" reduziert.

Trotz dieses engen Betrachtungsfokus, zeigen sich schnell eklatante Mängel im grundsätzlichen Umgang mit solchen unvalidierten Daten. Insbesondere wurde aufgezeigt, dass die Daten verschiedene Sprach-Kontexte durchlaufen, ohne jemals validiert oder gar konform zum Zielkontext kodiert werden. Ich möchte dies hier aus folgenden Gründen festhalten:

- Code Injection ist in vielen dieser Kontexte möglich, aber Mitigation beschränkt sich hier offensichtlich auf den Vektor "CSV Injection" (auch wenn disbezügliche Maßnahmen bisher noch nicht ersichtlich waren). Für den Kontext der SORMAS Rest API findet zum Beispiel keinerlei Input- oder Output-Filterung statt.
- Eingabe Validierungen an den richtigen Stellen, könnten bereits zahlreiche Injection-Vektoren mitigieren (Code Injections die auf den Datenbank-Kontext abzielen, JavaScript Injection/Cross-Site-Scripting, Template Injection, Prototype Pollution ... um nur einige zu nennen). Dies wäre allein deshalb möglich, weil für die Kontaktdaten bereits nach Entschlüsselung eine klar definierte Struktur erwartet wird. Diese wird aber nicht erzwungen. Ebensowenig werden semantische Regeln an den Input angelegt, die allein viele Zeichen ausschließen könnten, welche für Code Injection in den verschiedenen Kontexten nötig wären.
- **Die Daten-Handhabung in der Implementierung bewegt sich abseits aller "best practices". Sie ist übermäßig kompliziert, sie ist nicht konsistent (redundante Funktionalität mit unterschiedlicher Implementierung), sie erscheint hochgradig fehleranfällig. Code wie der vorliegende ist äußerst schwer zu testen, nicht nur unter dem Sicherheitsaspekt, auch funktional! (Das in Abschnitt 2.8.2 dargestellte Problem zu Schlüsselanhängern, die durch Gesundheitsämter nicht auswertbar waren, unterstreicht diese Annahme)**
- Die Diskrepanz zwischen "mangelnder Sorgfalt" und "Sensitivität der von Luca verarbeiteten Daten" lässt nur zwei Schlüsse zu: Es fehlt den Entwicklern an Erfahrung oder es wird vorsätzlich ein Sicherheitsniveau beworben, von dem man weiß, dass es nicht gehalten werden kann.
- Ein Blick in den Code von System-Komponenten, welche außerhalb des hier gewählten Betrachtungsfokus liegen, zeigt keine gesteigerte Qualität. Man muss daher annehmen, dass das gesamte System mit Implementierungsmängeln behaftet ist, welche unmittelbar in Sicherheitsrisiken münden.
- Statt den sicheren Umgang mit Daten von hochgradig-sensitivem Character in gut definierten, sauber ausgestalten und nachvollziehbar implementierten Prozessen abzubilden, vertraut man diese Daten externen Drittanbieter-Bibliotheken an (Beispiele folgen). Hierbei wird die Kontrolle über die **robuste** Datenverarbeitung nicht nur vollständig abgegeben, es sind darüberhinaus keinerlei Tests erkennbar, die sicherstellen könnten, dass die ausgelagerten Funktionalitäten auch die erwarteten Ergebnisse liefern. Dies wiegt umso schwerer, wenn komplexe Drittanbieter-Libraries eingebunden werden, um am Ende nur rudimentäre Teilfunktionalitäten zu nutzen, welche sich innerhalb des Luca-Codes mit geringen Aufwand kontrolliert abbilden liesen. Das fehlende Verständnis für das Paradigma "Security-By-Design" wird hier überdeutlich.

## 3.6 Zusammenfassung: Ungefilterter Input (`userData`), auch in der aktuellesten Luca-Version `v1.1.16`

Am Ende des Abschnitts 3.4 wurden einige Output-Kontexte für ungefilterte Kontaktdaten angesprochen.

Dieser Abschnitt soll einige dieser Output Kontexte betrachten, denn hier müsste der Input passend zum jeweiligen Kontext kodiert werden. Der Input sollte dabei bereits validiert sein. Zunächst soll resümiert werden, von welchem Input hier die Rede ist:

- Der Input wird als JavaScript Array namens `traces` bereitgestellt. Es entspricht der "Gästeliste" einer Location (**alle** Luca-Nutzer die überschneiden mit der Person die seitens Gesundheitsamt "getracet" anwesend waren)
- Jeder Eintrag (`trace`) in diesem Array, ist ein JavaScript Object welches weitere eingebettete Objekte mit den "Check-In-Daten" weitere Luca-Nutzer enthält
- Eines der eingebetteten Objekt zu jedem trace ist das (bereits umfassend beschriebene) `userData` Objekt, welches aufgrund der fehlenden Eingabevalidierung durch beliebig gestaltet werden kann

Eine Pseudo-Code Darstellung des `traces` Array:

```
// traces array (handled as "React" Component state):
[
  {
    "traceID": ...,
    "checkin": ...,
    "checkout": ...,
    // arbitraryUserData:
    //    base64 string with length up to 1024 characters, no content restriction, if:
    //      - proper base64
    //      - properbly encrypted (up to 768 arbitrary bytes)
    //      - if decryption results in proper JSON string (UTF-8 encoded)
    "userData": JSON.parse(AES128_CTR_decrypt(Base64_decode(arbitraryUserData))),
    "additionalData": ...,
    "isInvalid": ...
  },
  {
    ...
    "userData": JSON.parse(AES128_CTR_decrypt(Base64_decode(arbitraryUserData2))),
    ...
  },
  {
    ...
    "userData": JSON.parse(AES128_CTR_decrypt(Base64_decode(arbitraryUserData3))),
    ...
  },
  ...
]
```

Erwähnt sei, dass die `additionalData` Objekte ebenfalls ohne weitere Filterung "auflaufen" und (aufgrund ihrer Handhabung) ein noch höheres Potential für Injection-Angriffe bieten.

Die erwartete Objekt-Struktur für `userData` Objekte wurde unter "Abschnitt 3.4 - Schritt 1" dargestellt, kann aber vernachlässigt werden, da sie bisher nicht mittels Eingabe-Validierung durchgesetzt wurde.

Ein `userData` Objekt kann also beliebig gestaltet sein, solange die UTF-8 kodierte JSON-Repräsentation des Objektes, die Größe von 768 Bytes nicht überschreitet (nach Verschlüsselung noch immer 768 Bytes, nach Base64 Kodierung 1024 Bytes - wie vom Schema der REST API erzwungen).

Im weiteren Verlauf sollen nur noch `userData` Objekte isoliert betrachtet werden (festgelegter Fokus). Der enge Betrachtungsfokus ist der "ungüstig komlexen" Code-Struktur geschuldet, ich kann aber versichern, dass an vielen Stellen im Code ähnliche Mängel auszumachen sind. Diese herauszuarbeiten "is up to the reader".

Bisher wurde nur auf Luca-Code der Version `v1.1.11` verwiesen. Zum Zeitpunkt der Erstellung dieses Dokumentes, ist allerdings die Version `v1.1.16` im Produktionsbetrieb. Version `v1.1.16` (Release vom 02. Juni 2021) beinhaltet zusätzlich alle Patches zur öffentlich diskutierten "CSV Injection" Schwachstelle.

**ABER: Alle bisher gemachten Feststellungen zur fehlenden Eingabe Validierung, treffen analog auf die aktuellste Version des Luca-Systems zu.**

Auch in Version `v1.1.16` werden `userData` nach der Entschlüsselung nicht validiert. Siehe hierzu:

1. [Code Link v1.1.16 - Entschlüsselung/JSON-Parsing für App Nutzer](https://gitlab.com/lucaapp/web/-/blob/v1.1.16/services/health-department/src/utils/decryption.js#L121)
2. [Code Link v1.1.16 - Entschlüsselung/JSON-Parsing für Schlüsselanhänger](https://gitlab.com/lucaapp/web/-/blob/v1.1.16/services/health-department/src/utils/decryption.js#L46)).

Nach der Entschlüsselung werden die Daten, **noch immer ungefiltert**, durch die React Komponente `ContactPersonView` ([Code Link v1.1.16](https://gitlab.com/lucaapp/web/-/blob/v1.1.16/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L57)) an die React Komponente `Headers` übergeben ([Code Link v1.1.16](https://gitlab.com/lucaapp/web/-/blob/v1.1.16/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.react.js#L92)). Dort dienen die Daten als "Single-Source-of-Thruth" für jedeweitere Verarbeitungen, vollkommen unabhängig vom Ausgabe-Kontext.

## 3.6.1 Output-Kontext CSV-Export

Vorbemerkung: dieser Abschnitt ist ausfühlich gehalten. Der CSV-Export dient hier als **exemplarisches Beispiel**. Mittels des Beispieles solll analytisch dargelegt werden, dass das Luca-System (Implementierungs-bedingt) externe Eingabedaten **nicht** so filtern kann, dass Angriffe über Nutzereingaben verhindert werden. Obwohl der Abschnitt konkret den Angriffsvekor "CSV Injection" im Kontext der "CSV Export" Funktionalität betrachtet, finden sich die gleichen Fehler in zahlreichen anderen Ausgabe-Kontexten, aber auch in anderen Luca-Systemkomponenten, wieder. Eine Analyse der Zusammenhänge in "voller Tiefe" erfolgt allerdings nur für diesen Abschnitt.

## 3.6.1.1 Vorbetrachtung Output-Kontext CSV-Export: **Warum Luca bei der Filterung von Nutzerdaten versagen muss** (Definition der Anforderungen an Ein-/asugabefilterung in `v1.1.11`)

Wie am Ende des Abschnittes 3.4 dargestellt, wird das `traces` Array mit den nicht validierten `userData` Objeketen von der React Komponente `Header` and die React Komponente `CSVDownload` weitergegeben: [Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/Header/Header.react.js#L50)

Die Komponente `CSVDownload` wird in `ContactPersonView.helper.js` implementiert: [Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.helper.js#L313)

```
export const CSVDownload = ({ traces, location }) => {
  const intl = useIntl();
  return (
    <CSVLink
      data={getCSVDownloadDataFromTraces(traces, location, intl)}
      filename={`${location.name}_luca.csv`}
    >
      Download CSV
    </CSVLink>
  );
};
```

Die erstellung des CSV-Outputs wird an eine weitere React Komponente `CSVLink` delegiert.

**Die `CSVLink` Komponente gehört aber nicht zum Luca-Code, sondern wird von der externe React-Library `react-csv` bereitgestellt. Das Luca-System kann hier also gar kein CSV-bezogenes Output-Encoding mehr vornehmen. Die `CSVLink` Komponente, der externe `react-csv` Library, stellt dabei die Ausgabedaten direkt an den Nutzer bereit (die CSV Datei, welche im Gesundheitsamt heruntergeladen wird) und übernimmt damit die Aufgabe des Output-Encodings und - Escapings. Darüber hinaus, hat diese Library nun die alleinige Kontrolle über den Output, welcher dem Gesundheitsamt bereitgestellt wird.**

**Ob diese Library erwartungsgemäß funktioniert, kann nur durch Tests beantwortet werden. Der Luca-Quellcode lässt aber keine diesbezüglichen Tests erkennen. Damit werden Datenschutz- und Sicherheitskritische Funtionalitäten ungetestet nach "Extern" ausgelagert.**

Ohne Funktions- und Sicherheitstests könnte man die Verlässlichkeit solcher externen Libraries eventuell noch grob abschätzen (wenn man denn so etwas wie "Dependency Management" betreibt und dabei "Security" nicht aus den Augen verliert). VErsuch man dies, lässt sich zur `react-csv` Library folgendes feststellen:

- Luca in der Version `v1.1.11` verwendet `react-csv 2.0.3` [(Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/package.json#L36)
- Luca in der aktuellsten Version `v1.1.16` verwendet ebenfalls `react-csv 2.0.3` [(Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.16/services/health-department/package.json#L38)
- `react-csv` hat seit 01. April 2020 keine Updates mehr erfahren, `v2.0.3` war die letzte veröffentlichte Version ([Link](https://github.com/react-csv/react-csv/releases/tag/v2.0.3))
- Man könnte annehmen, die Library wäre so weit gereift, dass keine Updates mehr nötig sind, aber:
- Es warten **über 30 Pull Requests**, welche überwiegend **weitere externe Abhängikeiten auf den aktuellen Release-Stand bringen sollen** ([Link](https://github.com/react-csv/react-csv/pulls)). Die "Dependency Hell" kann hier nicht als Entschuldigung dienen. Erneut gibt man grob fahrlässig Verantwortung und Sicherheit auf.
- `react-csv` pflegt **über 70 offene issues** - ganz allein, ohne Betrachtung der weiteren Dependencies-Updates die in Pull Requests auf Umsetzung warten ([Link](https://github.com/react-csv/react-csv/issues)). Unter anderem Pflegt man hier auch das Thema "CSV Injection" seit über 2 Jahren als offenen Issue ([Link](https://github.com/react-csv/react-csv/issues/156)).

**Halten wir fest:**

---

Output-Encoding für CSV kann von Luca gar nicht vorgenommen werden, da der Output außehalb des Luca-Codes erstellt wird.

Die fehlende Input Validation nachzuholen, wäre an dieser Stelle noch denkbar, aber deplaziert, denn: Man müsste die exakt selbe Eingabe-Validierung (der `userData` Objekte) für jeden Ausgabe-Kontext redundant implementieren. Außerdem, müsste jeder bereits von den Daten durchlaufene Kontext (Kontextwechsel zu JavaScript, Kontextwechesel zu React ...) trotzdem auf diese Eingabe-Validierung verzichten.

Die Luca-Entwickler haben zwar bewiesen, dass sie durchaus gewillt sind mit redundantem Code zu arbeiten, aber auch, dass dieser dann unterschiedlich schlecht funktioniert.

---

Wo findet sich nun die Umsetzung der OWASP Empfehlungen zu "CSV Injection" statt (welche zeitgleich zum Update auf Luca `v1.1.11` als vorhanden beworben wurde)?

Nun, die Daten die an externe `CSVLink` Komponente weiter gegeben werden, durchlaufen (wie im Code Auszug dargestellt) zunächst die Funktion `getCSVDownloadDataFromTraces` ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.helper.js#L317)).

Innerhalb der `getCSVDownloadDataFromTraces` durchläuft jedes `userData` Objekt durch die Funktion `filterTraceData` ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/components/App/modals/HistoryModal/ContactPersonView/ContactPersonView.helper.js#L272)):

```
  ...traces
    .map(({ userData, isDynamicDevice, ...other }) => ({
      ...other,
      userData: filterTraceData(userData, isDynamicDevice),
    }))
```

Ich hoffe es ist deutlich geworden, dass es sich hier nicht mehr um getrennte Eingabe-Validierung und Kontext-basiertes Ausgabe-Encoding handeln kann. Dieser "Filter" kann bestenfalls noch als "Sanitizer" implementiert sein. Ein solcher Ansatz birgt allerdings Risiken und Nachteile, vor allem aber ist es weitaus schwierigiger, mit einem "Sanitizer" zu einer funktionierenden Umsetzung zu kommen und diese geeignet zu testen. Vor der tatsächlichen Betrachtung der `filterTraceData` Funktion, möchte ich die Ansätze "Input Validierung + Output Encoding" und "Sanitization" kurz gegenüberstellen.

Ich nutzer dafür einen Bildhaften vergleich:

---

_Stellen sie sich die Wasserversorgung in einem Haus vor. Es gibt, verteilt über die Etagen, mehrerer Wasserhähne (Output-Kontext). Die Wasserhähne sollen, je nach Bedarf, Wasser in der gewünschten Temperatur liefern. Die Wunschtemperatur wird über die jeweiligen Mischbatterien der Wasserhähne geregelt (kontextbasiertes Output-Encoding)._

_Damit die Wasserhähne nicht nur kaltes Wasser liefern, benötigen sie jeweils Warmwasser, mit einer definierten Minimaltemperatur (valider Input). Die Bereitstellung des Warmwassers wird, für das gesamte Haus, durch einen Warmwasserboiler gewährleistet. Dieser wird zentral am Kaltwasseranschluss platziert. Der Boiler nimmt Kaltwasser auf (unvalidierter Input) und stellt sicher, dass dieses - vor weiterleitung - immer auf die gewünschte Minimaltemperatur gebaracht wird (Input Validierung)._

_Die Analogie für "Sanitization" würde so aussehen:_

_Es kommen nur noch Wasserhähne ohne Mischbatterie zum Einsatz (kein Output-Encoding). An jedem Wasserhahn kommt Kaltwasser, mit schwankender Temperatur an (unvalidierter Input). Um trotzdem an jedem Hahn die geünschte Wassertemperatur abzugreifen, muss jeweils ein Durchlauferhitzer angebracht werden (Sanitizer). Die Wunschtemperatur bestimmt jetzt der Durchlauferhitzer (Sanitization), dieser muss aber regelmäßig nachjustiert werden, da das zulaufende Kaltwasser in der Temperatur schwankt (unvalidierter Input). Wird vergessen, an einem Hahn einen Durchlauferhitzer zu platzieren, liefert der Hahn nur Kaltwasser mit schwankender Temperatur (unkontrollierter Output). Ist einer der Durchlauferhitzer fehlerhaft (Fehler im Sanitizer), merken Sie dies erst, wenn sie sich am zu heißen Wasser die Hände verbrennen. Haben Sie nicht den gesammten Wasserkreislauf des Hauses im Blick und es werden versehentlich zwei Durchlauferhitzer in Folge durchlaufen ("double encoding"), ist das Wasser nicht zu kalt, aber sie können sich erneut die Hände verbrennen._

---

Zusammengefasst: "Sanitization" ist ein "sub-optimaler" Ansatz mit vielen Nachteilen (Wartungsintensiv, Testintensiv, muss an allen wichtigen Stellen im Datenfluss unterschiedlich Implementiert werde - je nach Kontext, ist Fehleranfällig, lässt sich häufig Umgehen).

Zurück zur `filterTraceData` Funktion.

Wie erläutert, kann dieser "Filter" - aufgrund seiner logischen Positionierung im "Datenfluss" - nur noch als Sanitizer angelegt sein (als "Durchlauferhitzer").
Der Filter muss nicht nur "nachholen", was bisher im Bereich Input Validierung versäumt wurde, der Filter muss zusätzlich das Encoding/-Escaping für seinen Ausgabe-Kontext sicherstellen.

Zur Erinnerung: **Der Ausgabe-Kontext ist NICHT "CSV (Character-separated values)". Der Ausgabe-Kontext der `filterTraceData` Funktion sind Daten, die an die React Komponente `CSVLink` übergeben werden (als neuer Input).**

Demgegnüber steht die Behauptung des Luca-Herstellers, dass "... beim Entschlüsseln der Daten die OWASP Empfehlungen zu CSV Injections ..." umgesetzt werden (vergl. Abschnitt 3.3). Das keine Filterung beim "Entschlüsseln der Daten" vorgenommen wird, muss nicht wiederholt werden. Wichtig für die Implementierung `filterTraceData` ist, dass die Aufgabe darin besteht die OWASP-Empfehlungen zu "CSV Injection" umzusetzen.

Auszug aus den OWASP Empfehlungen ([Link](https://owasp.org/www-community/attacks/CSV_Injection))

```
When a spreadsheet program such as Microsoft Excel or LibreOffice Calc is used to open a CSV, any
cells starting with = will be interpreted by the software as a formula. Maliciously crafted
formulas can be used for three key attacks:

    - Hijacking the user’s computer by exploiting vulnerabilities in the spreadsheet software,
    such as CVE-2014-3524.
    - Hijacking the user’s computer by exploiting the user’s tendency to ignore security warnings
    in spreadsheets that they downloaded from their own website.
    - Exfiltrating contents from the spreadsheet, or other open spreadsheets.

This attack is difficult to mitigate, and explicitly disallowed from quite a few bug bounty programs.
To remediate it, ensure that no cells begin with any of the following characters:

    - Equals to (=)
    - Plus (+)
    - Minus (-)
    - At (@)
    - Tab (0x09)
    - Carriage return (0x0D)

...

Alternatively, prepend each cell field with a single quote, so that their content will be read as
text by the spreadsheet editor.

```

### Kurzanalyse der OWASP Empfehlung "CSV Injection", als Anforderungsdefinition für `filterTraceData`:

---

Znuächst legt die Empfehlung den Ausgabe-Kontext fest, in dem sie gilt: **"a spreadsheet program"** (ein Tabellenkalkulationstabellenkalkulationsprogramm)

Weiter wird festgelegt, welche Teile der Input-Daten zu Filtern sind: "... cells starting with ...", also CSV-Daten welche von der Tabellenkalkulation als **Zellen** interpretiert werden.

Die ungefilterter Ausgabe müsste also zunächst in Zellen zerlegt werden, um überhaupt eine Filterung ansetzen zu können. Diese Zellenzerlegung, müsste in der Logik folgen, welche die Tabellenkalkulation zur Zellenzerlegung ansetzt.

CSV ist ein nicht sauber standardisiertes Format, welches trotzdem breite Anwendung findet. Die spiegelt sich wieder, wenn man zunächst versucht abzuleiten, wie eine Zelle überhaupt definiert ist.
Ich habe CSV zuvor bewusst als **"Character-separated values"** ausformuliert, weitaus gebräuchlicher ist allerdings die Bezeichnung **"Comma-separated values"**. In der Regel wir ein `,` (ASCII `0x2C`) als Zellentrenner verwendet. Für alle gängigen Tabellenkalkulationen ist diese Interpretation eines Zellentrenners in CSV-Eingabedaten auch der "Default". Dennoch kann grundsätzlich jedes ASCII-Zeichen als Zellentrenner festgelegt werden und wäre dann im Zelleninhalt so zu escapen, dass es **nicht als Zellentrenner interpretiert wird**.

_Häufig wird auch `;` (ASCII `0x3B`, bspw. für den SORMAS Export) oder ein `tab` (ASCII `0x09`) als Zellentrenner verwendet._

RFC4180 ([Link](https://datatracker.ietf.org/doc/html/rfc4180)) versucht die CSV-Variante formal zu beschreiben, welcher die meisten Implementierungen folgen, macht dabei allerdings deutlich, dass es keine einheitliche Spezifikation gibt. Da auch Tabellenkalkulationen ("per Default") diese Interpretation anlegen, soll diese als Betrachtungsgrundlage dienen. Zunächst heißt das, dass **ein Zellentrenner immer ein Komma ist.**

Weiter definiert der RFC4180 die CSV-Syntax wie folgt:

```
file = [header CRLF] record *(CRLF record) [CRLF]
header = name *(COMMA name)
record = field *(COMMA field)
name = field
field = (escaped / non-escaped)
escaped = DQUOTE *(TEXTDATA / COMMA / CR / LF / 2DQUOTE) DQUOTE
non-escaped = *TEXTDATA
COMMA = %x2C
CR = %x0D
DQUOTE =  %x22
LF = %x0A
CRLF = CR LF
TEXTDATA =  %x20-21 / %x23-2B / %x2D-7E
```

Was ist hier relevant zur Umsetzung der OWASP-Empfehlungen:

1. **Zellen** sind hier als `field` definiert und der **Zelleninhalt** kann in zwei Varianten vorliegen: `escaped` oder `non-escaped`
2. Für `non-ecaped` Zellen sind als Inhalt nur die **druckbaren** ASCII Zeichen `0x20-0x7E` zulässig. Die Zeichen `"` (`0x22`) und `,` (`0x2C`) sind **explizit verboten**
3. Für `escaped` Zellen sind die Inhalte mit `"` (`0x22`) zu umschließen. Die `"` gehören selbst nicht zum Zelleninhalt, da sie dem escaping dienen. Als Zelleninhalt wären dann auch die Zeichen `,` (`0x2C`), `LF` (`0x0A`) un `CR` (`0x0D`) erlaubt. Die Verwendung des Zeichens `"` (`0x22`) ist allerdings auch hier nur als Doppelfolge `""` erlaubt.
4. Eine **Tabellenzeile** (`record` / `header`) besteht aus einer einzelnen **Zelle** oder einer **Reihe von Zellen** die durch ein `,` (`0x2C`) als Zellentrenner abgegrenzt werden.
5. Enthält die Tabelle mehr als eine Zeilen, werden die \*\*Tabelleinzeilen durch `CRLF` (`[0x0D, 0x0A]`) abgegrenzt.
6. Die Tabellenzeilen `header` und `record` unterscheiden sich nur formal, nicht syntaktisch.

Die OWASP Empfehlungen beziehen sich auf das **erste Zeichen einer Zelle** und machen dabei konkrete Vorgaben, welche Zeichen zu unterdrücken oder durch Voranstellen eine `'` (`0x27`) zu escapen sind: `[=+-@]`, `0x0D` und `0x0A`.

Die Umsetzung der OWASP Empfehlung für beliebigen Input bis zur Konvertierung einer RFC4180 konformen **CSV-Zelle**, könnte etwa so aussehen (Pseudo-Code, ohne Error-Handling, Length-Checks etc):

```
// Input validation according to RFC4180
ByteArray validateCsvCellInputRFC(BytaArray inputCellContent, Bool srict) {
  ByteArray output = [];

  // printable ASCII, without ',' and '"'
  ByteArray allowedBytes = [0x20..0x21, 0x23..0x2B, 0x2d..0x7e];

  // encodable/escapable characters DQUOTE, COMMA, LF, CR
  ByteArray encodableBytes = [0x22, 0x2c, 0x0a, 0x0d];

  for (int i = 0; i < inputCellContent; i++) {
    Byte textdata = inputCellContent[i];
    if (allowedBytes.contains(textdata) || encodableBytes.contains(textdata)) {
      output.append(textdata);
    } else if (strict) {
      throw InvalidCsvCellDataException(textdata);
    }

    // if here, invalid byte gets dropped (not appended to output)
  }

  return output;
}

// Output encoding according to RFC4180
ByteArray encodeCsvCellOutputRFC(BytaArray csvCellContent, Bool escape) {
  // Input was validated according to RFC4180, thus it could be handled as ASCII
  String strField = csvCellContent.decode("ASCII");

  // check if characters exist, which require an 'encoded' field according to RFC4180
  // an encoded field has to be enclosed with '"'
  Bool requiresEnclosing = strField.containsOneOf(['"', ',', '\n', '\r']));

  // special case: escape DQOUTES '"' to 2DQUOTES '""'
  strField = strField.split('"').join('""');

  // add enclosing if required
  if (requiresEnclosing) strField = '"' + strField + '"'

  // return result as ASCII-encoded ByteArray
  return strField.encode("ASCII")
}

// Input validation according to OWASP suggestion for "CSV Injection"
ByteArray validateCsvCellInputOWASP(BytaArray validInputCellContent, Bool srict) {
  // handover to OWASP-agnostic encoding, if no strict validation is required
  if (!strict) return validInputCellContent;

  // forbidden, but still escapable during output encoding ([=+-@], 0x0D, 0x0A)
  ByteArray forbiddenFirstCharForCell = [0x3d, 0x2b, 0x2d, 0x40, 0x0d, 0x0a];

  if (forbiddenFirstCharForCell.contains(validInputCellContent[0])) {
    throw ForbiddenFirstCellCharException(validInputCellContent[0]);
  }

  return validInputCellContent;
}

// Output Encoding according to OWASP suggestion for "CSV Injection"
ByteArray encodeCsvCellOutputOWASP(BytaArray csvCellContent, Bool escape) {
  // forbidden, but still escapable during output encoding ([=+-@], 0x0D, 0x0A)
  ByteArray forbiddenFirstCharForCell = [0x3d, 0x2b, 0x2d, 0x40, 0x0d, 0x0a];

  // if cell-content starts with forbidden character, as defined by OWASP
  if (forbiddenFirstCharForCell.contains(csvCellContent[0])) {
    // if escaping is enabled, prefix with "'"
    if (escape) return ByteArray.concat([0x27], csvCellContent);

    // if escaping is disabled, drop forbidden first character
    return csvCellContent.trim(1, csvCellContent.Length); // drop first character
  }

  return csvCellContent; // no further encoding required
}

// filters unsanitized Input to RFC4180 compliant CSV-Field with "CSV Injection" prevention according to OWASP
ByteArray filterCellInputForCSV(ByteArray rawCellInput, Bool strict, Bool escapeOWASP) {
  // Input validation according to RFC4180
  ByteArray validCsvCellContent = validateCsvCellInputRFC(rawCellInput, strict);

  // Input validation according to OWASP suggestion for "CSV Injection"
  ByteArray nonEncodedCsvCellContent = validateCsvCellInputOWASP(validCsvCellContent, strict);

  // Encode Output according to OWASP (by escaping forbidden characters or dropping them)
  ByteArray encodedCellContentOWASP = encodeCsvCellOutputOWASP(validCsvCellContent, escapeOWASP); // escape forbidden characters

  // Encoding Output according to RFC4180
  return encodeCsvCellOutputRFC(validCsvCellContent);
}

```

Der Pseudo-Code zur Ein- und Ausgabefilterung von CSV-Zellen, soll herausstellen, warum die Luca-Implementierung in `filterTraceData` nicht effektiv arbeiten kann (auch wenn dei konkrete Implementierung noch nicht betrachtet wurde).

Die Pseudo-Code verhindert CSV-Injection auf **"Zellen-Ebene"**. Damit die OWASP-Filterung wie vorgeshen erfolgen kann, müssen die Eingangsdaten als **Zellinhalte** vorliegen, denn nur hier lassen sich die Vorgaben anwenden. Die `filterTraceData` Funktion aus dem Luca Code verarbeitet allerdings (beliebige) JavaScript Objekte (`userData`), also nicht Zellinhalte.  
Die `filterTraceData` Funktion könnte bestenfalls OWASP-konforme **Zelleninhalte** ausgeben, die Weiterverarbeitung wird allerdings von der `CSVLink` Komponente der `react-csv` Library übernommen. Das wiederum heißt: Die `CSVLink` Komponente, verarbeitet die Eingabedaten der `filterTrace` Funktion zunächst zu CSV-Zellen und letztendlich zu CSV. Dies ist in sofern problematisch, als das die `filterTraceData` Funktion nun gar nicht mehr zwischen Eingabedaten die als CSV-Zelleninhalte fungieren und der erzeugten CSV-Ausgabe ansetzen kann. Der Pseudo-Code stellt das Problem ebenfalls dar:

Die Funktionen `validateCsvCellInputOWASP` und `encodeCsvCellOutputOWASP` setzen die OWASP-Filterung um. Allerdings **muss diese Filterung zwischen** der RFC4180-konformen **Eingabeverarbeitung** (`validateCsvCellInputRFC`) und der RFC4180-konformen **Ausgabeverarbeitung** (`encodeCsvCellOutputRFC`) erfolgen. Nur so kann überhaupt sichergestellt werden, dass die Inhalte von CSV-Zellen gefiltert werden, auf die sich die OWASP-Empfehlungen beziehen. Analog dazu, müsste die `filterTraceData` Funktion aus dem Luca-Code innerhalb der `react-csv` Library arbeiten, nämlich da wo valide CSV-**Zellen**inhalte vorliegen, aber bevor diese Inhalte zu CSV-Dateien weiterverarbeitet werden. Da die `filterTraceData` Funktion aber logisch **vor der CSV-Verarbeitung** arbeitet, muss sie zusätzliche Anforderungen erfüllen, um die OWASP-Empfelungen umzusetzen:

- Validierung der Eingabedaten `userData` (Der Sicherheits-Effekt ist beschränkt, da eine Verarbeitung der unvalidierten Eingaben bereits in anderen Kontexten erfolgt ist. Die Eingabe-Validierung an dieser Stelle erzielt keinen Nutzen für andere Ausgabe-Kontexte - wie bspw. SORMAS Rest Schnittstelle - mehr und müsste dort erneut erfolgen).
- Genaue Festlegung, welche der Eingabedaten (`userData`) in der Weiterverarbeitung durch die `CSVLink` Komponente der `react-csv` Library, als **Zelleninhalte** angesehen werden. Die genaue Art und Weise der Weiterverarbeitung durch `react-csv` (und weiterer Libraries welche von `react-csv` eingebunden werden) muss dabei so analysiert werden, dass für **alle möglichen Eingabedaten** feststeht, wo und wie diese als Zellen interpretiert werden (deterministisch).
- Das Ausgabe-Encoding für CSV-Zelleninhalte (vergleiche Analogie im Pseudo-Code-Beispiel: `encodeCsvCellOutputRFC`) wird nun Anteilig von der Luca Funktion `filterTraceData` und von der internen Funktionalität der `react-csv` Library übernommen. Die dazu muss genau definiert sein. Funktionsanpassungen in `react-csv` müssen zu Funktionsanpassungen in der Luca Funktion `filterTraceData` führen, um sicher zu stellen, dass diese Schnittstelle klar definiert bleibt. So muss zum Beispiel klar sein, welche der beiden Komponenten das Encoding/Escaping der CSV-Zellen übernimmt.
- Nach Anwendung der Filterfunktionalität bezüglich der OWASP Empfehlungen, muss die `filtertraceData` Funktion aus dem Luca-code zusätzlich sicherstellen, dass es durch die `react-csv` Library nicht zu Veränderungen an den Eingangsdaten kommt, die die Filter wieder unwirksam machen oder zu funktionalen Problemen führen (z.B. Double-Encoding).

Zusammengefasst ergeben sich Anforderungen an die `filterTraceData` Funktion, die nur erfüllt werden können, wenn die Weiterverarbeitung der Daten, bis zum letztendlichen Export als CSV-Datei, vollständig vom Luca-Code kontrolliert wird. Mit der Verwendung einer externen Library (`react-csv`) kann dies nicht sichergestellt werden, noch kann ein Filter gegen "CSV Injection" an einer Stelle platziert werden, an der dieser Wirkung entfaltet.

---

## 3.6.1.2 Output-Kontext CSV-Export: Umsetzung der Filterung für "CSV Injections" in `filterTraceData` (`v1.1.11`)

Die ursprüngliche `filterTraceData` Funktion wurde [hier (Code Link)](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/utils/sanitizer.js#L32) implementiert:

```
import { pick } from 'lodash';
import {
  assertStringOrNumericValues,
  escapeProblematicCharacters,
} from './typeAssertions';

const staticDeviceDataPropertyNames = [ 'fn', 'ln', 'pn', 'e', 'st', 'hn', 'pc', 'c', 'vs', 'v', ];

const dynamicDevicePropertyNames = ['fn', 'ln', 'pn', 'e', 'st', 'hn', 'pc', 'c', 'v', ];

export function filterTraceData(userData, isDynamicDevice) {
  const picked = escapeProblematicCharacters(
    pick(
      userData,
      isDynamicDevice
        ? dynamicDevicePropertyNames
        : staticDeviceDataPropertyNames
    )
  );
  assertStringOrNumericValues(picked);
  return picked;
}

```

Zunächst ruft die `filterTraceData` Funktion eine weitere Funktion namens `escapeProblematicCharacters`.
Die Funktion `escapeProblematicCharacters` erhält allerdings nicht mehr das vollständige `userData` Objekt, sondern nur noch eine Kopie des Objektes, welche nur noch die eigentlich vorgesehenen Objekt-Eigenschaften (Properties) enthält, die für "Kontaktdaten" existieren dürfen.

_Vorgesehen sind die Objekt-Keys aus `staticDeviceDataPropertyNames` für Kontaktdaten von Schlüsselanhängern, bzw. aus `dynamicDevicePropertyNames` für Kontaktdaten aus der Luca-App (siehe auch Abschnitt 3.4, Schritt 1)._

Zur Auswahl der zulässigen `userData` Objekteigenschaften wird die Funktion `pick` der Library `loadsh` genutzt. Es wurde bereits ausführlich dargelegt, dass diese (semantische) Eingabe-Filterung viel früher vorzunehmen wäre. Als Beispiel wurden Angriffsszenarien wie "Prototype Pollution" benannt, die bereits vorher bei der Datenverarbeitung im JavaScript-Kontext zum Tragen kommen könnten (auch die `loadsh` Library war von "Prototype Pollution" schon betroffen). Weiter wurde dargelegt, dass andere Kontexte von dieser Filterung nicht mehr profitieren, sofern diese nicht redundant implementiert wird. So würde bswp. für den CSV-Export eine JavaScript-Objekt-Eigenschaft wie `userData.__proto__ = <something bad>` verworfen, im Verarbeitungs-Kontext für die visuelle Darstellung in der Web-Applikation bleibt sie allerdings erhalten. Klar ist auch, dass **die Werte (Values)** von zulässigen Objekteigenschaften noch immer Schaden in der weiteren Verarbeitung anrichten können. Die Funktion `escapeProblematicCharacters` musss diesem Risiko begegnen, denn sie nimmt die weitere Filterung an der Kopie des `userData` Objektes vor.

Die Werte für zulässige Objekteigenschaften, können bisher noch immer beliebig gestaltet sein. Für die Postleitzahl aus den Kontaktdaten, wären beispielsweise folgende Werte zulässig (zur Erinnerung: Nahezu alle Werte werden als String erwartet, wie in Abschnitt 3.4 dargestellt).

```
// Postleitzahl mit führender 0 als String (angenommene Eingabe)
userData.pc = "01337"

// Postleitzahl vom Type 'number', führende 0 wird vernachlässigt
userData.pc = 01337

// Postleitzahl vom Typ 'number' als '-Infinity' um Fehler zu provozieren
// aus `JSON.parse('{"p": -1e500 , ...}'))`
userData.pc = -Infinity

// nested Object
userData.pc = {"__proto__": {"__proto__": {"foo": "bar"}}}

...
```

Auch können Objekteigenschaften fehlen (das Vorhandensein eines Vornamens wird bswp. vor der Weiterverarbeitung nicht geprüft).

Erst nach der `escapeProblematicCharacters` Funktion, wird auf das neue Objekt die Funktion `assertStringOrNumericValues` angewendet, welche dem Namen nach für korrekt typisierte Object-values sorgen soll (Typ `string` oder `number`).

Auch hier entbehrt die Codeabfolge einer gewissen Logik, sofern man annimmt, dass die `escapeProblematicCharacters` Funktion nur auf die Datentypen angewendet werden soll, die als Properties im `userData` Objekt erwartet werden (also der Typ `string` für alle Kontaktdaten-Attribute und der Tpy `number` für die Property namens `"v"`, welche die Version des Kontaktdatenobjektes speichert).

Die beiden Funktionen `escapeProblematicCharacters` und `assertStringOrNumericValues` sind gesondert im Modul `typeAssertions.js` definiert ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.11/services/health-department/src/utils/typeAssertions.js#L3)):

```
import assert from 'assert';

export function assertStringOrNumericValues(object) {
  Object.values(object).forEach(value => {
    assert(typeof value === 'string' || typeof value === 'number');
  });
}

export function escapeProblematicCharacters(object) {
  const target = {};
  Object.entries(object).forEach(([key, value]) => {
    if (typeof value === 'string') {
      const valueWithReplacedPlus = value.replace('+', '00');
      target[key] = valueWithReplacedPlus.replace(/^([=-@\t\r])/, "'$1");
    } else {
      target[key] = value;
    }
  });
  return target;
}
```

Die Funktion `assertStringOrNumericValues` tut was sie laut ihres Namens tun soll: Sie stellt sicher, dass alle Werte für die Properties des übergebenen Objektes den Typ `string` oder `number` haben.

Die Funktion `escapeProblematicCharacters`, welche innerhalb von `filterTraceData` **vor der** `assertStringOrNumericValues` Funktion aufgerufen wird, muss aber noch aber noch mit Projekt-Properties beliebiger Typen arbeiten. Das macht aus logischer Sicht wenig Sinn, aus Sicherheitssicht kan es sogar hoch problematisch werden. Eine Erläuterung:

Die Funktion `escapeProblematicCharacters` erwartet als Eingabeparameter ein beliebiges JavaScript-Objekt (der Parameter ist sogar als "objekt" benannt, um dies zu verdeutlichen). Die Funktion ist weiter logisch getrennt von der `filterTraceData` Funktion (welche in `sanitizer.js` definiert wurde, `escapeProblematicCharacters` gehört aber zu dem gesonderten Modul `typeAssertions.js`). Ich stelle dies aus genau einem Grund heraus: Die Funktion ist so generisch gestaltet, dass sie Entwickler dazu verleitet, sie auch an anderen Stellen im Code zu verwenden (außerhalb der `filterTraceData` Funktion). Der Funktionsname impliziert dabei, dass für die beliebigen Objekte, welche als Parameter übergeben werden können, "problematische Zeichen" gefiltert werden. Zeichen können aber nur in Objekt-Properties vom Typ String gefiltert werden! Was passiert also mit Properties, welche nicht vom Typ String sind?

Die Codezeile `target[key] = value;` beantwortet diese Frage: Jede Objekt-Property, deren Wert (`value`) nicht die Bedingung `if (typeof value === 'string')` erfüllt, wird ohne weitere Änderungen an das neue Objekt `target` zugewiesen. Der Name der jeweiligen Property (`key`) wird dabei unverändert übernommen.

Im Abschnitt 3.4 (unter Schritt 2), habe ich in einer Randbemerkung den Angriffsvektor "Prototype Pollution" angeschnitten. Dabei wurde festgehalten, dass Objekte die mittels `JSON.parse()` erzeugt werden, nicht allein für "Prototype Pollution" genutzt werden können. Es braucht ein "Sprungbrett" welches die relevanten Objekt-Properties über sogenannte **Setter** bedient. Die `escapeProblematicCharacters` Funktion "baut ein solches Sprungbrett". Würde sie an einer falschen Stelle eingesetzt, kann sie einem Angriff zum Erfolg verhelfen (Auswirkungen können vom Denial-of-Service bis zur Remote-Code-Execution im "Health-Department Frontend" reichen).

Auch diese "Sprungbrett" Funktion soll kurz erläutert werden (Für ausführliche Informationen zum Vektor "Prototype Pollution" empfehle ich eine Internetrecherche. Für Software Projekte der tragweite von Luca, wird solcher Code eigentlich im Rahmen von Sicherheitstests, -audits und Code-Reviews ausgemerzt).

**Exkurs: Prototype Pollution mittels `escapeProblematicCharacters`**

---

JavaScript ist nicht wirklich eine objektorientierte Programmiersprache (OOP). Konstrukte wie "Klassen" oder "Instanzen" von Klassen (Objekte) werden nachgeahmt. Auch das Prinzip der Vererbung wird nachgeahmt. In einer OOP würde eine Klasse den Prototyp eines Objektes dieser Klasse beschreiben. Dieser beinhaltet Attribute ("Properties" in JavaScript) und Methoden ("functions" in JavaScript). Eine Klasse `Auto` könnte bspw. festlegen das jedes Auto ("Instanz" der Klasse) ein Attribut besitzt, welches die Anzahl der Räder als `radCount` speichert (dabei würde auch festgelegt, dass diese Anzahl immer den Typ Ganzzahl hat). Die Klasse `Auto` könnte auch eine Methode wie `Radwechsel` vorgeben, die Veränderungen an den Attributen vornimmt. Entscheidend ist, dass die Klasse nur einmal existiert! Jede Instanz der Klasse (ein Objekt), würde ein tatsächliches Auto repräsentieren. Diese Objekte belegen die vorgegebenen Attribute jeweils mit unterschiedlichen Werten. So kann es ein Objekt `pkw` der Klasse `Auto` geben, welches das Attribut `radCount` mit dem Wert `4` belegt (`pkw.radCount = 4`), aber auch ein Objekt `lkw` der geleichen Klasse, welches das gleiche Attribut mit `8` belegt (`lkw.radCount = 8`). Verschiedene Programmiersprachen setzen dies formal unterschiedlich um, allen gemein ist: Eine Klasse existiert nur **einmal** zentral angelegt, aber es kann (beliebig) viele Instanzen geben, die vorgegebenen Attribute unterschiedlich belegen. Auch die Methoden einer Klasse, werden im Regelfall nur einmal implementiert.

Im Zusammenhang mit der "Prototype Pollution" sind für die JavaScript-Umsetzung von Objekt-Orientierung folgende Dinge wichtig:

1. Eine JavaScript Klasse (`prototype`) kann zur Laufzeit geändert werden. Die Änderungen wirken sich auf alle zukünftigen und bereits bestehenden Instanzen (`objetc`) der Klasse aus.
2. Jede Klasseninstanz die vom Typ `object` erbt, enthält Attribute, welche auf die Klasse des Objektes verweisen (auf den `prototype`). Da der `prototype` veränderbar ist, können diese Attribute genutzt werden, um zur Laufzeit auf den `prototype` zuzugreifen (über ein entsprechendes Attribut eines `object`) und diesen nachhaltig zu verändern. Die Veränderungen wirken sich auf **alle** Instanzen aus, welche den selben `prototype` nutzen, **wenn dies nicht verhindert wird**. Eines der Attribute, welches für jede Instanz existiert die von der Klasse `object` erbt, und Zugriff auf den `prototype` erlaubt trägt den Namen `__proto__`.
3. Ein JavaScript `object` verweist nicht nur auf seinen eigenen `prototype`, sondern der `prototype` verweist selbst auf Klassen von denen er geerbt hat. Da jedes JavaScript Objekt von der Klasse `object` erbt, ist es ohne entsprechende Vorkehrungen potentiel möglich, ausgehend von einer beliebigen Objekt-Instanz auf den `prototype` der "Basisklasse" `object` zuzugreifen und diesen zu verändern. Eine solche Änderung würde sich **global** auf alle exitierenden Objekte auswirken. (Wir d hier vernachlässigt, da bereits die Manipulation **einer** Klasse eine beliebigen Types zu unvorhersehbaren Folgen führen kann, je nachdem wie die Instanzen der Klasse weiter verwendet werden)

Ein Kurzbeispiel:

```
> obj1 = {}
> obj2 = {}
> obj1.toString()
'[object Object]'
> obj2.toString()
'[object Object]'
> obj1.__proto__.toString = function() {return "Klasse 1"}
[Function]
> obj1.toString()
'Klasse 1'
> obj2.toString()
'Klasse 1'
>
```

Das Beispiel legt zunächst zwei JavaScript-Objekte `obj1` und `obj2` an. Beide Objekte haben Zugriff auf eine Methode (`Function`) namens `toString`. Die Funktion `toString` ist in der Klasse `Object` definiert. Sowohl `obj1`, als auch `obj2` imlementieren Standard-mäßig die Klasse `Object` (da mit der Kurzschreibeweise `{}` Instanzen dieses Typs erzeugt wurden). Die Property `__proto__` erlaubt dabei den Zugriff auf die "Definition" der Klasse `Object` über eine Instanz der Klasse: so kann mittels `obj1.__proto__.toString = ...` die Methode `toString` für die Klassendefinition (für den `prototype`) der Klasse `Object` überschrieben werden. Da hier nicht eine Methode der Instanz, sondern des Prototyps überschrieben wird, wirkt sich dies auch auf `obj2` aus (in diesem Fall sogar auf alle existierenden Objekte im Scope). Die `toString()` Methode welche standardmäßig den String `'[object Object]'` zurückgibt, gibt nun für **alle** Objekte `'Klasse 1'` zurück.

!!! t.b.d. !!!!!!
(JSON.parse() mit **zu später** Einschränkung möglicher properties in Kombination mit "Setter" Verwendung - wie in escapeProblematicCharacters)

Prototype Pollution in `escapeProblematicCharacters`:

```
> jsonParsedObject1 = JSON.parse('{"foo": "bar"}')
{ foo: 'bar' }
> jsonParsedObject2 = JSON.parse('{"foo": "bar", "__proto__": {"toString":"I am not a function"}}')
{ foo: 'bar', __proto__: { toString: 'I am not a function' } }
> jsonParsedObject1.toString()
'[object Object]'
> jsonParsedObject2.toString()
'[object Object]'
> escapedObject1 = escapeProblematicCharacters(jsonParsedObject1)
{ foo: 'bar' }
> escapedObject2 = escapeProblematicCharacters(jsonParsedObject2)
{ foo: 'bar' }
> escapedObject1.toString()
'[object Object]'
> escapedObject2.toString()
Uncaught TypeError: escapedObject2.toString is not a function
>
```

## 3.6.x SORMAS Rest API (bis zur aktuellen Version `v1.1.16)

Die (Ende Abschnitt 3.4) bereits benannnte Funktion `personsPush` ([Code Link](https://gitlab.com/lucaapp/web/-/blob/v1.1.16/services/health-department/src/network/sormas.js#L35)) ist wie folgt implementiert:

```

const personsPush = (traces, currentTime = Date.now()) =>
fetch(`${SORMAS_REST_API}/persons/push`, {
headers,
method: 'POST',
body: JSON.stringify(
traces.map(trace => ({
uuid: trace.uuid,
firstName: trace.userData.fn,
lastName: trace.userData.ln,
emailAddress: trace.userData.e,
phone: trace.userData.pn,
address: {
uuid: trace.uuid,
city: trace.userData.c,
changeDate: currentTime,
creationDate: currentTime,
street: trace.userData.st,
postalCode: trace.userData.pc,
houseNumber: trace.userData.hn,
addressType: 'HOME',
},
}))
),
});

```

Für `userData` Objekte wird weder geprüft ob die erwarteten Properties vorhanden sind (ein Fehlen von keys wie `"fn"`, `"ln"` usw. würde vermutlich einen Crash im "Health Department Frontend" auslösen und die Auswertung von Gästelisten unmöglich machen), noch werden die Daten (Values) vorhandenen Properties geprüft. Durch Luca-Nutzer beliebig gestaltbare Daten, werden hier ungefiltert and die API eines nachgeschalteten Fachverfahrens weitergegeben (welches hoffentlich sauber mit dem Input umgeht).

Um im Bild der Wasserhähne zu bleiben: Es gibt keine Mischbatterien, aber auch keine Durchlauferhitzer mehr. Sie lassen Ihrem Kind trotzdem ein Bad ein, setzen es ohne weitere Prüfung in die Badewanne und hoffen, dass es mit der Temperatur umgehen kann, die Sie gar nicht kennen.

## notes

- Sanitization ist schlecht ...
- keys von "additional data" sind auch böse

Notes: JSON not strictly typed (like, f.e. Protobuf)

Output Encoding:

- sub Kontext beachten, bspw für Browser output: in HTML Kontext eingebettets JavaScript eingebettetes Javascript, bei Einsatz von Rendering Frameworks wie React, VueJS, Angular die Sprachkontext der Template-Engine (vergleiche Template Injection)
- wann Output encoding (vor Output, um z.B. Double Encoding zu vermeiden)

- Anmerkung zu nicht betrachteten Bestandteile (insb. Location Frontend)

## Ursachen persönliche Meinung

- kein Testing, schnelle Patch releases, Bewerbung von fixes ohne Test
- gravierende Fehler bleiben unbemerkt (Badge Abfrage GA)
- keine fundamental kritik an zentralem Ansatz, aber kaum einer der Fehler würde in einem dezen System gleicher Funktionalität bestehen (die **Kern**Funktionalität ist ohne zentrale Komponenten abbildbar)
- angeführte Probleme könnten schnell behoben werden, und System würde auf Basis externer Zuarbeit reifen, trotzdem überwiegt Risiko, Vergangenheit hat gezeigt, dass Betreiber der Verantwortung NICHT gerecht wird (öffentliche Irreführung, Dementi von Sicherheitslücken, Falschaussagen in Chronologie, Quellcode release ist nicht gleich Transparenz ... hier konstenlose Reviews etc etc)
- Problem überflüssiger zentraler Speicherung: Locations ohne Anbindung des Gesundheitsamtes

## sonstiges

- private meeting limit (50 Besucher) gilt nur für echtes private meeting https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/routes/v3/traces.js#L60

## Kryptoschmutz

- over engineered ... Hybridansatz, obwohl Ressourcen für asymmetrisch
- [already covered] Schlüsselanhänger Katastrophal (V3)

```

```

```

```

```

```
