# Luca Auffaellikeiten / Issues

Liste von Auffälligkeiten/Problemen mit potentieller Sicherheitsrelevanz in der "Luca" Fachanwendung.

Versionen zum Betrachtungszeitpunkt

- Backend/Web Services aus `Web` Repository: v1.1.15
- AndroidApp: v1.7.4

Die Ausführungen **haben keinen Anspruch auf Vollständigkeit** und werden ggF nach Veröffentlichung ergänzt. Das Dokument unternimmt keine Anstregungen Termini, prozessuale oder funktionale Sachverhalte zu erläutern, die sich aus dem veröffentlichten Material zu "Luca" ergeben (Dokumentaion, Quellcode). Das Dokument nimmt an, dass LeserInnen die mit dem System vertraut sind.

# Referenzmaterial

1. [Kurzanalyse Netzwerkverkehr (Erstellung Bewegungsprofile)](https://github.com/mame82/misc/blob/master/luca_traceIds.md)
2. [Youtube Playlist mit Erlaeuterungen zu diversen Problemstellungen](https://www.youtube.com/playlist?list=PLKuX6iczGb3kuDsm2RFgbmRkTugkR9-UE)
3. [Demo Video "CSV Injection" Gesundheitsamt (Download-Link, da Youtube Video entfernt)](www.cyberawareness.de/public/luca_attack5.mp4)

# 1. Erläuterungen zu Nutzerdaten im Backend (Auszug)

## 1.1 Verschlüsselte Kontaktdaten "Encrypted User Data"

Die Kontaktdaten des Nutzers werden als JSON string serialisiert und mit AES128 (Counter Mode) verschlüsselt dauerhaft auf dem Server abgelegt, sie umfassen:

- numerische Version der Kontaktdaten (2 für AppNutzer, 2 für Schlüsselanhänger)
- Vorname
- Nachname
- Telefonnummer
- Email
- Straße
- Hausnummer
- Postleitzahl
- Stadt
- Verification Secret (nur für Schlüsselanhänger)

Der Schlüssel zu den Kontaktdaten (`data secret`) ist für App-Nutzer nur Lokal bekannt, wird aber in der "verschlüsselten Kontaktdaten Referenz" bei jedem Location check-in übermittelt (vergleiche Abschnitt "Checkin-traces"; erlaubt dem Gesundheitsamt die Entschlüsselung von Kontaktdaten nach Zustimmung eines Location Operators).

Neben der Möglichkeit das `data secret` aus Location check-ins zu generieren (nach Zustimmung Location Operator), kann ein berechtigtes Gesundheitsamt den Schlüssel direkt vom Nutzer erhalten, wenn dieser ihn bereitstellt (im Rahmen des gesonderten Verfahrens zur Bereitstellung der Nutzer Location Historie an Gesundheitsamt).

**Das `data secret` für Schlüsselanhänger leitet sich aus der Seriennummer des Anhängers ab. Die Offenlegung einer Seriennummer ist also gleichbedeutend mit der Offenlegung des Crypto-Schlüssel zu den zentral gespeicherten Kontakdaten. Die Seriennummern der bisher produzierten Schlüsselanhänger, wurden durch das gleiche Unternehmen vergeben, welches auch das Luca-System entwickelt (Nexenio). Es ist daher davonn auszugehen, dass diese bekannt sind.**

Die verschlüsselten Kontaktdaten werden als Base64 String mit maximaler Länge von 1024 Zeichen gespeichert. Es lassen sich hier also **beliebige Sequenzenzen** aus 768 Bytes AES verschlüsselte Daten speichern, die vollständig vom Nutzer kontrolliert werden (input). Eine Validierung dieser Eingabedaten, kann (und muss) nur im "Health Department Frontend" erfolgen, da die Daten im Normalfall erst beim Gesundheitsamt entschlüsselt werden.

Zu den verschlüsselten Kontaktdaten wird eine Signatur angelegt. **Diese Signatur wird nicht über validierte Kontaktdaten gebildet, sondern über die "rohen" Binärdaten welche verschlüsselt werden (also 768 Bytes, die beliebig wählbar sind)**

## 1.2 Checkin-traces

Ein `Trace` bildet im Luca-System den Besuch eines Nutzers in einer Location ab, er umfasst u.a.

- checkin Zeitpunkt
- checkout Zeitpunkt (wenn bereits erfolgt)
- `TraceID` (zur eindeutigen Identifikation eines Traces; Nutzer-pseudonym, da mittels Einwegfunktion aus einzigartigem `tracing secret` des Nutzers und minutengenauem Zeitstempel generiert)
- Geräte Type (iOS App, Android App oder Schluesselanhänger)
- Location ID (verweist auf Datensatz mit **unverschlüsselten** Daten der Location)
- **verschlüsselte** "Kontaktdatenreferenz" (`encrypted contact data reference`)
  - setzt sich zusammen aus `UserID` eines registrierten Nutzers und dem `data secret` des Nutzers (der symmetrische Schlüssel zur entschlüsselung der Kontakdaten des Nutzers, welche bei Registrierung persistent in der Backend Datenbank abgelegt werden)
  - zweifach AES128 verschlüsselt
  - der innere Schlüssel wird aus dem assymetrischem `Daily Key Pair` der Gesundheitsämter (gleich **für alle Gesundheitsaemter**) mittels DLIES abgeleitet
  - für Schlüsselanhänger (badges) kommt bei der inneren Verschlüsselung nicht der `Daily Key Pair` der Gesundheitsämter zum Einsatz, sondern das sogenannte `Badge Key Pair` (ein Schlüsselpaar, welches **nicht täglich rotiert**, aber durch die Gesundheitsämter erstellt wird)
  - der äußere Schlüssel wird aus dem assymetrischem Schlüsselpaar des jeweiligen `Location Operators` mittels DLIES abgeleitet (Wichtig: dieses assymetrische Schlüsselpaar existiert nicht je Location, sondern es ist **für alle LocationGroups und Locations welche der Location Operator verwaltet gleich**)
- "additional Trace Data" (optional, durch Location Operator entschlüsselbar)
  - AES128 verschlüsselt
  - der Schlüssel wird aus dem assymetrischem Schlüsselpaar des jeweiligen `Location Operators` mittels DLIES abgeleitet (Wichtig: dieses assymetrische Schlüsselpaar existiert nicht je Location, sondern es ist **für alle LocationGroups und Locations welche der Location Operator verwaltet gleich**)
  - "additional Data" können von Location Betreibern optional zusätzlich erhoben und entschlüsselt werden. Diese Daten gehen aber auch in die Ergebnisse der Location Abfragen durch Gesundheitsämter ein (z.B. in die Datenexporte). Darüberhinaus kommt dieser Datenansatz für sogennante private Meetings zum Einsatz, bei denen der Vor- und Nachname des gastes als "additional Data" zum Checkin codiert wird und so vom Gastgeber entschlüsselt und dargestellt werden kann.
  - Ob und welche Zusatzdaten von einer Location erhoben werden sollen, wird für jede Location in einem Schema festgehalten (API Endpunkt `api/v3/locations/additionalDataSchema/{locationId}`).

### 1.2.1 Ergänzungen zu "additional Trace Data" für Location Betreiber (Bestandteil der Checkin-Traces)

Die "additional Trace Data" werden als Base64 String mit maximaler Länge von 4096 Zeichen gespeichert. Es lassen sich hier also **beliebige Byte-Sequenzenzen** von bis zu 3072 Bytes AES verschlüsselte Daten speichern, welche vollständig vom eincheckenden Nutzer kontrolliert werden (input). Eine Validierung dieser Eingabedaten, kann (und muss) an jeder Stelle erfolgen, an der die Daten entschlüsselt werden (Input) und in der Folge verarbeitet und ausgegeben werden (Output). Solche Stellen sind beispielsweise:

1. Frontend für Location Betreiber (bisher werden hier "additional Data" nicht angezeigt, es wurde aber Funktionalität hinzugefügt, welche Tischnummern als additional Data führt und im Location Frontend verarbeitet und darstellt.)
2. App, bei privaten Treffen (für private Meetings werden Ersteller des Meetings Vor- und Nachname der Gäste in der App angezeigt. Die dargestellten Daten basieren auf den "additional Data" welche der Gast - in Form eines 3072 Byte großen Blocks beliebiger Daten - beim einchecken bereitstellt)
3. **Health Department Frontend** (hier werden neben den Kontaktdaten der Gäste einer Location auch alle "additional Data" die die Gäste bereitgestellt haben verarbeitet)

# 2. Problemstellungen

## 2.1 [Backend] - IP Protokollierung

Das Backend verwendet als Schutzmechanismus u.a. IP basiertes Rate-Limiting. Der Ansatz bietet ein niedrigschwelliges Hindernis für AngreiferInnen mit durchschnittlichen Fähigkeiten (limitiert u.a. maximale Checkins, maximale Anzahl Nutzerregistreirungen usw , welche von der Gleichen IP-Adresse ausgehen). Demgegenüber stehen die Risiken die durch die **flüchtige** Speicherung der Request-IPs (nicht pseudonymisiert/gehasht) - i.V.m. mit dem genauen Endpunkt welcher angefragt wurde und Zeitpunkt des jeweils letzten Zugriffes auf diesen Endpunkt (ableitbar aus "expiry time") - in einer Redis DB einhergehen.

Entstehende privacy Risiken könnten bereits durch hashing der IP-Adresse gemildert werden.
Entstehende Möglichkeiten zur zeitlichen Korrelation der Redis Datensätze (IP-Adressen, Endpunkt, Timestamp als Expiry Time), zu weiteren mit Zeitstempeln versehenen Informationen (beispielsweise pseudonymisierte Checkins), wären durch ein "künstliches Bias" in den "Expiry times" machbar.

### Hinweis:

Analog zum IP-basierten Rate-Limiting Code, existiert Code zum Telefonnummern-basierten Rate Limiting (jeweils Mobil und Festnetz).
Die Funktionalität kommt (bisher) nur für Festnetznummern zum Einsatz, im Gegensatz zu IP-Adressen werden Telefonnummern vor Speicherung gehasht (SHA256).

1. [Code Refernz: IP-Logging](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L19)
2. [Code Referenz: **einer** Datenspeicherung in Redis](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L74)
3. [Code Referenz: Speicherung gehashter Telefonnummern (Keying)](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L26)
4. [Code Referenz: Speicherung gehashter Telefonnummern (Speicherung)](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/middlewares/rateLimit.js#L95)
5. [Code Referenz: Speicherung gehashter Telefonnummern (Anwendung)](https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/routes/v3/sms.js#L53)

### Auswirkungen

Es wurden bereits anderweitig Möglichkeiten aufgezeigt, die einem Backend beobachter (Berechtigtes Betriebspersonal oder Threat-Actor mit Zugriff), durch längere Beobachtung der Kommunikation folgende Ableitungen zu treffen:

- Zuordnung aller Checkins/Checkouts zu einzelnen Mobilgeräten
- Zuordnung der Telefonnummer zu den Mobilgeräten
- Zuordnung von Abfragen der Gesundheitsaemter zu den jeweiligen Mobilgeräten

(Vergleiche dazu Referenzmaterial 1 und 2)

Durch die Speicherung von IP-Adressen mit ableitbaren Zugriffszeiten, ergeben sich ähnliche Möglichkeiten auch **ohne längerfristige Beobachtung des Backends" bei einmaligem Datenzugriff**. Dies ist insbesondere Möglich, da die Datenlage zu einer Vielzahl an logischen Ereignissen (Nutzer-Registrierungen, Nutzer-Checkin/Checkout, Location Registrierung etc) ebenfalls mit unverschlüsselten Zeitstempeln gespeichert wird.

## 2.2 [Backend API] Unauthenticated access EP `/v3/locations/traces/{accessId}`

- Endpunkt erlaubt Abfrage von Traces einer Location ohne Authentifizierung als Operator
- benötigt wird zur Abfrage die `AccessID` der Location
  - wird bei Registrierung der location automatisch generiert (durch Postgres DB, beim anlegen Datensatz)
  - Verwendung als Query Parameter (ohne weitere Authentifizierung) birgt Risiko der Offenlegung (bspw MitM Angriffe im WiFi Netzwerk einer Location, Logging des Query-Path an Intermediaries in komplexeren Enterprise IT-Netzen/ggF Übermittlung von Queries an externe Security Services etc etc)
- Ableitbare Informationen
  - individuelle Checkin / CheckOut Zeitpunkte
  - Type des Checkins (Android App / iOS App / Schlüsselanhänger)
  - verwendete TraceID, die **TraceID ist Nutzerpseudonym**, verschiedene Nutzer können nie gleiche TraceIDs generieren (vergl Referenzmaterial 1 und 2). Für Schlüsselanhaenger (badges) zu denen der QRCode (Tracing Seed) oder die Seriennummer (erlaubt ableitung aller geheimen Nutzerschlüssel) bekannt geworden ist, **ist eine direkte Nutzer-Zuordnung der TraceIDs möglich**

## 2.3 [Backend, Health Department Frontend] Fehlende Plausibilitätsprüfungen (exemplarisch)

Die Plausibiltät der durch Nutzer und Locationbetreiber eingebrachten Daten kann technisch bedingt oft nicht zentral, sonder nur nach Entschlüsselung von Daten erfolgen. Das heißt:

- Für "encrypted user data" (vergleiche Abschnitt 1.1) kann die Plausibilitätsprüfung erst im Frontend des Gesundheitsamtes erfolgen (Anteil des Luca-Systems, ausgelegt als WebApp, Datenentschlüsselung erfolgt lokal im Browser)
- Für "additional Trace Data" (vergleiche Abschnitt 1.2.1), ist eine Plausibilitätsprüfung möglich:
  - im Frontend des Gesundheitsamtes (nach Abruf der Daten von einer Location)
  - im Frontend des Locationbetreibers (z.B. beim Auswerten von Tischnummern, welche als "additional Data" geführt werden; auch hier handelt es sich um einen Anteil des Luca-Systems, ausgelegt als WebApp, Datenentschlüsselung erfolgt lokal im Browser)
  - in der App, für private Meetings (Vor- und Nachname der Gäste werden als "additional data" geführt)

Weiter bestehen bis Heute Probleme bei der Verifizierung der Nutzer Telefonnummern (diese wird Client-seitig beim Nutzer durchgeführt und kann daher umgangen/übersprungen werden), die weiteren Kontaktdaten (Name, Adresse etc) werden ohnenhin nicht auf plausibilität geprüft.

Hieraus ergeben sich folgende Probleme, welche die Sicherheit und Nutzbarkeit des Systems schwächen können:

1. Durch Einzelpersonen können beliebig viele Luca-Nutzer registriert werden. Falsche, aber auch bereits vorhandene, Kontaktdaten können mehrfach registriert werden und die so reigstrierten Nutzer dann in beliebige Locations eingecheckt werden. Da die Telefonnummer nicht verifiziert wird, ist es auch möglich plausible Kontaktdaten fremder Personen über Checkins in (beliebige Locations) Infektionsketten einzubringen. Das einzige als Datum für das garantiert wird, dass es verifiziert sei ist dabei die Telefonnummer, welche daher durch die Gesundheitsämter zur Kontaktaufnahme herangezogen werden muss. Unter dem Fakt, dass beliebige Telefonnummern mehrfach registriert werden können, leidet nicht nur die System-Sicherheit erheblich, sondern auch dessen Funktionalität.
2. Der gleiche Nutzer kann in mehrerer Locations gleichzeitig eingecheckt werden. Festgestellt werden könnte dies (aus vorgenannten Gründen) nur im Gesundheitsamt, wenn genau dieser Nutzer "getracet" wird, also der Nutzer seine vollständige Location Historie bereitstellt. Solche unplausiblen "mehrfach Checkins" könnte im Gesundheitsamt **nicht** festgestellt werden, wenn die Kontaktdaten des Nutzers im Rahmen der Abfrage einer Location entschlüsselt werden (Location Betreiber stellt Gästeliste bereit), sofern nicht zufällig mehrere Locations abgefragt werden in denen sich der Nutzer zeitgleich befand. Hieraus ergibt sich, dass Schwachstellen die darauf aufbauen, dass manipulierte Kontaktdaten eines Nutzers (bspw. Schadcode) durch ein Gesundheitsamt verarbeitet werden, beliebig skalieren. Ein solches Angriffsszenario würde nur zum Erfolg führen, wenn das Gesundheitsamt eine Location abfragt, in der sich im Abfrage-relevanten Zeitraum ein solcher "Schadnutzer" befunden hat. Die Möglichkeit redundanter Checkins, erlaubt es Angreifern allerdings bereits einen einzelnen Schadnutzer beliebig oft in beliebig vielen Locations einzuchecken, um die Erfolgschancen eines Angriffsversuches zu steigern.
3. Aus Punkt 1 und 2 ergibt sich, dass Locations mit Checkins "geflutet" werden können (sowohl mehrfach checkins des gleichen Nutzers, als auch durch verschiedene Nutzer die Mangels funktionierender Telefonnummernverifikation in beliebiger Anzahl durch einen Angreifer registriert werden können). Es wird behauptet, dass solche "ungültigen" Checkins vor Auswertung im Gesundheitsamt herausgefiltert werden. Tests haben gezeigt, dass diese Filterung auf Signaturen der Kontaktdaten der registrieten Nutzer basiert, d.h. **sie greift ausschließlich, wenn die bei Registrierung des Nutzers verwendeten Daten nicht im vorgesehenen technischen Prozess verschlüsselt und signiert wurden. Die Signatur wird dabei nicht über validierte Kontaktdaten gebildet, sondern über Binärdaten welche beliebigen Inhalt transportieren können (vergleiche 1.1, letzter Absatz)**. Darüber hinaus ist es in vielen Angriffsszenarien unerheblich, ob die beworbene Datenfilterung überhaupt funktional ist, denn: Zur Umsetzung der Filterung selbst müssen (unter Umständen schadhafte) Kontakdaten im Gesundheitsamt verarbeitet werden.

## 2.3.1 Ergänzung Plausibilität: Locations die keine verwertbaren Daten produzieren (Ergänzung )

Es häufen sich Berichte über Locations, welche Luca als Checkin-System anbieten, aber im Zuständigkeitsbereich von Gesundheitsämtern liegen, welche nicht an Luca angebunden sind.

Die Luca Webseite bietet einen [Postleitzahlen-basierten Verfügbarkeitstest (link)](https://www.luca-app.de/nutzeluca/) an. **Dennoch wird beim Erstellen/Registrieren von Locations im Luca-System nicht geprüft, ob zu der für die Location angegebenen Postleitzahl ein zuständiges Gesundheitsamt an das System angebunden ist.** Die Unterlassung dieser Plausibilitätsprüfung führt offenbar dazu, dass gehäuft Location Betreiber Luca als **einzige** digitale Checkin-Lösung anbieten, obwohl das zuständige Gesundheitsamt die Gästelisten nie abrufen könnte (mangels Anbindung). Werden die Gästedaten durch den Location-Betreiber nicht zusätzlich in anderer Form erfasst, kommt dieser idR seiner Verpflichtung gem. gültiger CoronaSchVO nicht nach. Der Erhebungszweck der Daten durch Luca, dürfte dabei ebenfalls in Frage gestellt sein.

## 2.4 [Location Frontend] Permanentes Vorhalten des Privaten Schlüssels des Location Operators in der Browser Session

Beim Registrieren eines "Location Operators" (Betreiber einer oder mehrerer Locations), wird ein assymetrisches Schlüsselpaar erstellt, für welches der private Schlüsselanteil im Registrierungsprozess einmalig zum Download angeboten wird. Dieser private Schlüssel ist nochmals mit AES128 umschlüsselt (encrypted private key). Der zugehörige Entschlüsselungsschlüssel (`private key secret`) ist im Backend gespeichert und kann nur mittels authentifizierter Session des `Location Operators` abgerufen werden.

Der private Schlüssel des Location Betreibers kann u.a. dazu genutzt werden die "additional Trace Data" eingecheckter Gäste zu entschlüsseln (vergleiche Abschnitt 1.2 und 1.2.1) oder die äußere Verschlüsselung der "encrypted contact data reference" (vergl. Unterpunkt in Abschnitt 1.2) aufzuheben.

Diese Möglichkeit diese Entschlüsselungen vorzunehmen besteht für einen authorisierten "Location Operator" ohnehin, allerdings nicht für Angreifer die in der Lage wären durch die Asunutzung von Sicherheitslücken die Browser Session zu übernehmen. Dies begründet sich darin, dass das "Location Frontend" - auch wenn kompromittiert - in einer Browser-Sandbox läuft, aus welcher heraus ein Zugriff auf den (als lokale Datei gespeicherten) privaten Schlüssel des Location Operators nicht ohne weiteres möglich ist.

Bisher wurde der private Schlüssel des "Location Operators" nur im Bedarfsfall in den Browser geladen, nämlich dann wenn eine Abfrage der Gäste-Checkins durch ein Gesundheitsamt erfolgt und der Location Operator dieser Anfrage nachkommt. Das Risiko hierbei ist überschaubar, da der private Schlüssel nur temporär im Browser-Kontext verfügbar ist.

Mit einem Update der Web-Services Anfang Mai (v1.1.8 ??), wurde die Funktionalität des Location Frontends allerdings so angepasst, dass der Location Operator beim Login aufgefordert wird, seinen privaten Schlüssel in die Browser-Session zu laden.

Dies schwächt die Schlüssel-Sicherheit im Kontext möglicher Angriffe auf den Browser immens. Als Grund für diese Maßnahme wurde angeführt, dass der Location Operator nur so die Tischnummern der Gäste-Checkins entschlüsseln kann (diese werden als "additional data" im Checkin trace hinterlegt).

### Bewertung:

Die Funktionalität Tischnummern auf Basis des permanent in den Browser geladenen **privaten Schlüssels** des Location Operators anzuzeigen, steht im Missverhältniss zu den entstehenden technischen Risiken. Zunächst hat der private Schlüssel nicht nur Bezug zu einer Einzel-Location hat, sondern gilt global für alle Locations des Location Operators. Darüber hinaus, wäre die Segementierung eines Veranstaltungsortes in Zonen (wie "Tische"), wäre auch ohne die Verwendung des "additional data" Konstruktes möglich (das System verwaltet bereits LocationGroups, welche mehrere Locations zusammenfassen; im Frontend sind LocationGrous als "Location" benannt, welche die eigentlichen Locations als "Area" bennant werden).

Die Funktionalität der "additional data", welche durch Location-Betreiber ohne das Zutun des Gesundheitsamt, entschlüsselt werden können ist ohnehin höchst fragwürdig und bietet Missbrauchspotential. Eines der möglichen Angriffsszenarien auf "additional trace data" wird im nächsten Abschnitt dargestellt.

## 2.5 [App, Backend] Ausnutzung "additinal Trace Data", Erschleichen von Nutzerdaten durch Location Provider

Die Abschnitte 1.2 und 1.2.1 sprechen "additional Trace Data" als Konstrukt an, welches es ermöglicht an **jeden Nutzer Checkin** weitere beliebige Daten zu koppeln, welche nicht für das Gesundheitsamt verschlüsselt werden, sondern bereits durch den Location-Betreiber entschlüsselt werden können (ohne Zutun eines Gesundheitsamtes).

Es ist vorgesehen, dass der Location-Betreiber beim Erstellen von Locations festlegt, welche Daten er zusätzlich erhebt. Die Daten sollen aus key-value paaren bestehen. Über die Struktur der für eine Location zusätzlich zu erhebenden Daten wird ein Schema angelegt (vergleiche Abschnitt 1.2).

Aus funktionaler Sicht, werden die vom Betreiber vorgesehenen Zusatzdaten ("additional data") nur abgefordert, wenn der Locationbetreiber selbst seine Gäste mittels des Kontaktformulares erfasst, welches das Luca-System als zusätzliche Checkin-Möglichkeit bereitstellt. Ein self-checkin mit der App führt derzeit Beispielsweise nicht zu einer Abfrage dieser Daten (dies könnte anndernfalls durch den Location Betreiber missbraucht werden, um zusätzliche persönlche Daten von eincheckenden Gästen zu "erschleichen").

Dennoch kommt das angelegte Schema nicht zur Plausibilitätsprüfung der "additional data" die ein Gast beim einchecken bereitstellt zum Einsatz. So ist es z.B. möglich als Gast "additional data" an einen Checkin anzuhängen, obwohl dies von der Location gar nicht vorgesehen ist. Überall wo diese Zusatzdaten ungefiltert verarbeitet werden, entsteht daher zusätzliche Angriffsfläche (wird in anderen Abschnitten behandelt).

Eine riskante Konstelation ergibt sich im Zusammenhang mit den sogenannten "private Meetings". Es handelt sich dabei um Treffen, welche von Luca-App Nutzern geöffnet werden können. Gäste können dan durch Scannen des QRCodes des Gastgebers bei dem "private Meeting" einchecken. Das private Meeting unterscheidet sich (Backend-seitig) in der technischen Gestaltung nur in einem Punkt, von einer regulären Location: Der Datensatz der Location hat das Attribut `isPrivate` als `True` hinterlegt (siehe [link](https://gitlab.com/lucaapp/web/-/blob/af4bdb2a3af8d2b5d46ef8f27d69eff59516710a/services/backend/src/database/models/location.js#L87)).

Für Gäste die einchecken, unterscheidet die App zwischen "private Meetings" und "echten Locations" wiederum anhand des **Aufbaus der Location URL** im QRCode des Meetings/der Location. Der eigentliche Checkin-Prozess und die damit einhergehende Datenverschlüsselung läuft für "private Meetings" und self-checkins in "echten Locations" analog. Es existiert nur ein entscheidender Unterschied: Für **alle Locations deren QRCode den Aufbau eines privaten Meetings hat, sendet die App den Vor- und Nachnamen des Gastes als "additional data" mit (d.h. für Locationbetreiber entschlüsselbar)**. Der Übermittlung der Daten geht ein kurzer Informationsdialog voran, in dem darauf hingewiesen wird, dass für private Meetings Vor- und Nachname übermittelt werden.

Aufbau der Checkin-URL für eine reguläre Location:

```
https://app.luca-app.de/webapp/{scannerID}#...
```

Aufbau der Checkin-URL für ein privates Meeting:

```
https://app.luca-app.de/webapp/meeting/{scannerID}#...
```

**Da die App an keiner Stelle überprüft, ob es sich bei der Ziellocation tatsächlich um ein "privates Meeting" handelt, erfolgt die übermittlung von Vor- und Nachnamen des Gastes als "additional data" auch an Locations, welche kein privates Meeting sind aber dies in ihrem QRCode so ausweißen.** Mehr noch, wird der checkin-trace (welcher nun Vor- und Nachname des Nutzers als "additional data" enthält) vom Backend Server selbst dann gespeichert, wenn das für die Location laut Schema gar keine "additional data" anfallen dürften. Der Server könnte bei Speicherung zwar nicht auf Plausibilität der "additional data" gegenüber dem Schema prüfen (Daten sind nur durch Locationbetreiber zu entschlüsseln), aber sehr wohl feststellen das für ein Schema welches keine zusätzlichen Daten fordert, auch keine zusätzlichen verschlüsselten Daten zu speichern sind.

Mit einer minimalen Veränderung am QRcode für Self-Checkins, kann ein Location-Betreiber also die automatisierte Übermittlung von Vor- und Nachnamen eincheckender Gäste auslösen. Die Gäste werden zwar mit einem Informationsdialog konfrontiert, der aussagt, dass für "Private Meetings Vor- und Nachnamen an den **Meeting Gastgeber** übermittelt werden". Der Hinweis macht im Kontext einer Location wenig Sinn, dürfte aber ohnehin von vielen Nutzern ignoriert werden die einchecken möchten.

Der Angriff wurde hier demonstriert: [Youtube link](https://youtu.be/jWyDfEB0m08).

Die Problemstellung ist dem Hersteller [bekannt](https://twitter.com/patrick_hennig/status/1387738281757061125)

Die Problemstellung wird von [CVE-2021-33839 (link)](https://github.com/mame82/misc/blob/master/cve-luca/cve-2021-33839.md) erfasst.

## 2.6 [Backend, App] Durch Beobachtung von Netzwerkverkehr können Bewegungsprofile erstellt und mit Nutzerdaten verknüpft werden

Durch **reine Beobachtung des Netzwerkverkehrs am Backend**, lassen sich **ohne Kenntnis des Schlüsselmaterials für Kontaktdaten oder für Checkin-Traces** folgende Ableitungen treffen:

- Checkin-Historie für das Mobilgerät von teilnehmenden App-Nutzern lässt sich rekonstruieren
- für rekonstruierte Checkin-Historien lässt sich die Telefonnummer als persönliches Identifikationsmerkmal zuordnen
- für rekonstruierte Checkin-Historien lässt sich zuordnen, ob Checkins durch ein Gesundheitsamt im Rahmen der Nachverfolgung einer Infektionskette abgefragt wurden (idR ist die entsprechende Checkin-Historie damit Infektionsrelevant).

Ursächlich sind hier:

1. Hohe Abfragefrequenz von Checkins durch die App am Backend (bis zu 20-Mal pro Minute), unter wiederholter Verwendung gleicher `TraceIDs` welche **nur von einem Gerät im System stammen können (pseudonym)**. Hierdurch wird die Korrelation verschiedener Checkins zum gleichen Gerät möglich, selbst wenn das Gerät die IP-Adresse wechselt oder die Nutzung der App unterbrochen wird (auch über einen Geräteneustart werden `TraceIDs` wiederholt abgefragt).
2. Die zusätzlich erzwungene Übermittlung von weiteren Meta-Informationen für **jeden** Request der App zum Backend (Gerätehersteller, Gerätemodell, Betriebssystemversion). Im Grunde genügen die wiederholt verwendeten TraceIDs, um requests zu einem Gerät zu korrelieren. Die ergänzenden Metadaten geben allerdings weitere Korrelationsmöglichkeiten für Requests der App, welche selbst keine TraceIDs enthalten (u.a. lässt sich der Request zur Übermittlung der Telefonnummer bei der Reigstrierung so korrelieren). Für mobile Datenverbindungen ist es häufig der Fall, dass der Mobilfunkanbieter mehrer Geräte hinter einer IP-Adresse "kaskadieren". Die Übermittlung ergänzenden Gerätedaten genügt allerdings, um diese Kaskadierung mit hoher Genauigkeit wieder zu Einzelgeräten aufzulösen (es existieren 3 Classifier mit hoher Entropie, während nur wenige Geräte hinter einer IP-Adresse kaskadiert werden).

Das Problem ist seit langem bekannt und wurde mehrfach kommuniziert. Bestrebungen zur Mängelbeseitgung waren bisher nicht erkennbar.
Ausführliche Beschreibungen, siehe: "Referenzmaterial Nr 1" und "Referenzmaterial Nr 2".

Die Problemstellung wird von [CVE-2021-33838 (link)](https://github.com/mame82/misc/blob/master/cve-luca/cve-2021-33838.md) erfasst.

## 2.7 Keine verifizierten Kontaktdaten für Gesundheitsamt (Umgehung Telefonnummern Verifikation)

Die Kontakdaten der Luca Nutzer werden weitestgehend **nicht verifiziert**. Die Ausnahme bildet hierbei die Telefonnummer, die be der Registrierung durch den Nutzer angegeben wird. Die Telefonnummer stellt damit das einzige verlässliche Datum, im Falle einer nötigen Kontaktaufnahme durch ein Gesundheitsamt, dar.

Die Telefonnummer Verifizierung lässt sich jedoch umgehen, da deren erfolgreiche Durchführung keine Voraussetzung für die Registrierung eines Nutzers ist. Die Registrierung eines **gültigen Nutzers** kann nicht nur unabhängig von der SMS-TAN Verifizierung erfolgen, sondern es sind auch beliebige Telefonnummern verwendbar.

Die Problemstellung wird von [CVE-2021-33840 (link)](https://github.com/mame82/misc/blob/master/cve-luca/cve-2021-33840.md) erfasst.

## 2.8 Schlüsselanhänger (Badges)

Es existieren derzeit zwei Versionen von Badges, welche sich im Umlauf befinden (V3 und V4).

Es ist öffentlich nicht bekannt, wie viele der Badges der VErsion 3 im Umlauf sind. Aus Betreiber Sicht ist dies allerdings auf mehreren Wegen feststellbar (z.B. sind die `UserIDs` der Version 3 Badges für das fünfte Byte wie folgt maskiert: `BadgeUserID[4] = BadgeUserID[4] & 0xf0`, siehe auch [Code link](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/locations/src/components/RegisterBadge/RegisterForm/SerialCode/SerialCode.helper.js#L64)).

Die Unterscheidung in Badges der jeweiligen Versionen ist in sofern relevant, als das die Badges der Version 3 das gesammte Schlüsselmaterial mit vergleichsweise schwachen kryptografischen Hash-Funktionen erstellen. Dies soll kurz erläutert werden:

Die Badges repräsentieren Nutzer (analog zu Nutzern welche sich per Luca-App registrieren). Im Gegensatz zu App Nutzern, können geheime Schlüssel nicht sicher auf dem Gerät eines Nutzers gespeichert werden, sondern werden in den Badges kodiert. Geheime Schlüssel sind unter anderem:

- `tracingSeed`: Basis zur ABleitung des `tracing secret`. Aus dem `tracing secret` können **alle** `TraceIDs` generiert werden, welche für Checkins eines Schlüsselanhängers verwendet werden. Ist dieses Secret bekannt, können damit alle Locations in die der Schlüsselanhänger eingecheckt wurde abgeleitet werden (`TraceIDs` für Check-ins und zugeordnete Locations werden im Backend unverschlüsselt gespeichert). Beliebige `TraceIDs` waren zeitweise ohne authentifizierung von außen abfragbar, so dass Check-in-Historien für Schlüsselanhänger wiederhergestellt werden konnten ("LucaTrack"). Mittlerweile API-Anfragen für Checkin-Daten zu `TraceIDs`, welche Schlüsselanhängern zugeordnet sind, nicht mehr beantwortet (vergleiche [code link 1](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/traces.js#L137), [code link 2](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/traces.js#L168)), dennoch liegen die entsprechenden Daten unverschlüsselt in der Postgres Datenbank des Backends. **Das `TracingSeed` welches zur Zuordnung diese Checkin-Historie leitet sich aus der Seriennummer eines Badges ab, ist aber auch Bestandteil des QRCodes (welcher naturgemäß für Check-Ins gezeigt werden muss)**
- `user data secret`: Der symmetrische AES128-Schlüssel zu den verschlüsselten Kontaktdaten des Nutzers, welche in der Datenbank des Luca-Backend gespeichert sind (`encrypted contact data`, vergleiche Abschnit 1.1). **Das `user data secret` leitet sich aus der Badge Seriennummer ab und ist nicht Bestandteil des QRCodes. Die Seriennummer ist aber auf Vorder- oder Rückseite des Badges aufgedruckt.**
- `user key pair`: Aus der Seriennummer eines Badges leitet sich auch ein assymetrisches Schlüsselpaar ab. Der öffentliche Schlüssel der sich dabei ergibt, wird (neben der UserID) vom Backend als Auswahlkriterium für Nutzerdatensätze herangezogen.  
  So war es beispielsweise möglich für Badges der Version 3 möglich mit bekannte Seriennummern die Kontaktdaten der Badge-Nutzer zu überschreiben, sofern ein Datensatz für den public key des `user key pair` vorhanden war (für existierende Badges ist dieser Datensatz immer vorhanden, für Badges der Version 4 war dies nicht durchführbar, da der komrimierte public key - also ein anderes Format - als Identifier in der Postgres Datenbank diente). Die gemeldete Sicherheitslücke wurde in einem Gitlab Issue dokumentiert ([link](https://gitlab.com/lucaapp/web/-/issues/16)) und zum "error report" umdeklariert (Betroffen war hier das IT-Sicherheits-Schutzziel "Integrität").  
  Aufgrund des abweichenden Public Key Formates, lässt sich durch den Betreiber auch feststellen, wieviele Badges der Version 4 im Einsatz sind (für die Datensätze von App Nutzern, Nutzern die über Kontaktformulare angelegt wurden und Nutzern von Badges der Version 3 werden **unkomprimierte** public keys verwendet).  
  **Das `user key pais` leitet sich aus der Badge Seriennummer ab und ist nicht Bestandteil des QRCodes. Die Seriennummer ist aber auf Vorder- oder Rückseite des Badges aufgedruckt.**

Zusammenfassend kann man sagen: Das gesamte Schlüsselmaterial für Badges leitet sich aus der Seriennummer ab. Die Seriennummer selbst repräsentiert dabei die Base32 Crockford kodierte Form eines 56Bit Zufallswertes (vom sogenannten "Badge Generator" festegelegt). Die Funktion des "Badge Generators" entfällt derzeit auf "neXenio" (also die Firma die auch das Luca-System selbst entwickelt und Security Issues handhabt), wie in einem weiteren Gitlab Issue dokumentiert wurde ([link](https://gitlab.com/lucaapp/web/-/issues/15)):

```
... Currently, there are 29,000 badges in use, we [neXenio] do not have a distinction in V3/V4 here. These are currently created by a member of the security team of neXenio on behalf of culture4life and luca and are directly transferred to the producer in NRW without any detours. ...
```

Technische Maßnahmen, die eine missbräuchliche Nutzung - der beim "Badge Generator" bekannten Seriennummern aller Schlüsselanhänger - verhindern, sind derzeit nicht aus dem Quellcode ableitbar.

Ungeachtet dessen, wird **jedem** dem der QRCode eines Schlüsselanhängers zur Kenntnis kommt, die `TracingSeed` bekannt gemacht.

Für Badges der Version 3 werden alle geheimen Schlüssel, ausgehend von der 56Bit Seriennummer, auf Basis von SHA256 hashes generiert. Erst für Badges der Version 4, kommt hier das wesentlich Ressourcenaufwendigere `argon2` Hash-Verfahren zum Einsatz. Im Resultat, sind **QRCodes von Schlüsselanhängern der Version 3 anfällig für Brute-Force-Angriffe**.

Der im QRCode enthaltene `TracingSeed` leitet sich wie folgt aus der Seriennummer ab (`SerialBytes` als 56Bit Byte-Sequenz, also nicht Base32 codierte Form).

```
// Die 7 Byte Seriennummer wird um das byte 0x02 ergänzt und mit SHA256 gehasht.
// Vom resultierenden SHA256 Hash, werden die ersten 16 Byte als TracingSeed verwendet
TracingSeed = SHA256(SerialBytes + (byte) 0x02).slice(0, 16)
```

Nimmt man an `0x3f0ab086a8246e397ba2e202ee4bbd4a` repräsentiert das `TracingSeed` welches aus dem offengelegten QRCode Schlüsselanhängers der Version 3 extrahiert wurde, liese sich bereits mit Standard-Tools ein Angriff durch Laien starten, auch wenn nur 16 Bytes des SHA256 hashes verwendet werden. Als Beispiel soll hier John-The-Ripper dienen (in der Praxis würde man einen performanteren Ansatz wählen, der auch alle "matches" für den gekürzten SHA256hash zurückliefert).

**haslist.txt:**

```
tracingseed1:3f0ab086a8246e397ba2e202ee4bbd4a
```

**JtR Aufruf zum Bruteforce des partiellen SHA256 hashes (liefert bei Erfolg nur ersten Treffer, verwendet nur die ersten 16 Byte des hashes als Match-Kriterium):**

```
john --mask='?b?b?b?b?b?b?b\x02' --fork=8 --format=dynamic_1029 hashlist.txt
```

Führt ein solcher Brute-Force Angriff zum Erfolg, ist das Ergebnis die Seriennummer des Schlüsselanhängers, aus der sich das gesammte Schlüsselmaterial ableiten lässt.

Ein Bruteforce Angriff wäre ebenfalls denkbar, indem mann für "geratene" Seriennummern NutzerIDs ableitet und dann prüft, ob diese Nutzer existieren (API Endpunkt `api/v3/users/{userId}`). Für badges der Version 3 bleibt der Brute-Force-Aufwand dabei vertretbar (zeimaliges hashen mit SHA256), erst Badges der Version 4 bauen hier Hürden durch Verwendung von `argon2` als Hash-Funktion auf. Das [IP-basierter Rate-Limit zur Abfrage von `userIDs`](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/users.js), stellt für Bruteforce-Angriffe kaum ein Hindernis dar (vergleiche Abschnitt 2.1)

## 2.8.1 Plausibilität beim Schlüsselanhänger Check-in wird unzureichend geprüft

Ein Schlüsselanhänger QRCode beinhaltet zusätzlich eine `Attestation Signature`, welche im Grunde eine Signatur der im QRCode enthaltenen Daten darstellt. Dies Signatur basiert auf dem privaten Schlüssel des "Badge Generators" (Entität welche die Schlüsselanhänger erstellt). Ein Angreifer, welcher die Seriennummer eines Schlüsselanhängers kennt, kann zwar (ohne Kenntnis des QRCodes) das gesammte Schlüsselmaterial zu diesem Badge ableiten, nicht aber die `Attestation Signature`. Theoretisch könnte damit verhindert werden, dass ein Akteur der die Badges Seriennummner kennt, nicht aber den QRCode (und die beinhaltete `Attestation Signature`), den Schlüsselanhänger wahllos in Locations eincheckt. In der Praxis wird die `Attestation Signature` aber **nur vom "Scanner Frontend"** (also einem aktiven QRCode Scanner, den der Location Owner betreibt) **geprüft**, bevor das "Scanner Frontend" den eigentlichen Checkin am entsprechenden API Endpunkt vollführt. Der Backend-API Endpunkt für Checkins nimmt keine weitere Signatur-Prüfung vor (und kann es technisch auch nicht). Ein Angreifer kann deshalb Badges, zu denen die Seriennnummer bekannt ist, ohne Probleme in beliebige Locations einchecken (ohne Kenntnis der `Attestation Signature`).

Bemerkenswert an dieser Stelle:

Die `Attestation Signature` ist unterschiedlich aufgebaut für Badges der Version 3 ([Link: V3 Signature check - Variante 1](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/scanner/src/utils/qr.js#L53), [Link: V3 Signature check - Variante 2](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/scanner/src/utils/qr.js#L59)) und der Version 4 ([Link: V4 Signature check](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/scanner/src/utils/qr.js#L140)). Der Quellcode welcher Entitäten in der Rolle eines "Badge Genrators" erlaubt hat Badges der Version 3 zu generieren ist allerdings nie veröffentlicht worden. Der API Endpunkt zur Badge Generierung lässt in allen veröffentlichten Quellcode-Varianten ausschließlich Signaturen für V4 Badges zu (Signatur über `userId + encrypted contact data reference`, siehe auch [Link: Signature Check bei Badge Erstellung](https://gitlab.com/lucaapp/web/-/blob/14098e0683114479ddf3e399b79f788dc6b88e33/services/backend/src/routes/v3/users.js#L117)).  
Ebenso wurde der Source Code für zur Badge Erstellung durch "Badge Generator" Entitäten nur für Badges der Version 4 veröffentlicht. Es lässt sich daher nicht sagen, obe der PRNG der zur Generierung der Seriennummern von V3 Badges zum Einsatz kam ggF. Mängel aufwieß (die z.B. Erlauben gültige Seriennummern zu "erraten").

## 2.8.2 Schlüsselanhänger Designfehler (persönliche Bemerkung)

Das Konzept der Schlüsselanhänger (oder "static badges") vereint - nach meiner persönlichen Meinung - mehr Designfehler allein auf sich, als der verbleibende ["Security Overview"](https://luca-app.de/securityoverview/intro/landing.html) abbildet.

Allem voran ist hier die **Ableitung aller kryptologischen Geheimnisse aus einem 56 Bit Zufallswert - welcher durch den Nutzer nicht verändebar ist und als Seriennummer auf den Schlüsselanhänger gedruckt wird** - zu nennen. Bedenkt man wie die Schlüsselanhänger zu nutzen sind (Vorzeigen zum Scannen) ist diese Seriennummer kaum geheim zu halten.

Eine bekannte gewordene Seriennummer erlaubt es die mit dem Schlüsselanhänger verknüpften Kontaktdaten beliebig zu ändern (rückwirkend, da Kontaktdaten bei Änderungen System-weit überschrieben werden) und die Anhänger an beliebigen Orten einzuchecken (ein bekanntgewordener Badge-QRCode genügt dafür auch). Da die "allmächtige" Seriennummer der Schlüsselanhänger durch den Nutzer nicht veränderbar ist, wird insbesondere dem ersten Problem (Änderung der Kontaktdaten), auf fragwürdige Art und Weise begegnet:

- Das System verhindert das Lesen der hinterlegten Kontaktdaten durch die Besitzer der Schlüsselanhänger vollständig
- Das Schreiben der Kontaktdaten ist nur **einmal** erlaubt (Registrierung des Anhängers durch Nutzer). Eine Fehlerbehebung oder die Aktualisierung der Kontaktdaten ist seitens Besitzer des Schlüsselanhängers nachträglich nicht mehr möglich.

Es gab aber bereits einen Fehler, der die nachträgliche Veränderung der Kontaktdaten zu Schlüsselanhängern ermöglicht hat, hier haben die "Absicherungsmaßnahmen" dazu geführt, dass der tatsächliche Besitzer des Anhängers von dieser Änderung nichts bemerken konnte ([Demo Video, Youtube](https://youtu.be/WjV0nCAojg4), [Gitlab Issue/fix](https://gitlab.com/lucaapp/web/-/issues/16)).

Kurz vor der Meldung des vorgennanten Sicherheitsproblems, wurde außerdem festgestellt, dass mit Schlüsselanhängern vorgenommene Checkins durch Gesundheitsämter nicht auswertbar waren. Ursächlich war ein "kleiner" Programmierfehler: Für die Schlüsselanhänger-Erstellung und -Registrierung wurde Seriennummern anders dekodiert, als im Frontend des Gesundheitsamtes (Base32 vs. Base32-Crockford). Im Resultat, wurde für Abfragen durch das Gesundheitsamt nicht nur ungültiges Schlüsselmaterial erzeugt, sonder auch ungültige NutzerIDs und TraceIDs. Für diese TraceIDs konnten im System gar keine Checkins abgefragt werden.

Aus meiner Sicht erneut bemerkenswert: Wie der gemeldete Security Issue (hier war erneut das Schutzziel der "Integrität", aber auch der "Verfügbarkeit" betroffen, [vergl. Kurzauszug aus der Meldung - Twitterlink](https://twitter.com/mame82/status/1392209069352574983)) abgearbeitet wurde:

Auch hier wurde ein gemeldeter Security Issue zu einem "Error Report" umdeklariert ([vergleiche Gitlab Issue](https://gitlab.com/lucaapp/web/-/issues/15)). Da das Problem klar umrissen wurde, konnte es auch scnell behoben werden ([Update - Link Gitlab](https://gitlab.com/lucaapp/web/-/commit/2eb0c4687e65d0c1f095803cf1c21b9fcc5bd68e)). Allerdings viel auch auf, dass der angepasste Code verzugsfrei am Produktionssystem integriert wurde ... kein Rollout auf einem Referenzsystem, kein Staging, vor allem **keine Tests**. Dies mag für eine überschaubare Änderung vertretbar sein, dass eine solche Kernfunktion allerdings wochenlang unbemerkt ohne Funktion war, hat auch gezeigt: **Es gab hier nie funktionale Tests**.

In dem zugehörigen [Gitlab Issue](https://gitlab.com/lucaapp/web/-/issues/15), wurde dazu folgende Bemerkung veröffentlicht:

```
We followed up on this issue. We were able to determine that history retrieval via serial number was no longer possible due to the incorrect renaming of the Base32 Crockford function in one of the latest luca releases.
```

Aus der Commit-Historie war eine solches `"...incorrect renaming of the Base32 Crockford function..."` nicht ersichtlich (zwischen dem dem Initial Release und diesem Patch lagen mittlerweile **10 Versions Patches**, davon 1 Minor Release Update, über eine Zeit von einem Monat Codeanpassungen). Der fehlerhafter Patch der dieses Problem verursacht haben soll, ist vor dem Initial-Commit der Version `v1.0.0` für mich bis Heute nicht erkennbar. Aus meiner persönlichen Sicht heißt dies: Es fehlt nicht nur an Tests für Patch-Deployment, sondern es finden auch **keine hinreichenden funktionalen Tests für Kernfuntionalitäten des Systems statt**. Das Kommunikationsverhalten bzw. "Acknowledgment" des Herstellers zu gemeldeten Problemen, erscheint im Vergleich zu anderen Vendoren höchst fragwürdig. Ich selbst würde sogar soweit gehen zu sagen, dass das \*\*Herstellerverhalten nicht nahelegt, dass man der Verantwortung geachsen ist, die sich aus der Gestaltung des Luca-Systems (bezogen auf die Systemteilnehmer) ergibt.

# 3. Input filtering / Output filtering

## 3.1 Allgemeines

Dieser Abschnitt bildet den Kernteil dieser Notizen, da hier aus meiner Sicht die offensichtlichsten und eklatantesten Mängel bestehen. Ich möchte diese exmplarisch am Beispiel des "Health Department Frontends" anhand der Kontaktdaten von Nutzern des Systems darstellen (Kontaktdaten sind Nutzerkontrollierter Input). Es existieren auch an anderen Stellen Eingabedaten (Input), welche nach Verarbeitung im System wieder zu Ausgabedaten werden. Ob diese Ausgabedaten dann über definierte Schnittstellen an nachgeordnete Systeme weitergegeben werden (Export, Anbindung an externer APIs) oder vom Luca-System selbst verwendet werden (z.B. zur visuellen Darstellung oder System-internen Weiterverarbeitung) spielt keine Rolle, sofern man folgenden "common sense" Maßstab anlegt:

1. **Eingabedaten (Input) ist zu validieren**
2. **Ausgabedaten (Output) sind entsprechend des Kontextes in dem sie verwendet werden zu Kodieren oder zu "escapen", um ungewünschte Interpretation im Ziel-Kontext zu vermeiden**

Vor der Erläuterung dieser Methodik und deren Abgrenzung gegen Sanitization, möchte ich einige Beispiele für Input im Luca-System und die entsprechenden Output-Kontexte darstellen.

Geht man davon aus, dass die Kernfuntionalität des Luca-Systems die digitale Abbildung von Kontaktlisten (gefüllt mit Gästedaten), welche (auf Anfrage) an ein berechtigtes Gesundheitsamt übermittelt werden sollen, darstellt, erscheint die Untergliederung in Input/Output zunächst einfach:

1. Ein Gast stellt seine Kontaktdaten als Input für eine Location bereit (Output Kontext ist ein einzelner Datensatz für eine Gästeliste, z.B. in Form eines Datenbeankeintrages für eine Tabelle)
2. Aus sicht der Location ist jeder Gästedatensatz ein Tabelleneintrag für die Gästeliste, welcher als solcher validiert werden muss (z.B. Spaltenanzahl, Typ und Länge der Spaltenwerte). Bevor dieser Datensatz in die Datenbank eingetragen wird, muss er im Kontext der Datenbank codiert werden.
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

Diese Darstellung von Input und Output ist noch immer zu abstrakt, um eine korrekte Filterung anzusetzen. Darüber hinaus wurde der Input hier Kontext-Frei betrachtet. Der "additional data" Anteil von traces (vergleiche Abschnitte 1.2 und 1.2.1) kannn zum Beispiel Input für das "Location Frontend", für das "Health Department Frontend" als auch für die App des Gastgebers eines "Private Meetings" sein.

Dennoch sollte bereits hier klar sein, dass das Output Encoding, je nach Kontext, schnell komplex werden kann:

So wäre z.B. im Kontext der Browser-Darstellung Input der als HTML interpretiert werden könnte, so zu codieren oder zu escapen, dass er eben nicht als HTML interpretiert wird (ein String wie `<img>..` müsste zu `&lt;img&gt;...` werden) und auch Sub-Kontexte (wie eingebettetes JavaScript) wären zu beachten. Wird die Darstellung von externen UI-Frameworks übernommen (Luca verwendet `React`) ist ggF. auch der Kontext von Templatesprachen zu beachten (um z.B. Angriffe durch "Template Injection" zu verhindern).

Im Kontext von Datenbankabfragen wäre der der Output wiederum so zu kodieren, dass keine unerwünschten Abfragen ausgelöst werden. Einen als String in einer Datenbank zu speichernde Location Name kann durchaus `Hipster Bar'; DROP TABLE users; --'` lauten, wenn man ihn vor Speicherung in der Datenbank z.B. mit Base64 kodiert.

Setzt man eine saubere Input-Validierung an, kann man bereits viele Problemstellungen ausschließen. Idealer Weise nimmt man eine solche Validierung in zwei Schritten vor, als Beispiel soll hier eine Postleitzahl dienen. Zur Validierung könnten hier die beiden folgende Schritte vorgenommen werden (Luca verarbeitet Postleitzahlen als Zeichenketten, nicht als Integer):

1. Validierung der Struktur, z.B. für Deutsche Postleitzahlen: Die Postleitzahl besteht nur aus Ziffern, sie überschreitet nicht die maximale Länge von 5 Zeichen
2. Validierung Semantik/Plausibilität (Kontextabhängige Prüfung): Für Locations sind nur Postleitzahl aus dem Zuständigkeitsereich registrierter Gesundheitsämter zulässig, für Postleitzahlen aus Nutzerkontaktdaten sind nur Postleitzahlen aus den vorgesehenen Regionen zulässig

Entscheidend für die Input-Validierung ist auch, wo diese ansetzt. Unter funktionalen Gesichtspunkten kann die Validierung dort erfolgen, wo bspw. ein Nutzer Daten bereitstellt (z.B. innerhalb der App). Unter dem Aspekt der Sicherheit, muss eine Validierung von Eingabedaten dort erfolgen, wo eine schadhafte Manipulation weitestgehend ausgeschlossen ist.

Konkret heißt das, für Nutzerkontaktdaten die erst im WebFrontend des Gesundheitsamtes entschlüsselt werden, dass die Input Validierung in diesem Frontend, unmittelbar nach der Entschlüsselung vorgenommen werden muss. Luca zeigt kaum Ansätze dies zu tun. Der Großteil der verschlüsselten Daten wird Client-seitig (vor Verschlüsselung validiert). Unter dem Sicherheits-Aspekt kann eine solche Validierung vernachlässigt werden, da Angreifer Daten unter Umgehung des Clients einbringen können. Für unverschlüsselte gespeicherte Daten (z.B. Kontaktdaten iner Location), wird hier für die meisten API Endpunkte des Backends zumindest eine Validierung gegen das Datenbankschema angesetzt (korrekte Datentypen, korrekte Größe/Länge der Daten).

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

Hier wurde nicht nur erneut so schnell am Live-System gepatcht, dass Tests offensichtlich gar nicht durchfühbar waren. Dabei ging hier um ein Sicherheitsfeature, welches wenige Stunden nach dem Patch als umgesetzt beworben wurde (Beachtet man die Vorlaufzeit zur Veröffentlichung eines solchen Artikels, muss man sogar davon ausgehen, dass der Patch eingepflegt wurde, nachdem gegenüber der "Zeit" erklärt wurde, dass OWASP Vorgaben zur Mitigation von CSV Injections umgesetzt waren.)

Aufgrund dieses Tweets, wurde auch sehr schnell klar - was vorher unklar war:

Setzt das Output-Encoding für den CSV-Kontext wirklich direkt "beim Entschlüsseln der Daten" (am Input) an?

Der "Filter" aus besagtem Patch befand sich hier: [Code link](https://gitlab.com/lucaapp/web/-/commit/2f878ef9e624224722aa073ee71cb8703f6728f1?page=7#7691cd5a586200d7401cc54324010eae3f559fdc)

Angwendet wurde er [hier](https://gitlab.com/lucaapp/web/-/commit/2f878ef9e624224722aa073ee71cb8703f6728f1?page=7#18895b77c1e5c724c891e09f24ab44236d617e56_20_51) und angewendet wurde er [hier](https://gitlab.com/lucaapp/web/-/blob/2f878ef9e624224722aa073ee71cb8703f6728f1/services/health-department/src/utils/decryption.js#L90) und [hier](https://gitlab.com/lucaapp/web/-/blob/2f878ef9e624224722aa073ee71cb8703f6728f1/services/health-department/src/utils/decryption.js#L162).

Ein sehr kurzer Blick in diesen "schnell nachgeschobenen" Patch genügt, um Festzustellen:

- Filterung wird tatsächlich unmittelbar nach der Entschlüsselung von Rohdaten angesetzt (nach einem Kontext-Wechsel zu JavaScript, denn die entschlüsselten Daten wurden "noch schnell" als JSON geparst)
- Auch ohne umfassende Kenntnis des Luca-Codes wird damit klar: **Eine Filterung an dieser Stelle kann sich nicht auf einen CSV Output-Kontext beziehen, denn es gibt hier noch keinen CSV-Output**
- Es handelt sich auch nicht um eine Input Validierung, denn die Funktionalität validiert kaum Annahmen, die über den Input getroffen werden müssen
- statt Eingabe-Validierung und Ausgabe-Kodierung kommt eine Art "Sanitization" zum Einsatz, die offensichtlich an einer Stelle platziert wurde, an denen nicht allen relevanten Ausgabe-Kontexten Rechnung gertagen werden kann, welche aus Sicherheitsgründen gefiltert werden müssten (man könnte hier seitens Entwickler allerdings entgegen halten, dass man "maliziösen Input" ausschließlich für den Sonderfall "CSV Injection" behandeln wollte)

Nach dieser (sehr ausführlichen) Einleitung, soll nun zunächst betrachtet werden, welche Kontextwechsel der User-Input im "Health Department Frontend" durchläuft (beschränkt auf verschlüsselte Kontaktdaten)

## 3.4 Verarbeitungskette von Nutzer-Input zu resultierenden Output-Kontexten im "Health Department Frontend" (Rückblick auf v1.1.11)

t.b.d.

- Sanitization ist schlecht ...
- keys von "additional data" sind auch böse

In den nächsten Abschnitten

Wo anzusetzen: Dort wo validation nicht umgangen werden kann.

Notes: JSON not strictly typed (like, f.e. Protobuf)

Output Encoding:

- sub Kontext beachten, bspw für Browser output: in HTML Kontext eingebettets JavaScript eingebettetes Javascript, bei Einsatz von Rendering Frameworks wie React, VueJS, Angular die Sprachkontext der Template-Engine (vergleiche Template Injection)
- wann Output encoding (vor Output, um z.B. Double Encoding zu vermeiden)

t.b.d.

Allgemeine Erläuterungen, Rückblick CSV als Beispiel (nach wie vor) mangelhafter Filterung. Fokus auf SORMAS API (keine Filterung).

Anmerkung nicht betrachteter Bestandteile (insb. Location Frontend)

### Input

1. location data (name address etc) --> Binary Blob (expected JSON)
2. location additional data schema --> ?Binary Blob?

- bei unverschlüsselten Daten Inputvalidation durch DB Schema

### Output Contexts

- JS Objects (expects parsable JSON strings, Exception Handling applied, but no validation of input)
- Postgres Queries (protected by Sequelize, keine Pruefung)
- React state (komlettes data processing, einbindung 3rd party libs)
- SORMAS Rest API (ungefiltert)

## Ursachen persönliche Meinung

- kein Testing, schnelle Patch releases, Bewerbung von fixes ohne Test
- gravierende Fehler bleiben unbemerkt (Badge Abfrage GA)
- keine fundamental kritik an zentralem Ansatz, aber kaum einer der Fehler würde in einem dezen System gleicher Funktionalität bestehen (die **Kern**Funktionalität ist ohne zentrale Komponenten abbildbar)
- angeführte Probleme könnten schnell behoben werden, und System würde auf Basis externer Zuarbeit reifen, trotzdem überwiegt Risiko, Vergangenheit hat gezeigt, dass Betreiber der Verantwortung NICHT gerecht wird (öffentliche Irreführung, Dementi von Sicherheitslücken, Falschaussagen in Chronologie, Quellcode release ist nicht gleich Transparenz ... hier konstenlose Reviews etc etc)
- Problem überflüssiger zentraler Speicherung: Locations ohne Anbindung des Gesundheitsamtes

## sonstiges

- KEINE Löschung der Kontaktdaten?

- private meeting limit (50 Besucher) gilt nur für echtes private meeting https://gitlab.com/lucaapp/web/-/blob/6f426776c9e569fc21e0bd29a52092803e21fa60/services/backend/src/routes/v3/traces.js#L60

## Kryptoschmutz

- over engineered ... Hybridansatz, obwohl Ressourcen für asymmetrisch
- Schlüsselanhänger Katastrophal (V3)
