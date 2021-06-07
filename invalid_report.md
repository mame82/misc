# Meldung einer vermeintlichen Sicherheitslücke an Luca Team

Die Zusammenfassung, die ich hier wiedergebe, ist für mich etwas ungewöhnlich, denn ich schreibe nicht auf Englisch (ich entschuldige mich schonmal für alle Typos, da ich keine Helferlein mit German Language-Pack installiert habe) und ich schreibe nicht nur über Technik.

Warum? Weil es um die LucaApp geht, über die viel im öffentlichen Raum diskutiert wird (das schließt mich mit ein). Mein Fokus liegt i.d.R. ausschließlich auf Technik und Code, denn dort gibt es nicht viel Interpretationsspielraum oder viele Auslegungsvarianten. Das gestaltet sich im Kontext der "Luca app" derzeit offensichtlich etwas anders, daher gebe ich auch Rahmeninformationen wieder.

# Um was geht es eigentlich

Das Luca Backend implementiert verschiedenste Sicherheitsmechanismen. Dieser Text behandelt aus der Fülle dieser Mechanismen genau einen: das "Rate Limiting".

Die grundsätzliche Idee hinter "Rate Limiting" ist die Anzahl von Requests einzelner Nutzer (oder Quell-IPs) auf eine festgelegte maximale Anzahl in einem vorgegebenen Zeit-Intervall zu beschränken. Genauso unterschiedlich wie die Gründe für einen solchen Mechanismus sind, sind die Parameter die beim Einsatz von "Rate Limiting" zum Tragen kommen (maximale Anzahl erlaubter Requests, Kriterien für Requestzählung, Sperrzeit beim Erreichen des Limits usw.).

Ein offensichtliches Beispiel für einen sinnvollen Einsatz von Rate Limiting, wäre bspw. ein Endpunkt der Nutzer authentifiziert. Das "Rate Limit" würde hierbei üblicherweise NICHT direkt die Anzahl falsch eingegebener Kennwörter zählen, um den Nutzer nach zu vielen Fehlversuchen zu sperren, denn das gehört er in die Applikations-Logik. Über "Rate Limiting" könnte man aber verhindern, dass ein Nutzer 100 Kennwörter in wenigen Sekunden testet, denn dabei würde es sich aller Wahrscheinlichkeit nach um einen Bruteforce-Versuch handeln. Klares Messkriterium (und damit Parameter), wäre hier also schonmal die Anzahl der Requests pro Zeit-Intervall. Die Requests müssten aber auch einem Nutzer zugeordnet werden. Das könnte z.B. über die Quell-IP erreicht werden (eher schlecht, aufgrund DoS-Potential bei source IP spoofing _wink_). Zu den Parametern/Kriterien für "Rate Limits" gehört aber auch deren "Scope" (Anwendung nur auf den Authentifizierungs-Endpunkt / Anwendung auf alle Endpunkte gleichermaßen, oder aber, Anwendung individuell je Endpunkt).

Ich denke, das reicht zur Kurzerläuterung von "Rate Limiting".

Für Luca kommt Rate Limiting an verschiedenen Endpunkten (EP) zum Einsatz, auch hier werden u.a. Bruteforce Angriffe damit verhindert. Problematisch wäre es aber auch, wenn man an die EPs für SMS-TAN Verifizierung beliebig viele Anfragen senden könnte, denn so wäre man in der Lage den Massenversand von SMS auszulösen. Eine Umgehung des "Rate Limiting" wäre also an verschiedenen Stellen kritisch.

Ich habe mir also  (neben vielen anderen) die Frage gestellt, ob man für das Luca Backend das Rate Limiting umgehen kann.

Fragen wie diese kann man sich auf verschiedenste Arten beantworten: Quellcode lesen und nach Implementierungsfehlern als Ansatz suchen (der Code für das Backend wurde gerade veröffentlicht), blind testen, ohne überhaupt eine Idee zu haben (nein, das ist kein Fuzzing - bestenfalls Blackbox-Testing) oder: Man hat eine konkrete Idee, probiert diese aus, passt sie an ein mögliches Szenario an - sofern sie funktioniert, erstellt dann ein Proof-of-Concept (PoC) und leitet potentielle Folgen ab, um den Impact abschätzen zu können (denn man sollte nicht wirklich alles testen, wie z.B. Massen-SMS-Versand).

Gewählt habe ich die letzte Variante, denn ich hatte bereits eine simple Idee und erste Tests waren vielversprechend. Derartige Ideen führen oft nicht ad-hoc zum Ziel, aber kein Grund schnell aufzugeben. Ist man in die erste Sackgasse gelaufen, nimmt man einen anderen Weg. Das tut man so lange, bis man das Ziel erreicht hat oder man jeden möglichen Weg beschritten hat, **erst dann verwirft man die Idee**.

In diesem Fall gab es nicht wirklich viele Sackgassen und alles ging mir recht gut von der Hand. Es sollte sich allerdings herausstellen, dass ich "an Stellen abgebogen bin, wo gar keine Wege mehr waren". Im Resultat habe ich zwar einen Ausgang aus dem Ideen-Labyrinth entdeckt, nur leider nicht bemerkt, dass über diesem Ausgang nicht wirklich das Wort "Ziel" stand.

Neben dem öffentlichen Interesse an Luca, ist das einer der wichtigsten Gründe, warum ihr diesen Text lest. **Scheitern ist ganz normal. Es gehört dazu, denn aus Fehlern lernt man und nur wenn man aus Fehlern lernt, wächst man!** Gerade die Security-Community ist oft so scheinheilig, dass man in ihr oft schnell verzweifeln kann. Es gibt Massenhaft Blender, Imposter, auch viel Ideenklau und Lügen. Gerade für Newcomer ist das oft schwer zu erkennen. Überall liest man von Erfolgen, Exploits mit klangvollen Namen - als stammen sie aus der Werbeindustrie -, "critical vulnerabilities" werden scheinbar am Fließband entdeckt. Was man kaum in den Vordergrund rückt: Die zahlreichen Fails und die riesige Menge an Arbeit, die oft in die Ausarbeitung eines funktionalen Exploits geht (meist müssen ganze Ketten an Schwachstellen entdeckt und verknüpft werden, um ein einfaches Ziel zu erreichen).

Für mich sind "fails" ganz normal, ich gehe damit locker um und habe über die Jahre auch gelernt zu akzeptieren, dass man (gerade bei der Suche nach Schwachstellen) wesentlich mehr Lebenszeit auf das Scheitern verschwendet, als darauf Erfolge zu feiern. Nochmal: **Das ist ganz normal und dessen sollte man sich von vornherein bewusst sein**.

Trotzdem mache auch ich den Fehler, andere hauptsächlich an Erfolgen teilnehmen zu lassen und Misserfolge schnell zu übergehen. Damit trage auch ich zur schlechten Fehlerkultur in der Sec-Community bei und möchte das wenigstens an dieser Stelle einmal anders machen.

Leider kann ich kein wirklich großes Klagelied singen, denn diesmal habe ich nur wenige Stunden Lebenszeit mit einem Fehler verbracht (remember: diese Zeit ist trotzdem nicht verschwendet), dennoch ist so etwas exemplarisch.

Bevor ich zum technischen Teil komme, möchte ich noch den zweiten Aspekt abhandeln, an dem die meisten interessiert sein dürften:

# Umgang des Luca Teams mit gemeldeter Sicherheitslücke

Zunächst einmal bin ich gar nicht den üblichen (und richtigen) Weg gegangen, mich direkt an den betroffenen Hersteller zu wenden, sondern habe public über Twitter nach den "Frontleuten" des Luca-Teams gerufen.

Eine Antwort hatte ich innerhalb weniger Minuten (als DM). Natürlich habe ich den Weg über Twitter bewusst gewählt. Über Luca wird nicht nur viel geredet (auch viel Bullshit), sondern man sagt dem Team auch nach, dass sie ausweichend reagieren und Probleme nicht adressieren. Ich kann das in Teilen für mich bestätigen, aber die Handhabung von Schwachstellen ist ja nochmal ein ganz anderes Feld, als public-relationship oder customer-relationship. Will sagen, anhand dessen wie ein Vendor mit Meldenden von Schwachstellen und den Schwachstellen selbst umgeht, trennt sich schnell die Spreu vom Weizen.

Weiter im Text ... Ich habe also eine DM mit Antwort erhalten und daraufhin gebeten, auf meine öffentliche Frage auch eine öffentliche Antworten zu erhalten. Auch dies ist alles andere als üblich, aber seitens Luca kam man der Bitte prompt nach.

Der Rest ging mehr oder weniger im Standard-Prozess weiter: Melden der potentiellen Schwachstelle auf vorgesehenem Kanal (verschlüsselte Mail) und dann auf Vendor warten. Da der PoC so schlicht war, habe ich keinen Report geschrieben, sondern zu Problem-Ursache und Mitigation nur einige Kommentare in den PoC selbst eingefügt.

Mit einer Antwort hätte ich nicht mehr am selben Tag gerechnet, aber die kam schon weniger als 3 Stunden später (in dieser Zeit haben wesentlich besser aufgestellte Firmen noch nicht mal ein Ticket aufgemacht). Der Inhalt der Mail war nicht nur eine einfache technische Rückfrage, sondern:

- das Problem wurde technisch verstanden (nicht sehr komplex)
- konnte nicht reproduziert werden (Ui, das wurde schnell getestet)
- es wurden auch andere Varianten eine "Rate Limit Bypasses" auf Basis des PoC getestet (die ich gar nicht vorgesehen hatte), aber ebenfalls ohne Erfolg

Darüber hinaus wurde angeboten, auf Deutsch weiter zu kommunizieren (macht ja Sinn).

... und nun?! Scheiße, keine 3 Stunden rum und ich hab das Ding wieder auf dem Tisch. Eigentlich Family time, aber auch nach so vielen Jahren tue ich mich noch schwer, von einem Problem abzulassen, wenn ich nicht weiß wo die Ursache liegt.

Hier kommt erschwerend hinzu, dass die Luca-Leute plausibel dargestellt haben, dass alles erdenkliche versucht wurde, um die Ausnutzung der vermeintlichen Schwachstelle zu reproduzieren. "Fehler auf meiner Seite? Wäre nicht so schlimm, aber dann will ich es sofort wissen!".

Also an der Stelle alles zurück auf Null: Neues (schlichteres) PoC Skript ... und siehe da, ganz andere Ergebnisse. Frage an mich: "Haben die da heimlich was gefixt?" ... Antwort: "Sicher nicht, würde auch rauskommen!" _(Anmerkung: Habe ich aber bei anderen Deutschen Branchen-Riesen mit gehostetem BugBounty schon erlebt)_

Also habe ich einen Fehler gemacht. Diesen Fehler zu finden, hat mich wesentlich mehr Zeit gekostet als den ersten PoC zu erstellen! Merkt euch das bitte, falls ihr mal für Bounties oder VDPs einreicht ... nicht sofort drängeln, vollständige Analyse und Fix einer Schwachstelle können deutlich mehr Zeit in Anspruch nehmen, als sie zu finden und zu proofen (Je nachdem wir ehrlich der Vendor ist, ist das insbesondere dann gut, wenn dieser die Kritikalität noch hoch setzt, weil der Impact größer ist als ihr ursprünglich dachtet).

Ein Weile später war dann alles klar: Ein Schwung an Fehlanahmen auf meiner Seite, alles Murx.

Also, Mail zurück an das Luca Team (Abends 20:30Uhr), gemachte Fehler klarstellen ... "Drops gelutscht".

Dann noch Klarstellung bei Twitter (Wichtig Leute: "Wer A sagt muss auch B sagen!") und ab zur Family.

Das sollte es jetzt zur Kommunikation gewesen sein. IMO hat man da bei Luca nichts anbrennen lassen. Aber "Oha!" am nächsten Tag wieder eine Mail von Luca im Eingang! Why? Bekomme ich Feedback, dass das Ticket geschlossen ist? Nein! Wer auch immer meine Einreichung reviewt hat, hat sich nach meiner letzten Mail auch noch die Mühe gemacht, nachzuvollziehen warum mein **nicht funktionaler** PoC am Real-System andere Ergebnisse produziert als in meinen Tests und mir dazu zusätzliche Informationen zukommen lassen. Nicht schlecht! Für mich ist das ein klares Anzeichen dafür, dass man seitens Luca daran interessiert ist, dass ResearcherInnen auch die nötigen Informationen an die Hand bekommen, um saubere Tests durchzuführen.

An dieser Stelle kann ich nur sagen: Wenn im Umgang mit diesem Report etwas falsch gehandhabt wurde, dann nicht auf der Seite von Luca. AmS wurde der Vorgang schnell, präzise und umfassend abgearbeitet!

Weiter mit der Idee und PoC Entwicklung...

# Tinkering with Luca-backend rate limiting

Wie Eingangs erläutert, habe ich nicht den bereits verfügbaren Code zur "Rate Limiting" Implementierung gelesen und nach schwächen gesucht, sondern bin von einigen Annahmen ausgegangen und habe eine Idee verfolgt.

Annahmen für etabliertes Rate Limiting:

1. Key Quell-IP des Requester
2. Key auf nicht-dynmaischen teil des query path (kein keying der query params und dynamischen Pfad-Anteile, wie z.B. UUIDs im request Pfad)
3. Unterscheidung je Endpunkt (ergibt sich aus 2.)
4. Keying ist nicht case-sensitive (das es hier ein Problem gab, war ausreichend lange bekannt, um es zu fixen)
5. Requests mit gültiger Response rechenen nicht auf rate limit an (habe an andere Stelle bereits festgestellt, dass Design-bedingt sehr viele Requests vom gleichen Client in kurzen Intervallen gestellt werden können)

Idee:

Sobald ein request das rate limit triggert (Response mit Status Code 429), den Query-Pfad so anpassen, dass ein anderer key erzeugt wird (Annahme Nr 2), aber der Request immer noch am vorgesehenen Endpunkt aufläuft. Konkret: Einfügen relativer Pfade.

Als Endpunkt für einen test soll `api/v3/users/{uuid}` dienen (der uuid ist dynamisch und nach meinen Annahmen nicht "gekeyed" angepasst werden kann also `/api/v3/users/` )

Kurzer Test mit Curl:

```
curl "https://app.luca-app.de/api/v3/users/./././20eb1d96-377f-4a86-be50-e687cc6dfc05"
{"userId":"20eb1d96-377f-4a86-be50-...snip...2zykU="}
```

Der erste Test mit Curl war erfolgreich, denn es gibt eine valide Response, trotz der eingefügten `/././.` Sequenz. Damit würde laut meiner Annahmen ein anderer Request Pfad "gekeyed" werden, den man beliebig erweitern kann, um das rate limiting zu umgehen.

Hier ist mir auch der erste Fehler passiert. Curl reduziert solche request Pfade, bevor der request gesendet wird (wurde von mir nicht bemerkt). Mit Curl mit verbose output hätte das bereits gezeigt:

```
# curl -v "https://app.luca-app.de/api/v3/users/./././20eb1d96-377f-4a86-be50-e687cc6dfc05"
..snip..
> GET /api/v3/users/20eb1d96-377f-4a86-be50-e687cc6dfc05 HTTP/1.1
> Host: app.luca-app.de
> User-Agent: curl/7.72.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
..snip..
```

Okay, davon ausgehend, dass man so einen anderen Request-Pfad keyen kann (Annahme 2), geht es weiter mit Annahme Nr. 5. Ein ungültiger request muss her, um den counter für das rate limiting hochzuzählen, bis das Limit erreicht ist (response mit status code 429).

Für diesen Endpunkt ist das einfach, ein Request mit ungültiger user UUID sollte den counter hochzählen, z.B.

```
# curl "https://app.luca-app.de/api/v3/users/11111111-1111-1111-1111-111111111111"
Not Found
```

Natürlich macht hier Curl keinen großen Sinn mehr, denn es braucht viele Requests für, um das Limit zu triggern (möglichst parralel) und die response muss ausgewertet werden, um auf ein rate limit zu reagieren. Richtiger Zeitpunkt um in das Scripting einzusteigen. Das hatte ich an der Stelle auch schon gemacht, aber es gibt einen Grund, warum ich den Curl request mit der UUID `11111111-1111-1111-1111-111111111111` it aufliste. Mein zweiter Fehler: **"ungültige UUID" != "ungültige UUID"**

An dieser Stelle gehe ich von drei möglichen HTTP responses status codes für requests mit ungültiger UUID aus:

- 200: gültige UUID, triggert kein rate limiting
- 404: ungültige UUID, zählt rate limit counter hoch, **aber rate limit ist noch nicht erreicht**
- 429: rate limit erreicht

Entgangen ist mir folgender Fall mit response status code 400, der vieles leichter gemacht hätte:

```
# curl "https://app.luca-app.de/api/v3/users/11111111"
{"errors":[{"validation":"uuid","code":"invalid_string","path":["userId"],"message":"Invalid uuid"}]}

```

Welches Problem habe ich mir hier geschaffen? Ganz einfach, die Logik für mein PoC-Skript sollt folgende sein:

1. Stelle requests mit ungültiger UUID, bis Response Status 429 ist (rate limit, erwarteter Status Code ohne rate limit wäre 404)
2. Füge eine Sequenz `/.` in den request pfad ein und mache bei 1. weiter

Erwartetes Verhalten:

1. Viele requests mit 404 response (1000 für diesen Endpunkt)
2. Mindestens eine Response mit 429
3. Nach anpassung des Request Pfades wieder 404 responses

usw.

Genau das gewünschte Ergebnis habe ich auch erhalten, ABER die 404 status codes für Nr. 3 im erwarteten Verhalten resultierten nicht aus ungültigen UUIDs, **sondern aus ungültigen request Pfaden**.

Warum habe ich das nicht bemerkt? Weil ich es vermeintlich durch Tests mit Curl ausgeschlossen hatte (Remember: erster Fehler).

Was hätte man hier besser machen können? Vieles, und genau da liegt der Lerneffekt (passiert also kein zweites mal):

- man muss nicht das gesamte interne Verhalten von Curl kennen, aber wenn man Curl für so etwas benutzt: `-v` is your friend
- man sollte möglichst viele Inputs für jeden Endpunkt Testen, um alle unterscheidbaren Responses zu kennen. Hätte ich hier mit dem 400 für falsch formatierte UUIDs gearbeitet, wäre der Fehler schnell aufgefallen
- man sollte seine eigenen Ergebnisse umfassend validieren und die Ursachen genau analysieren. Zum Einen gehört diese Analyse zu einen guten Report, zum Anderen hilft sie Fehler zu vermeiden. Ich hätte hier z.B. den relevanten Source Code nachträglich analysieren müssen, um die Fehlerursache zu finden (wer sich die Rate Limiting Middleware mal anschaut, sieht schnell dass diese Idee nie funktionieren konnte. **Hinweis: X-FORWARDED-FOR wird auch nicht funtionieren, wäre aber aufgrund des Codes ein realistischere Ansatz ;-)**). Weiter hätte ich meinen PoC für mehr als 2000 Requests testen müssen, um das Rate Limit mehr als einmal zu triggern. Auch dabei wäre ein Fehler aufgefallen, denn der später ungültige Request-Path triggert gar kein rate limit mehr.

Nice. Dann hätten wird das, ich habe bei weitem mehr gesagt, als das Thema technisch hergibt.

Zu guter letzt noch das PoC-Script, welches eingereicht wurde. Die Mail-Inhalte share ich nicht, aber ich hoffe ihr vertraut mir wenn ich sage: Die Kommunikation is so gut verlaufen, wie oben beschrieben.

# PoC-Script (nicht funtional, einschl. unmodifizierter Kommentare)

```
import requests
from uuid import UUID
import random
import threading

# Author: Marcus Mengs (MaMe82)
#
# Luca-backend rateLimit bypass, by introducing path traversal to intended endpoint
#
# The poc runs against the EP '/users/{userID}' to mimic bruteforce of legit user IDs,
# but would work on other EPs like the ones which trigger SMS verifications (which of
# course has not been used to keep the testing impact as low as possible ... the
# staging environment seems to be unavailable for tests, unfortunately)
#
# The rate limit bypass in this PoC is disabled by default, thus the limit should be
# hit after 1000 requests (1000 requests/hour apply to this EP, as defined here
# https://gitlab.com/lucaapp/web/-/blob/e3bc127067ac3bd221d61809e404ec8f7b18af1e/services/backend/src/routes/v3/users.js#L123).
# Once the Limit is hit, the PoC should receive and print 429 status codes for
# successive requests.
#
# To enable the bypass, set the global 'BYPASS_RATE_LIMIT' variable to 'True'.
# In result, the script extends the request path by a small path traversal (which still
# leads to the target route), whenever a 429 response appears. Ultimately, the rate limit
# is bypassed as the logic evaluates the full request path.
#
# For mitigation, the request path shall be resolved to the final target, before it gets
# evaluated for rate limiting (removal of relative URI path components, to get an absolute
# path)
#
# Additional notes:
# The script prints a message "!!! Hit rate limit, adjusted URI path by ...", whenever
# a 429 status was received and the path was adjusted (only if 'BYPASS_RATE_LIMIT=True').
#
# The status codes 200 (user with given uuid exists) and 404 (user does not exists) are
# specific to this endpoint (at least the 404), but are both legit responses (successful
# bypass of rate limit, even for 404).
#
# Last but not least: No real user UUID  was brute-forced, I kept the test-runs as short
# as possible.



API="https://app.luca-app.de/api/v3"
BYPASS_RATE_LIMIT=False

req_count=0
rate_limit_hit=False
path_mod=""

def gen_rand_uuid_str():
    u = UUID(bytes=random.randbytes(16))
    return str(u)

def req_uuid(uuid_str, is_retry=False):
    global req_count, path_mod, rate_limit_hit
    url=f"{API}/users/{path_mod}{uuid_str}"
    r = requests.get(url=url)
    req_count += 1
    if r.status_code == 200:
        print(f"User with id {uuid_str} exists")
        return (r.status_code, uuid_str)
    elif r.status_code == 429 and BYPASS_RATE_LIMIT:
        rate_limit_hit=True
        return (r.status_code, "")
    else:
        print(f"{uuid_str} ({req_count}): {r.status_code} {r.content}")
        return (r.status_code, "")

def req_rand_uuid():
    req_uuid(gen_rand_uuid_str())

for i in range(250):
    threads=[]
    for j in range(50):
        t = threading.Thread(target=req_rand_uuid)
        t.start()
        threads.append(t)

    rate_limit_hit=False
    for t in threads:
        t.join()

    if rate_limit_hit:
        path_mod += "./"
        print(f"!!! Hit rate limit, adjusted URI path by inserting '{path_mod}'")

```
