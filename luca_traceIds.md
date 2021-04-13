# Tracking of unique mobile devices and check-in locations from operator perspective of LucaApp backend

Author: Marcus Mengs (MaMe82)

## TL;DR

Based on the observation of network traffic between the Luca-app and the Luca backend, it could be concluded that an observer (f.e. backend operator) is able to:

- continuously and uniquely re-identify mobile devices:
  - across application restart
  - across device reboot
  - across IP-address changes
- ... and associate plain data of visited locations (check-in / check-out) to those devices

**...without any evolvement of responsible health departments or location owners**

## Disclaimer

_The content of this document is based on my personal observation of the HTTP communication of a single test device running the Luca app, thus I do not consider it being representative (without further verification). It is neither a full fledged analysis of the Luca ecosystem, nor a representative study. I take no responsibility for the abusive use of information given in this documents. I DO NOT GRANT PERMISSIONS TO USE CONTAINED INFORMATION TO BREAK THE LAW. The document is provided "as is"._

## Introduction

By design of the **LucaApp** architecture deploys a various asymmetric and symmetric keysfor involved entities, in order to protect user data from disclosure.

The detailed security objectives are described here: [link to security concept](https://luca-app.de/securityconcept/properties/objectives.html#objectives)

One out of multiple symmetric keys (or "secrets") is the `tracing secret`, which is used to generate `tracingIDs` for anonymized user check-ins into dedicated locations (in luca's terminology users are called `guests` and locations, which offer check-ins, are called `venues`).

The "security concept" describes a [tracingID](https://luca-app.de/securityconcept/properties/secrets.html#term-trace-ID) like this:

```
An opaque identifier derived from a Guest’s user ID and tracing secret during Guest Check-In. It is used to identify Check-Ins by an Infected Guest after that Guest shared their tracing secret with the Health Department.
```

The term `opaque` implies that **at no point in time, luca operators are able to draw conclusion on the guest, which produced a `trace ID`.**

Moreover, the `trace IDs` are meant to allow legit health departments (**and only health departments**) to reconstruct a guest' check-in history. A detailed description could be found in the process [Tracing the Check-In History of an Infected Guest](https://luca-app.de/securityconcept/processes/tracing_access_to_history.html#process-tracing). Below a short excerpt:

```
The first part of the contact tracing is for the Health Department to reconstruct the Check-In History of the Infected Guest. Each Check-In stored in luca is associated with an unique trace ID. These IDs are derived from the tracing secret stored in the Guest App (as well as from the Guest’s user ID and a timestamp). Hence, given the Infected Guest’s tracing secrets the Health Department can reconstruct the Infected Guest’s trace IDs and find all relevant Check-Ins.
```

In the 'security considerations' of said process description, the security concept also mentions the possible [Correlation of Guest Data Transfer Objects and Encrypted Guest Data](https://luca-app.de/securityconcept/processes/tracing_access_to_history.html#security-considerations)

```
After receiving a Infected Guest’s guest data transfer object the Health Department Frontend uses the contained user ID to obtain that Guest’s encrypted guest data from the Luca Server. This is done in order to display the Infected Guest’s Contact Data to the Health Department.

The Luca Server can (indirectly) use this circumstance in order to associate a guest data transfer object with the encrypted guest data of the same Guest by observing the Health Department Frontend’s requests
```

Based on my own observations of the behavior of the LucaApp (Android, version 1.4.12), the Luca-backend is able to uniquely identify devices (even across connectivity loss and IP-Address changes) and able to associate location check-ins to those devices **without any involvement of health departments**. I going to describe aforementioned observations and my personal conclusion throughout this document.

## Side note on: device tracking versus user tracking

For most real world cases, it is sufficient for 3rd party trackers to identify devices with a high probability of uniqueness. This is because it is almost always the case, that a single mobile device is used by a single user. There also exist additional tracking technologies with the goal of tracking dedicated users accross multiple device (cross-device tracking) which is not in scope of this summary.

It is also known, that while luca takes efforts to protect the actual user data (name, address, phone number etc), the authenticity of said user data can not be assured by the luca-service. This is even true for the phone number, as it was shown multiple times, that the deployed 'SMS TAN verification' could be bypassed easily, because it is implemented on client side (user controlled).

This leads to the conclusion, that the encrypted user data (which the luca backend holds ready for health departments) isn't necessarily of value. But of course, meta-information which arises at the luca backend and allows device- and behavior-tracking as described above **is of value for every tracking service**.

# Review of relevant network interaction between luca Android app and luca-backend

In this section I am going to review HTTP communication between the luca app and the backend, with focus on the `/traces/bulk` endpoint. Communication to other endpoints (e.g. user registration) is omitted, where it does not add up to the topic of this document.

The HTTP body data excerpts used to illustrate observations, use real data which was transmitted. In order to review this communication, a luca test account was created (SMS verification was skipped, in order to allow health departments to easily recognize the invalid phone number, in case the generated tracing data gets relevant).

Additional notes:

- In order to observe check-in/check-out behavior, one of multiple publicly-shared location QR-codes has been used for self-check-in. As those QR are already publicly available, no efforts have been taken to obfuscate related location data which occurs in the HTTP responses by the luca-backend endpoints.
- The production API `https://app.luca-app.de/api/v3/` was used for testing. A staging API is available at `https://staging.luca-app.de/api/v3/`, but using it would involve changes in the application code. As the provided Android source code is incomplete, it is not possible to compile an adjusted version of the app. Runtime-modification of the app by other means (to redirect API requests to the staging API) have not been applied for obvious reasons.

## 1. Classifiers in HTTP request headers

As I mostly present HTTP body data in this document, I want to make pretty clear that **each HTTP request from the luca app provides additional device classifiers to the backend**. Those classifiers are:

1. The Android OS version
2. The Device Manufacturer
3. The Device Model

The Luca app always assures that those classifiers are included, by enforcing a `User-Agent` string which is constructed like this ([link to code](https://gitlab.com/lucaapp/android/-/blob/master/Luca/app/src/main/java/de/culture4life/luca/network/NetworkManager.java#L127)):

```
    private static String createUserAgent() {
        String appVersionName = BuildConfig.VERSION_NAME;
        String deviceName = Build.MANUFACTURER + " " + Build.MODEL;
        String androidVersionName = Build.VERSION.RELEASE;
        return "luca/" + appVersionName + " (Android " + androidVersionName + ";" + deviceName + ")";
    }
```

For a request from my test device, the resulting HTTP Header looks like this:

```
User-Agent:       luca/1.4.12 (Android 9;samsung SM-G900F)
Content-Type:     application/json
Content-Length:   15
Host:             app.luca-app.de
Connection:       Keep-Alive
Accept-Encoding:  gzip
```

It can not be avoided, that the luca-backend also receives the public IP-Address of the user **for each HTTP request** in addition. For most mobile data connection, the public IP-Addresses are shared by multiple users. Additional identifiers, as used in this case, greatly increase the probability to uniquely distinguish mobile devices, even if they share the same IP-Address.

This problem of the luca architecture was covered in multiple reviews. Thus I want to focus on how 'trace IDs' could be used, to increase the probability (of identifying devices uniquely) even further.

For the rest of the review, I only cover HTTP body data, but it is crucial to keep in mind, that each and every request involves aforementioned classifiers and the IP-address (as identifier).

## 2. Communication after application startup

When the application is started the first time, a user account has to be created. Once that is done, the app creates the various crypto key, including the 'tracing secret' which is only known locally.

After 'tracing secret' creation, the app ultimately starts to derive `trace IDs`. Those trace IDeas are re-generated every 60 seconds, as described in the documentation. The documentation is less specific, when it comes to backend-polling of `trace IDs`. The topic is touched in the process [Check-In via Mobile Phone App](https://luca-app.de/securityconcept/processes/guest_app_checkin.html#process-guest-checkin) of the documentation, which states:

```
This polling request might leak information about the association of a just checked-in trace ID and the identity of the Guest (directly contradicting O2). As mobile phone network typically use NAT, the fact that the Luca Server does not log any IP addresses and the connection being unauthenticated, we do accept this risk.
```

So, what I described under `1. Classifiers in HTTP request headers` is an handled with "we do accept this risk". Again, I want to emphasize, that this statement refers to the user's IP-Address (not avoidable), not to the additional classifiers introduced by the app itself (not necessary).

So let's have a look, how frequently the polling occurs, to get a better picture. The polling is handled by the already mentioned Endpoint `/traces/bulk`:

```
  ..snip..
  07:29:48 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:29:51 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:29:54 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:29:57 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:30:00 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:30:03 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:30:06 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  07:30:09 HTTPS POST app.luca-app.de /api/v3/traces/bulk
  ..snip..
```

So when the app is running in foreground, the **endpoint is polled in a 3 second interval**.

In contrast to the (not unspecific) process description in [Check-In via Mobile Phone App](https://luca-app.de/securityconcept/processes/guest_app_checkin.html#process-guest-checkin), **the polling happens all the time, not only after a check-in**. At this point in time, the app wasn't used to create even a single check-in.

What about the content of the polling requests?

### Body data of POST request to `https://app.luca-app.de/api/v3/traces/bulk`:

```
{
    "traceIds": [
        "H2Tceqpx1yAl5ej3Mk1aAg==",
        "BHEHUaHvu0du0B0lobzVGw==",
        "50zVzW7ZS5+qPjKfPhdjsg==",
        "E4Rr5NtfbVvPXkoPxnUqew==",
        "s+yvuYyw6t78lGazu5VK1Q=="
    ]
}
```

For each polling request (avery 3 seconds) a set of device-generated 'trace IDs' is sent to the endpoint. This 'trace ID set' could safely be regarded as a user pseudonym. This is because each contained 'trace ID' was derived from the non-public 'tracing secret' of the user. The chance that another user generates a 'trace ID' which equal to an ID in this set is close to zero. This is because the ID is generated as `trace_id = HMAC-SHA256(user_id || timestamp, tracing_secret) # truncated to 16 bytes` **with a very low probability of collisions**. Even for the unlikely case, that a redundant 'trace ID' would be generated by another user, the combination of multiple 'trace IDs' in a set would allow to distinguish them clearly.

**To sum up: If the same 'trace IDs' are used across multiple requests, they could be used to uniquely identify a user device, even if the IP address changes.**

_Note: I am using the terms `user` and `device` interchangeably, because the user's `tracing secret` from which the IDs are generated, is unique per device. While calculated `trace IDs` are related to the luca-user, they do not reveal any contact data. Yet, it should be clear that `trace IDs` meet all requirements to serve as unique device identifier._

The `trace ID set` which gets sent every 3 seconds, continuously grows, as a newly generated `trace ID` is added every 60 seconds (the interval in which trace IDs are re-generated). For the tracing secret, the documentation states the following:

```
Moreover, the tracing secret is rotated on a regular basis in order to limit the number of trace IDs that can be reconstruced when the secret is shared.
```

The `tracing secret rotation` **does not change the fact, that a `trace ID` could be used as device identifier** (which is also is not the purpose of the rotation).

## 3. What the luca-backend has learned so far

According to the observation, the luca-backend learned how a unique set of `trace IDs` is associated to a single device, where the device is represented by the following classifier set:

- requesting IP-Address (could change)
- OS version (unlikely to change often)
- device manufacturer (persistent)
- device model (persistent)

Moreover, if the device' IP-address changes (f.e. after disruption of the mobile data connection), the `trace IDs` could be used to re-identify the same device across IP-Address changes, if a `trace ID` re-appears in a request after the address change.

So are `trace IDs` re-used across multiple backend requests? Yes, they are. As pointed out, the set of `trace IDs` sent to the endpoint `/traces/bulk` grows continuously, while new IDs are generated (up till a condition, which I will cover later), and gets transmitted to the backend every 3 seconds, when the app is in foreground. **Moreover, the device-unique `trace ID set` which gets transmitted, survives the following conditions without changes:**

- temporary connectivity loss
- temporary connectivity loss with IP address change
- application restart
- **device reboot**

Even if the device gets rebooted, as soon as the app starts again, the same identifier set gets sent (with new `trace IDs` appended, as they are generated).

The following additional facts are worth noting, for `trace ID sets` transmitted to `/traces/bulk`:

- no invalid trace IDs are introduced (no artificial error or bias is introduced)
- chronological order of trace IDs (last ID is always the one used, when the QR code gets scanned for self check-in)

So at which point does this "tracking" behavior change? It changes once a self check-in occurs!

## 4. Self check-in

To further analyse the polling behavior, it was necessary to do a `self check-in` against a publicly known location (Internet-published check-in QR code). The app sends the following POST request body data to the endpoint `/traces/checkin` to do so:

```
{
    "data":
"9XRuN771VktvWNfGbaxfg86qRxlqYe6I/CyBNCSG4a9htSkXMv4rVSGTVxzKlQjGzVMMpJQr1uDpmVAIkV9ciYcULydZS8n5hDRL",
    "deviceType": 1,
    "iv": "iHEzRMhhSrNSRR61OcMhRA==",
    "mac": "K8exxD+s1sHT026Muvwlz2yQ4Ij/NdTmLkfe3yNtgTc=",
    "publicKey": "BHuLR1yt98FsTfcnqv6IkSKw8Hn9EA597/ojKqxEz+zgL8RXhn/qRafQakqYSPE2CnxiY6oBYIF17ZqH5aZCksA=",
    "scannerId": "ec11e236-cf8a-419a-8644-68c56d8b8939",
    "timestamp": 1618295400,
    "traceId": "CbP29lubGaDIUD+QWJkcPg=="
}
```

In case of a "scanner check-in" this data would be sent to the luca-backend by the "scanner frontend", in case of "self check-in" this request gets sent by the user device. Distinguishing the two cases does not matter for my considerations, as the data always involves the `tracie ID` used for the check-in. Remember: The backend already learned about how `trace IDs` are associated to a user device, even if the IP-Address changes or the device is rebooted.

The next step is the one, which is actually describe for the [guest check-in process](https://luca-app.de/securityconcept/processes/guest_app_checkin.html#process):

```
Therefore, the Guest App polls the Luca Server via an unauthenticated connection. This inquires whether a Check-In was uploaded by a Scanner Frontend with a trace ID that the Guest App recently generated. Once this inquiry polling request is acknowledged by the Luca Server, the Guest App assumes that a successful QR code scan and Check-In was performed. Some UI feedback is provided to the Guest.
```

The user device continues to poll the `/traces/bulk` endpoint with the list of generated `trace IDs` including the one which was used for check-in:

### Body data of POST request to `https://app.luca-app.de/api/v3/traces/bulk` after checkin:

```
    "traceIds": [
        "H2Tceqpx1yAl5ej3Mk1aAg==",
        "BHEHUaHvu0du0B0lobzVGw==",
        "50zVzW7ZS5+qPjKfPhdjsg==",
        "E4Rr5NtfbVvPXkoPxnUqew==",
        "s+yvuYyw6t78lGazu5VK1Q==",
        "x1AgyFZg9Y6QcCUsAGEzDw==",
        "72EKGBGsDGpL6JB1EI1p4w==",
        "kNTZZ7Zs0Bb9shXSvlGeJw==",
        "/DI7FvPnlf8bQR3VKWy8cA==",
        "iHxdgTRB7q+sC19Z806urQ==",
        "iHxdgTRB7q+sC19Z806urQ==",
        "AwjP8y56D1ZdhtDM642EKA==",
        "CbP29lubGaDIUD+QWJkcPg=="
    ]
```

While previous requests received an empty JSON array `[]` in response the post-checkin-request receives the following response:

```
[
    {
        "checkin": 1618295400,
        "checkout": null,
        "createdAt": 1618295427,
        "locationId": "866170ab-0d0a-44ca-b441-1fd6e02b3579",
        "traceId": "CbP29lubGaDIUD+QWJkcPg=="
    }
]
```

So the last `trace ID` for which the device was polling, is now associated to a `location ID`. The fact, that the last `trace ID` in the set used for polling requests, was also the one used for the actual check-in, does not even matter. This is, because the response includes the exact `trace ID` in use - associated to the `location ID`. It is out of question, if the luca-backend has learned about which device is checked-in to which location, as it provides the plain information itself.

Before moving on, I want to define the phrase `"...the luca-backend learned..."` more precisely: All observations are based on monitoring legacy HTTP traffic between the app and the backend. This involves interception of the underlying TLS connection. As the luca-backend has to terminate the TLS connection at some point, I am not only talking about identifiers and classifiers learned by the luca-backend operators. The same information is available to all intermediaries placed behind the front-facing TLS endpoint (e.g. proxies, load balancers, WAF providers etc). One could conclude, that intermediaries do not learn about the user's source IP, but this does not hold true as most intermediaries include the source IP address in additional HTTP headers, to preserve it to for actual application server (f.e. X-Forwarded-For` header). From now on, I will use the term **observer** for to describe an entity which is able to look into plain HTTP content, this **always involves luca backend operators**!

Moving on...

Once the app received the `loactionId` for the `trace ID` which was used for check-in against the backend, the app **immediately** requests additional (plain) location data from the endpoint `https://app.luca-app.de/api/v3/locations/{locationId}`

### Response body for GET request towards `https://app.luca-app.de/api/v3/locations/866170ab-0d0a-44ca-b441-1fd6e02b3579`

```
{
    "city": "Büchen",
    "createdAt": 1617001391,
    "firstName": "",
    "groupName": "Bürgerhaus",
    "lastName": "",
    "lat": 53.48026,
    "lng": 10.61603,
    "locationId": "866170ab-0d0a-44ca-b441-1fd6e02b3579",
    "locationName": "Sitzungssaal",
    "name": "Bürgerhaus - Sitzungssaal",
    "phone": "",
    "publicKey": "BIb7wN2dShGNOXbzQq8wfW7Q/iv3jWrQSSFbkqjO6O9HuKR1WSxRpAfxYdKByN31qe8HHn+Evnq289RDXHoNtaU=",
    "radius": 0,
    "state": "Schleswig-Holstein",
    "streetName": "Amtsplatz",
    "streetNr": "1",
    "zipCode": "21514"
}
```

## 5. At this point, an observer of the plain HTTP content has the following information:

- checkin `trace ID` (associated to a device, even after reboot, connectivity loss, IP-address change or app restart)
- checkin location, with all relevant data
- checkin time

From the request to `https://app.luca-app.de/api/v3/locations/{locationId}` alone, an observer learns (without continuosly monitoring `/traces/bulk`):

- plain location data
- high probability for a check-in of the requesting device (IP address, device brand, device model, OS version), because the request appears immediately after check-in

Even an observer, which only monitors the request URL (f.e. a WAF protecting the endpoint, load balancers, log servers etc), could draw the conclusion that the request is associated to a check-in (of the requesting device) at this exact point in time, while the location could be derived from the URI path.

In fact, the only thing which is not known to an observer or the backend operators is the content of the `encrypted contact data` (which, again, isn't of much value, because it does not have to be valid).

## 6. post-check-in behavior

Once the user has checked in to a location, the data set used to poll `/traces/bulk` changes for the first time.

### Body data of POST request to `https://app.luca-app.de/api/v3/traces/bulk` after check-in:

```
traces3_req={
    "traceIds": [
        "CbP29lubGaDIUD+QWJkcPg=="
    ]
}
```

The data set now only includes the `trace ID` used for the most recent check-in. No new IDs are added anymore (the app generates no new QR codes, as the UI shows the checkout dialog, now).

Also, to be more precise, this behavior change dos not occur directly after check-in (there have already been requests with a larger `trace ID set` including the check-in `trace ID`, which received a `locationID`in response). Instead, the behavior changes after the successful request to the aforementioned endpoint `/locations/{locationId}`. This, again, allows an observer to confirm a successful check-in to the location of a previous request.

Also, the continuous polling of a **single** `trace ID` allows to draw the conclusion that the device is checked in into a location with this exact ID (the list would otherwise get a new `trace ID` appended after 60 seconds, while the minimum time interval before a checkout is also enforced to 60 seconds). The checkin location itself, is provided in the HTTP response each time:

```
[
    {
        "checkin": 1618295400,
        "checkout": null,
        "createdAt": 1618295427,
        "locationId": "866170ab-0d0a-44ca-b441-1fd6e02b3579",
        "traceId": "CbP29lubGaDIUD+QWJkcPg=="
    }
]
```

So there is not even a need to monitor `/traces/bulk` continuously. A single bulk request, which holds a single `traceId` and receives as single `locationId` in response, could be safely assumed to indicate that the device is currently checked in to this exact location.

Such a request is sent every 60 seconds, now (increased polling interval, while user is checked in to a location).

## 7. Checkout

The checkout does itself does not add much information, with respect to the scope of this document. But it is worth mentioning, because of some other aspects.

### checkout POST request body against https://app.luca-app.de/api/v3/traces/checkout

```
{
    "timestamp": 1618296420,
    "traceId": "CbP29lubGaDIUD+QWJkcPg=="
}
```

For the checkout, the app provides a timestamp along with the `trace ID` associated to the checkin location. While the backend API places some measures against invalid timestamps (for example sending a checkout timestamp which is smaller than the checkin timestamp produces a 409 response), but an attacker could send random 'trace IDs' with a recent timestamp, to check-out random luca-users. This comes down to brute-forcing of valid 'trace IDs' and shall be countered by rate limiting. As the scenario is not in scope of this document, no tests for proper rate limiting have been carried out.

## 8. post checkout behavior

Once the user has checked out, the poling behavior against `/traces/bulk` is the same as described in section `2. Communication after application startup`. Before polling starts, again, the list of polled `trace IDs` is flushed. Still all conditions are met to allow an observer to track a unique device across polling requests (even if the IP-Address changes).

There is a single request, which could not be associated to a unique device, based on the transmitted `trace IDs`, as it just contains no `trace ID`. This is the very first request to `/traces/bulk` after the checkout. This is likely, because the next `trace ID` generated by the app was not put to the flushed `trace ID set` before the first polling request was sent. Anyways, this is only true for 3 seconds (which is the new polling interval), as the 2nd request contains a `trace ID`, again.

## Summary of information available to an observer of the `/traces/bulk` endpoint

1. This endpoint continuously receives HTTP requests, which include `trace IDs` which are unique to a single mobile device participating in the luca ecosystem.

2. While the `trace IDs` are suitable to uniquely identify a device, each request includes additional device classifiers (not covered by data protection laws). Those identifiers are not only usable for device fingerprinting. Given the fact that the Luca-system was designed to be extended with interfaces for services which offer less anonymity (f.e. event ticket handling), it should be kept in mind, that the device classifiers collected with each request (IP address, OS Version, device manufacturer, device model, request timestamp) could easily be associated to the same classifiers collected by "other services" for a large time window. This especially gets a problem, if those "other services" are operated by entities which involved in luca-backend operation (which includes possibly includes providers of intermediary sub-services like WAF, DDoS protection etc.).

3. As the `trace IDs` have the property of being unique to a device, they could be used to associated different requests against the endpoint to the same device, in case they are reused throughout successive requests. In fact, not only a single `trace ID` is reused, instead whole sets of `trace IDs` are sent to the endpoint by each device, with a high amount of overlap per participating device. This not only is an enabler for continuos device tracking, it also allows to associate different requests to the same device while its IP-Address has changed, ultimately allowing full-fledged behavior analysis.

4. A device's check-in state is known, by observing the endpoint for more than 60 seconds:

   4.1 If a device is not checked-in to a location, the device polls the endpoint in a **3 second interval**, with a continuously growing set of `trace IDs`. Multiple, successive requests of the same device could be associated to each other, based on overlapping `trace IDs`, even if the IP-Address and additional classifiers are disregarded. The state of a `trace ID set` used by a participating device to poll against `/traces/bulk` even survives device a reboot.

   4.2 If a device is checked-in to a location, the device polls the endpoint in a **60 second interval**, with a **single** `trace ID`. This trace ID is the one, which was used to check-in to the location. The `locationID` which could be used to obtain detailed plaintext information on the location, is contained in the HTTP response (additional location information could be retrieved from other endpoints, as detailed in this document). Multiple, successive requests of the same device could be associated to each other,based on the single `trace ID`, even if the IP-Address and additional classifiers are disregarded. _Note: If a user is not checked in to a location, a request with a single `trace ID` could still occur, but the response would not contain a `locationId` - also the polling interval would be 3 seconds, not 60 seconds_

## Conclusion

The only information which can not be obtained by observing the `/trace/bulk` endpoint, is the actual user contact data. This isn't worth much, as it has been proven multiple times, that random user contact data could be provided to the luca ecosystem (because the validation could be bypassed, which also affects the provide mobile number). The ability to analyse mobile device behavior as described above, **does not require any interaction with health departments or location owners**. Not only backend operators are able to obtains those information, also every intermediary service behind the front-facing TLS endpoint is able to do so. This of course includes possible attackers, which remain undetected.

### Personal note:

The fact that the luca-backend is able to track a unique device accross IP-address changes (based on the unique set of polled tracingIDs) is not only questionable in terms of privacy, it also appears to be absolutely unnecessary. The same is true for the collection of additional device classifiers in the User-Agent string, they just have no proper use in the advertised anonymous check-in tracing system.
