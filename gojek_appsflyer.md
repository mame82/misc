# Gojek AppsFlyer notes

Gojek sends massive amounts of privacy related data to AppsFlyer

Data is stored in 'com.appsflyer.AFEvent' instances.

Before data gets pushed out, it is encrypted.

AFEvent class has a property `public Map<String, Object> params` which could be used to
fetch the plain data.

## Note 1: 

As there also exists a AFEvent.params() method, the property has to be fetched with
<AFEvent instance>._params.value if Frida is used

## Note 2

Encrypted data (once generated) is stored as byte[] in the AFEvent using the member
function `public AFEvent post(byte[] encryptedData)`. This function is a nice place to
hook. Once it gets called, the `params` member field could easily be converted to
a JSON string, using Android's `org.json.JSONObject`.

Here's an example code snippet from a frida-trace hook for `com.appsflyer.AFEvent!post`
which decodes the `params` property to a JSON string and logs it:

```
  onEnter: function (log, args, state) {
        try {
            log('AFEvent.post(' + args.map(JSON.stringify).join(', ') + ')');
            let paramsMap = this._params.value
            const clazzJO = Java.use("org.json.JSONObject")
            let jsonParams = clazzJO.$new(paramsMap)
            log("AFEvent.urlString:",this.urlString())
            log("AFEvent.params",jsonParams.toString())
        } catch (e) {
                log("Exception in hook for AFEvet.post", e)
        }
  },

```

# AFEvent encryption

There's strong indication, that encryption id done by the function

`ı` (function name corresponds to U+0131) of class `com.appsflyer.internal.j`.

The function gets accessed using reflections. Stringifying the Method object
after it gets accessed (I don't want to deep dive on where the `java.lang.reflect.Method`
object is fetched, as the surrounding code is heavily obfuscated) reveals the following method siganture:

```
public static byte[] com.appsflyer.internal.j.ı(com.appsflyer.AFEvent)
```

So there is a static class method, which receives an `AFEvent` object and produces an (encrypted)
byte[] as result. This byte[] then is stored back into the AFEvent using AFEvent.post(byte[]).

The AFEvent gets eventually send out using `java.net.HttpURLConnection` in a POST request, for which
the stored encrypted data byte[] serves as request body. Content-type for the request is
`application/octet-stream`. If encryption is disabled, a plain JSON object would be sent out with the request.


Now, while the aforementioned encryption function `com.appsflyer.internal.j.ı` could be hooked with Frida
at runtime, the whole class `com.appsflyer.internal.j` is not included in the dex files of the app.
Also early instrumentaion would fail, as the class is loaded at runtime.

I placed a small frida-trace hook on `com.appsflyer.internal.j.ı`, to get some insights on the ClassLoader
in use:

```
  onEnter: function (log, args, state) {
// method sig: "public static byte[] com.appsflyer.internal.j.ı(com.appsflyer.AFEvent)"
// likely AFEvent encryption
    log('j.ı(' + args.map(JSON.stringify).join(', ') + ')');
    let ae = args[0]
    let ldr = this.class.getClassLoader()
    log(`loader=${ldr}`)
  },

```

Unsuprisingly, the respective class is loaded by an in-memory ClassLoader, which itself was loaded from
a buffer in RAM. 

Below, an excerpt of the output from the hook:

```
  3196 ms  j.ı("<instance: com.appsflyer.AFEvent, $className: com.appsflyer.internal.model.event.Launch>")
  3196 ms  loader=dalvik.system.InMemoryDexClassLoader[DexPathList[[dex file "InMemoryDexFile[cookie=[0, 2865265056]]"],nativeLibraryDirectories=[/data/app/com.gojek.app-IVJiC-UoLeJjQ3xI9DDuoQ==/lib/arm, /data/app/com.gojek.app-IVJiC-UoLeJjQ3xI9DDuoQ==/base.apk!/lib/armeabi-v7a, /system/lib, /system/vendor/lib]]]
  3388 ms  <= [-93,70,77,-124,9, ...snip...
```

So the class loader used to propagate the `com.appsflyer.internal.j` (and likely other runtime classes) is an instance of `dalvik.system.InMemoryDexClassLoader`.

## Dumping in Memory dex files

After a while of digging into the Dalvik implementation for InMemoryDexClassLoader functionality, I learned that in-memory dexfiles
are created here (at least if this isn't an array of dex files): https://android.googlesource.com/platform/libcore/+/57dfd7182e6d169ec5a195ab03900a323b27ea13/dalvik/src/main/java/dalvik/system/DexFile.java#120

The relevant code 

```
    DexFile(ByteBuffer buf) throws IOException {
        mCookie = openInMemoryDexFile(buf);
        mInternalCookie = mCookie;
        mFileName = null;
    }

... snip...

    private static Object openInMemoryDexFile(ByteBuffer buf) throws IOException {
        if (buf.isDirect()) {
            return createCookieWithDirectBuffer(buf, buf.position(), buf.limit());
        } else {
            return createCookieWithArray(buf.array(), buf.position(), buf.limit());
        }
    }

    private static native Object createCookieWithDirectBuffer(ByteBuffer buf, int start, int end);
    private static native Object createCookieWithArray(byte[] buf, int start, int end);
```

I was a bit lazy, instead of hooking 'openInMemoryDexFile', I hooked both
'createCookie*' functions with frida-trace using a command like this:

```
frida-trace -U -j '*AFEvent*!post*' -j 'com.appsflyer.internal.j!ı' -j '*!*openInMemory*' -j '*!*createCookie*' -f com.gojek.app
```

... it turns out, that the buffers holding the runtime dex files aren't direct and `createCookieWithArray` is called.
That's good, as it is easier to deal with Java `byte[]` then with `ByteBuffer` objects from the frida perspective.

As dumping of the dexfiles is a one-time-job, I did not fully automate it, but used base64 encoding and manual copy&paste
for decoding.

My frida-trace handler script for `dalvik.system.DexFile.createCookieWithArray(byte[] buf, int start, int end)` looks like this:

```
/*
 * Auto-generated by Frida. Please modify to match the signature of DexFile.createCookieWithArray.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
  /**
   * Called synchronously when about to call DexFile.createCookieWithArray.
   *
   * @this {object} - The Java class or instance.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Java method arguments.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onEnter: function (log, args, state) {
    log('DexFile.createCookieWithArray(...snip...)');
    let byteArray = args[0]
    let start = args[1]
    let end = args[2]
    
    let b64 = Java.use("android.util.Base64")
    let b64Str = b64.encodeToString(byteArray, start, end, 0)
    log("base64 dump:\n" + b64Str)
  },

  /**
   * Called synchronously when about to return from DexFile.createCookieWithArray.
   *
   * See onEnter for details.
   *
   * @this {object} - The Java class or instance.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {NativePointer} retval - Return value.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onLeave: function (log, retval, state) {
    if (retval !== undefined) {
      log('<=', JSON.stringify(retval));
    }
  }
}
```

The handler script is applied is applied to the Gojek app with (spawn gating, to catch events from the very beginning):

```
frida-trace -U -j '*!*createCookie*' -f com.gojek.app
```

Note the wildcard after `createCookie*`, it assures that calls to `createCookieWithDirectBuffer` are traced, too (just in case).

Once frida trace is running, the output looks something like this:

```
# frida-trace -U -j '*!*createCookie*' -f com.gojek.app
Instrumenting...                                                        
DexFile.createCookieWithArray: Loaded handler at "/root/research/android/__handlers__/dalvik.system.DexFile/createCookieWithArray.js"
DexFile.createCookieWithDirectBuffer: Loaded handler at "/root/research/android/__handlers__/dalvik.system.DexFile/createCookieWithDirectBuffer.js"
Started tracing 2 functions. Press Ctrl+C to stop.                      
           /* TID 0x6af5 */
  5637 ms  DexFile.createCookieWithArray(...snip...)
  5637 ms  base64 dump:
ZGV4CjAzNQCcBTCtZCzrJ1f8Vwb3MBjLHX5proWPYF3IOwAAcAAAAHhWNBIAAAAAAAAAAPg6AABy
AAAAcAAAACwAAAA4AgAAIQAAAOgCAAAQAAAAdAQAAC4AAAD0BAAAAQAAAGQGAABENQAAhAYAAAI0
 ... snip ...
AAAuAAAA9AQAAAYAAAABAAAAZAYAAAEgAAAOAAAAhAYAAAMgAAAMAAAA3S8AAAEQAAARAAAAZDMA
AAIgAAByAAAAAjQAAAQgAAAFAAAA8TkAAAAgAAABAAAAJzoAAAUgAAABAAAAhzoAAAMQAAAFAAAA
mDoAAAYgAAABAAAAwDoAAAAQAAABAAAA+DoAAA==

  5695 ms  <= "<instance: java.lang.Object, $className: [J>"
  5768 ms  DexFile.createCookieWithArray(...snip...)
  5768 ms  base64 dump:
ZGV4CjAzNQCnSsAmHmAxROD/uZcWnAYIh4K4UxG6F4IgfQAAcAAAAHhWNBIAAAAAAAAAAFB8AADm
AAAAcAAAAGEAAAAIBAAAVQAAAIwFAABLAAAAiAkAALAAAADgCwAADgAAAGARAAAAagAAIBMAAOBi
AADiYgAA5WIAAOpiAADtYgAAp2YAALFmAAC5ZgAAvWYAAMBmAADDZgAAxmYAAMpmAADWZgAA2WYA
...
```

Each base64 string represents a raw dex-class.

As already mentioned, I just copied each b64 string and pasted it back to a file.

If the resultin file is called `dump_dex1.b64` it could be converted back to a dex file like this:

`cat dump_dex1.b64 | base64 -d > dump1.dex`

The resulting file could be processed with the usual tools for dex decompilation,
but this is up to the reader.

Of course, the AppFlyer classes with the encryption routines, which have been missing
int the package, are part of the output.

I haven't done any investigation on how the respective ByteBuffers get loaded, as I am
too lazy. Anyways, malware could use this to load code from encrypted resources directly into memory
and this write-up shows a simple way to deal with such cases.
