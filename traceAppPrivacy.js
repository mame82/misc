/*
Frida test script for privacy related tracing of Android apps
*/

// from https://github.com/iddoeldor/frida-snippets
var Color = {
  RESET: "\x1b[39;49;00m",
  Black: "0;01",
  Blue: "4;01",
  Cyan: "6;01",
  Gray: "7;11",
  Green: "2;01",
  Purple: "5;01",
  Red: "1;01",
  Yellow: "3;01",
  Light: {
    Black: "0;11",
    Blue: "4;11",
    Cyan: "6;11",
    Gray: "7;01",
    Green: "2;11",
    Purple: "5;11",
    Red: "1;11",
    Yellow: "3;11"
  }
}

/**
 *
 * @param input.
 *      If an object is passed it will print as json
 * @param kwargs  options map {
 *     -l level: string;   log/warn/error
 *     -i indent: boolean;     print JSON prettify
 *     -c color: @see ColorMap
 * }
 */
var LOG = function(input, kwargs) {
  kwargs = kwargs || {}
  var logLevel = kwargs["l"] || "log",
    colorPrefix = "\x1b[3",
    colorSuffix = "m"
  if (typeof input === "object")
    input = JSON.stringify(input, null, kwargs["i"] ? 2 : null)
  if (kwargs["c"])
    input = colorPrefix + kwargs["c"] + colorSuffix + input + Color.RESET
  console[logLevel](input)
}

var getStacktrace = function() {
  //Java.perform(function() {
  var android_util_Log = Java.use("android.util.Log")
  var java_lang_Exception = Java.use("java.lang.Exception")
  var trace = android_util_Log.getStackTraceString(java_lang_Exception.$new())
  var caller =
    "Called by: " +
    Java.use("java.lang.Exception")
      .$new()
      .getStackTrace()
      .toString()
      .split(",")[1] +
    "\n"
  trace = caller + trace
  return trace
  //})
}

var printBacktrace = function() {
  Java.perform(function() {
    console.log(getStacktrace())
  })
}

var printBacktraceIfReflectionUsed = function() {
  Java.perform(function() {
    var trace = getStacktrace()
    if (trace.includes("at java.lang.reflect"))
      LOG("stacktrace hints REFLECTION usage\n" + trace, { c: Color.Light.Red })
  })
}

var findLoaderForClass = function(className) {
  console.log("Searching loader for class: " + className)
  var ldrs = Java.enumerateClassLoadersSync()
  for (var i = 1; i < ldrs.length; i++) {
    console.log(ldrs[i])

    var classLoaderToUse = ldrs[i] //Get another classloader
    Java.classFactory.loader = classLoaderToUse //Set the classloader to the correct one
    try {
      var res = classLoaderToUse.findClass(className) //Just some simple test to make sure that the class can be loaded
    } catch (e) {
      if (i == ldrs.length - 1) throw e // pass up ClassNotFoundException if this is the last loader

      continue
    }

    console.log("Class search result...:")
    console.log(JSON.stringify(res))
    return Java.use(className)
  }
}

Java.perform(function() {
  var clazz = Java.use("android.content.ContextWrapper")
  var clazzIntentFilter = Java.use("android.content.IntentFilter")

  clazz.registerReceiver.overload(
    "android.content.BroadcastReceiver",
    "android.content.IntentFilter"
  ).implementation = function() {
    console.log("ContextWrapper.registerReciever: " + JSON.stringify(arguments))

    var res = clazz.registerReceiver.apply(this, arguments)
    var br = arguments[0] // broadcast receiver
    var filter = arguments[1] // IntentFilter

    var ai = filter.actionsIterator()
    while (ai.hasNext()) {
      console.log("\tAction: " + ai.next())
    }

    if (br != null) {
      var brClass = br.$className
      console.log("\tReceiverClass: " + brClass)
    } else {
      // sticky intent: https://developer.android.com/reference/android/content/ContextWrapper#registerReceiver(android.content.BroadcastReceiver,%20android.content.IntentFilter)
      console.log("\tSticky Intent: " + res.toString())
    }

    //	printBacktrace();

    return res
  }

  clazz.registerReceiver.overload(
    "android.content.BroadcastReceiver",
    "android.content.IntentFilter",
    "java.lang.String",
    "android.os.Handler"
  ).implementation = function() {
    var res = clazz.registerReceiver.apply(this, arguments)
    console.log("ContextWrapper.registerReciever: " + res)

    var br = arguments[0] // broadcast receiver
    var filter = arguments[1] // IntentFilter
    var ai = filter.actionsIterator()
    while (ai.hasNext()) {
      console.log("\tAction: " + ai.next())
    }
    if (br != null) {
      var brClass = br.$className
      console.log("\tReceiverClass: " + brClass)
    } else {
      // sticky intent: https://developer.android.com/reference/android/content/ContextWrapper#registerReceiver(android.content.BroadcastReceiver,%20android.content.IntentFilter)
      console.log("\tSticky Intent: " + JSON.stringify(res))
    }

    //	printBacktrace();

    return res
  }
})

// HTTP
Java.perform(function() {
  var logSettings = { c: Color.Light.Green }
  var clazz = Java.use("java.net.HttpURLConnection")

  clazz.$init.implementation = function(url) {
    LOG("HttpUrlConnection()\n-- URL: " + url, logSettings)

    //	printBacktrace();
    return clazz.$init.apply(this, arguments)
  }

  // TikTok only
  /*
  var clazzTTNetCronetEngineBase = Java.use(
    "com.ttnet.org.chromium.net.impl.CronetEngineBase"
  )

  clazzTTNetCronetEngineBase.newUrlRequestBuilder.overloads[0].implementation = function() {
    var res = clazzTTNetCronetEngineBase.newUrlRequestBuilder.apply(
      this,
      arguments
    )
    var out =
      "(TikTok) CronetEngineBase.newUrlRequestBuilder()\n-- URL: " +
      arguments[0]
    LOG(out, logSettings)
    return res
  }
  */
})

// android.telephony.TelephonyManager.getTelephonyProperty(int, java.lang.String, java.lang.String)
Java.perform(function() {
  var logSettings = { c: Color.Light.Yellow }
  var clazz = Java.use("android.telephony.TelephonyManager")

  clazz.getTelephonyProperty.overload(
    "int",
    "java.lang.String",
    "java.lang.String"
  ).implementation = function(phoneId, property, defaultVal) {
    var res = clazz.getTelephonyProperty.apply(this, arguments)
    var out =
      "GetTelephonyProperty(phoneID=" +
      phoneId +
      " property='" +
      property +
      "' defaultVal='" +
      defaultVal +
      "')\n"

    out += "\t=> '" + res + "' [" + typeof res + "]\n"
    LOG(out, logSettings)

    //printBacktrace()
    return res
  }

  /*
  clazz.getTelephonyProperty.implementation = function() {
    var res = clazz.getTelephonyProperty.apply(this, arguments)
    var phoneId = arguments[0]
    var property = arguments[1]
    var defaultVal = arguments[2]
    var out =
      "GetTelephonyProperty(phoneID=" +
      phoneId +
      " property='" +
      property +
      "' defaultVal='" +
      defaultVal +
      "')\n"

    out += "\t=> '" + res + "' [" + typeof res + "]\n"
    LOG(out, logSettings)

    //printBacktrace()
    return res
  }
  */
})

// NetworkInfo
Java.perform(function() {
  var logSettings = { c: Color.Light.Purple }
  var clazzNetworkInfo = Java.use("android.net.NetworkInfo")

  // Note: used by com.bytedance.common.utility.l.d()
  // Used by TikTok to determine connection type (send in HTTP requests as param 'ac' and 'ac2')
  clazzNetworkInfo.getType.implementation = function() {
    var out = "NetworkInfo."
    var res = clazzNetworkInfo.getType.apply(this, arguments)
    out += "getType => " + res + " (" + this.getTypeName() + ")"

    LOG(out, logSettings)
    return res
  }

  clazzNetworkInfo.getState.implementation = function() {
    var out = "NetworkInfo."
    var res = clazzNetworkInfo.getState.apply(this, arguments)
    out += "getState => " + res
    LOG(out, logSettings)
    return res
  }
})

// WifiInfo
Java.perform(function() {
  var logSettings = { c: Color.Light.Purple }
  var clazzWifiInfo = Java.use("android.net.wifi.WifiInfo")

  clazzWifiInfo.getMeteredHint.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getMeteredHint.apply(this, arguments)
    out += "getMeteredHint => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getWifiSsid.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getWifiSsid.apply(this, arguments)
    out += "getWifiSsid => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getMacAddress.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getMacAddress.apply(this, arguments)
    out += "getMacAddress => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getIpAddress.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getIpAddress.apply(this, arguments)
    out += "getIpAddress => " + res
    LOG(out, logSettings)
    return res
  }

  // Note: used by com.bytedance.common.utility.l.d() to determine of WiFi is 'wifi5g'
  // Used by TikTok to distinguish 2.4G and 5G WiFi (send in HTTP requests as param 'ac2')
  clazzWifiInfo.getFrequency.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getFrequency.apply(this, arguments)
    out += "getFrequency => " + res
    LOG(out, logSettings)
    //return res
    return 5200
  }

  clazzWifiInfo.getSupplicantState.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getSupplicantState.apply(this, arguments)
    out += "getSupplicantState => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getLinkSpeed.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getLinkSpeed.apply(this, arguments)
    out += "getLinkSpeed => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getRssi.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getRssi.apply(this, arguments)
    out += "getRssi => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getDetailedStateOf.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getDetailedStateOf.apply(this, arguments)
    out += "getDetailedStateOf => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getNetworkId.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getNetworkId.apply(this, arguments)
    out += "getNetworkId => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getBSSID.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getBSSID.apply(this, arguments)
    out += "getBSSID => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getSSID.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getSSID.apply(this, arguments)
    out += "getSSID => " + res
    LOG(out, logSettings)
    return res
  }

  clazzWifiInfo.getHiddenSSID.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getHiddenSSID.apply(this, arguments)
    out += "getHiddenSSID => " + res
    LOG(out, logSettings)
    return res
  }
})

// SQLite
Java.perform(function() {
  var clazzSQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase")
  var clazzEntry = Java.use("java.util.HashMap$HashMapEntry")
  var logSettings = { c: Color.Light.Cyan }

  clazzSQLiteDatabase.$init.implementation = function() {
    var res = clazzSQLiteDatabase.$init.apply(this, arguments)
    var dbpath = arguments[0]
    console.log("SQLiteDatabase.$init (" + dbpath + ")")
    return res
  }

  clazzSQLiteDatabase.insert.implementation = function() {
    var res = clazzSQLiteDatabase.insert.apply(this, arguments)
    var db = Java.cast(this, clazzSQLiteDatabase)
    var table = arguments[0]
    //var out = "SQLiteDatabase.insert(" + JSON.stringify(arguments) + ")\n"
    var out = "SQLiteDatabase.insert\n"
    out += "-- DBPath : " + db.getPath() + "\n"
    out += "-- Table  : " + table + "\n"
    out += "-- Entries:\n"

    var clazzCV = Java.use("android.content.ContentValues")
    var cvs = Java.cast(arguments[2], clazzCV)
    var it = cvs.valueSet().iterator()
    while (it.hasNext()) {
      var entry = Java.cast(it.next(), clazzEntry)
      var key = entry.getKey()
      var val = entry.getValue()
      if (val != null)
        out += "     " + key + "=" + val + " [" + val.getClass() + "]\n"
      else out += "     " + key + "=" + val + "\n"
    }

    LOG(out, logSettings)
    return res
  }

  clazzSQLiteDatabase.delete.implementation = function() {
    var res = clazzSQLiteDatabase.delete.apply(this, arguments)
    var db = Java.cast(this, clazzSQLiteDatabase)
    var table = arguments[0]
    var whereClause = arguments[1]
    var whereArgs = arguments[2]
    //var out = "SQLiteDatabase.delete(" + JSON.stringify(arguments) + ")\n"
    var out = "SQLiteDatabase.delete\n"
    out += "-- DBPath      : " + db.getPath() + "\n"
    out += "-- Table       : " + table + "\n"
    out += "-- whereClause : " + whereClause + "\n"
    out += "-- whereArgs   : " + whereArgs + "\n"
    out += "-- deleted     : " + res + "\n"

    LOG(out, logSettings)
    return res
  }

  clazzSQLiteDatabase.execSQL.overload(
    "java.lang.String",
    "[Ljava.lang.Object;"
  ).implementation = function() {
    var res = clazzSQLiteDatabase.execSQL.apply(this, arguments)
    var db = Java.cast(this, clazzSQLiteDatabase)
    var query = arguments[0]
    //    var out = "SQLiteDatabase.execSQL(" + JSON.stringify(arguments) + ")\n"
    var out = "SQLiteDatabase.execSQL\n"
    out += "-- DBPath   : " + db.getPath() + "\n"
    out += "-- query    : " + query + "\n"
    LOG(out, logSettings)
    return res
  }

  clazzSQLiteDatabase.execSQL.overload(
    "java.lang.String"
  ).implementation = function() {
    var res = clazzSQLiteDatabase.execSQL.apply(this, arguments)
    var db = Java.cast(this, clazzSQLiteDatabase)
    var query = arguments[0]
    //var out = "SQLiteDatabase.execSQL(" + JSON.stringify(arguments) + ")\n"
    var out = "SQLiteDatabase.execSQL\n"
    out += "-- DBPath   : " + db.getPath() + "\n"
    out += "-- query    : " + query + "\n"
    LOG(out, logSettings)
    return res
  }

  clazzSQLiteDatabase.rawQueryWithFactory.overload(
    "android.database.sqlite.SQLiteDatabase$CursorFactory", // cursorFactory
    "java.lang.String", //sql (query string)
    "[Ljava.lang.String;", // selectionArgs
    "java.lang.String" // editTable
  ).implementation = function() {
    var res = clazzSQLiteDatabase.rawQueryWithFactory.apply(this, arguments)
    var db = Java.cast(this, clazzSQLiteDatabase)
    var table = arguments[3]
    var query = arguments[1]
    var selection = arguments[2]
    //var out = "SQLiteDatabase.rawQueryWithFactory(" + JSON.stringify(arguments) + ")\n"
    var out = "SQLiteDatabase.rawQueryWithFactory\n"
    out += "-- DBPath   : " + db.getPath() + "\n"
    out += "-- Table    : " + table + "\n"
    out += "-- query    : " + query + "\n"
    out += "-- selection: " + selection + "\n"

    LOG(out, logSettings)
    return res
  }

  clazzSQLiteDatabase.rawQueryWithFactory.overload(
    "android.database.sqlite.SQLiteDatabase$CursorFactory", // cursorFactory
    "java.lang.String", //sql (query string)
    "[Ljava.lang.String;", // selectionArgs
    "java.lang.String", // editTable
    "android.os.CancellationSignal" // cancellationSignal
  ).implementation = function() {
    var res = clazzSQLiteDatabase.rawQueryWithFactory.apply(this, arguments)
    var db = Java.cast(this, clazzSQLiteDatabase)
    var table = arguments[3]
    var query = arguments[1]
    var selection = arguments[2]
    //var out = "SQLiteDatabase.rawQueryWithFactory(" + JSON.stringify(arguments) + ")\n"
    var out = "SQLiteDatabase.rawQueryWithFactory\n"
    out += "-- DBPath   : " + db.getPath() + "\n"
    out += "-- Table    : " + table + "\n"
    out += "-- query    : " + query + "\n"
    out += "-- selection: " + selection + "\n"

    LOG(out, logSettings)
    return res
  }
})

// SystemProperties
Java.perform(function() {
  var clazzSystemProperties = Java.use("android.os.SystemProperties")
  var logSettings = { c: Color.Light.Blue }

  clazzSystemProperties.get.overload(
    "java.lang.String"
  ).implementation = function(key) {
    var res = this.get(key)
    var out = "SystemProperties.get(" + key + ")\n"
    out += "\t=> '" + res + "'\n"

    /*
    if (key === "persist.sys.timezone") out += getStacktrace()
    if (key === "ro.build.display.id") out += getStacktrace() // print stack trace if android build ID is requested
    if (key === "ro.product.cpu.abi") out += getStacktrace() // print stack trace if CPU ABI is requested
    if (key === "ro.product.cpu.abi2") out += getStacktrace() // print stack trace if CPU ABI is requested
    */

    LOG(out, logSettings)

    printBacktraceIfReflectionUsed()
    return res
  }
})

// TimeZone
/*
Java.perform(function() {
  var clazzTimeZone = Java.use("java.util.TimeZone")
  var logSettings = { c: Color.Light.Green }

  clazzTimeZone.getDefault.implementation = function() {
    var res = clazzTimeZone.getDefault()
    var out = "TimeZone.getDefault()\n"
    out += "\t=> '" + res + "'\n"

    //out += getStacktrace()

    LOG(out, logSettings)

    return res
  }

  clazzTimeZone.getDefaultRef.implementation = function() {
    var res = clazzTimeZone.getDefaultRef()
    var out = "TimeZone.getDefaultRef()\n"
    out += "\t=> '" + res + "'\n"

    //out += getStacktrace()

    LOG(out, logSettings)

    return res
  }
})
*/

// Reflection

// Note: Hooking reflective Java classes crashes (f.e. `Class.forName()`, `Method.invoke()`)
Java.perform(function() {
  //  Java.deoptimizeEverything()

  var logSettings = { c: Color.Light.Red }
  var clazzMethod = Java.use("java.lang.reflect.Method")
  var clazzClass = Java.use("java.lang.Class")

  /*

  // This interception leads to crashes (for TikTok)
  // Also, with this hook enabled, TikTok crashes if Frida spawns the App itself (early hooking)
  // ... attaching to the running App leads to a crash at some point, but output works up to this point.
  clazzMethod.invoke.implementation = function() {
    var objInstance = arguments[0]
    var methodArgs = arguments[1]
    var res = clazzMethod.invoke.apply(this, arguments)
    var out = "reflect.Method.invoke(" + JSON.stringify(arguments) + ")\n"
    out += "    Class: '" + this.getDeclaringClass() + "'\n"
    out += "    Method name: '" + this.getName() + "'\n"
    if (objInstance != null) out += "    Instance: '" + objInstance + "'\n"
    if (methodArgs != null) out += "    Arguments: '" + methodArgs + "'\n"
    out += "\t=> '" + res + "'\n"
    LOG(out, logSettings)

    return res
  }

  // This interception leads to crashes (for TikTok)
  // Also, with this hook enabled, TikTok crashes if Frida spawns the App itself (early hooking)
  // ... attaching to the running App leads to a crash at some point, but output works up to this point.
  clazzClass.forName.overload("java.lang.String").implementation = function() {
    var res = clazzClass.forName.apply(this, arguments)
    var out = "Class.forName(" + JSON.stringify(arguments) + ")\n"
    out += "\t=> '" + res + "'\n"
    LOG(out, logSettings)

    return res
  }

  var clazzClass = Java.use("java.lang.Class")
  clazzClass.forName.overload(
    "java.lang.String",
    "boolean",
    "java.lang.ClassLoader"
  ).implementation = function() {
    var res = clazzClass.forName.apply(this, arguments)
    var out = "Class.forName(" + JSON.stringify(arguments) + ")\n"
    out += "\t=> '" + res + "'\n"
    LOG(out, logSettings)

    return res
  }

  */
})

// Untested
Java.perform(function() {
  Java.use("android.webkit.WebView").loadUrl.overload(
    "java.lang.String"
  ).implementation = function(s) {
    send(s.toString())
    this.loadUrl.overload("java.lang.String").call(this, s)
  }
})

Java.perform(function() {
  send("--> isDebuggerConnected - Bypass Loaded")
  var Debug = Java.use("android.os.Debug")
  Debug.isDebuggerConnected.implementation = function() {
    send("isDebuggerConnected() --> returned false")
    return false
  }
})
