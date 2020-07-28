/*
Frida test script for privacy related tracing of Android apps
*/

var printBacktrace = function() {
  Java.perform(function() {
    var android_util_Log = Java.use("android.util.Log"),
      java_lang_Exception = Java.use("java.lang.Exception")
    // getting stacktrace by throwing an exception
    console.log(
      android_util_Log.getStackTraceString(java_lang_Exception.$new())
    )
  })
}

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

Java.perform(function() {
  var logSettings = { c: Color.Light.Green }
  var clazz = Java.use("java.net.HttpURLConnection")

  clazz.$init.implementation = function(url) {
    LOG("HttpUrlConnection()\n-- URL: " + url, logSettings)

    //	printBacktrace();
    return clazz.$init.apply(this, arguments)
  }
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

    LOG(
      "GetTelephonyProperty(phoneID=" +
        phoneId +
        " property='" +
        property +
        "' defaultVal='" +
        defaultVal +
        "')",
      logSettings
    )
    LOG("\t=> '" + res.toString() + "'", logSettings)

    //	printBacktrace();
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

  clazzWifiInfo.getFrequency.implementation = function() {
    var out = "WifiInfo."
    var res = clazzWifiInfo.getFrequency.apply(this, arguments)
    out += "getFrequency => " + res
    LOG(out, logSettings)
    return res
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
