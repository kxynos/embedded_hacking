// Andoird Logging by hooking into android.util.Log 
// Mod of https://gist.github.com/subho007/983d7a618694235bc6f2#file-test-js
// K.Xynos (2021)

Java.perform(function () {
    var Log = Java.use("android.util.Log");
    Log.d.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
        send("Log.d()");
        send(a.toString());
        send(b.toString());
        return this.d.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").call(this, a, b, c);
    };
    Log.d.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send("Log.d()");
        send(a.toString());
        send(b.toString());
        return this.d.overload("java.lang.String", "java.lang.String").call(this, a, b);
    };
    Log.v.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
        send("Log.v()");
        send(a.toString());
        send(b.toString());
        return this.v.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").call(this, a, b, c);
    };
    Log.v.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send("Log.v()");
        send(a.toString());
        send(b.toString());
        return this.v.overload("java.lang.String", "java.lang.String").call(this, a, b);
    };
    Log.i.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
        send("Log.i()");
        send(a.toString());
        send(b.toString());
        return this.i.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").call(this, a, b, c);
    };
    Log.i.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send("Log.i()");
        send(a.toString());
        send(b.toString());
        return this.i.overload("java.lang.String", "java.lang.String").call(this, a, b);
    };
    Log.e.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
        send("Log.e()");
        send(a.toString());
        send(b.toString());
        return this.e.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").call(this, a, b, c);
    };
    Log.e.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send("Log.e()");
        send(a.toString());
        send(b.toString());
        return this.e.overload("java.lang.String", "java.lang.String").call(this, a, b);
    };
    Log.w.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
        send("Log.w()");
        send(a.toString());
        send(b.toString());
        return this.w.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").call(this, a, b, c);
    };
    Log.w.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send("Log.w()");
        send(a.toString());
        send(b.toString());
        return this.w.overload("java.lang.String", "java.lang.String").call(this, a, b);
    };
 });
