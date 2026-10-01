# JNA and the generated UniFFI bindings are reached through reflection and JNI.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keep class uniffi.easydoge_km_ffi.** { *; }
-dontwarn java.awt.**
