# The JNI glue calls into these classes by name: shrinking must keep them.
-keep class org.todoke.ffi.** { *; }
