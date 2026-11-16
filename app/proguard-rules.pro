# OkHttp (HTTP/2 media through the Cloudflare proxy). Its jar ships these rules too
# (META-INF/proguard/okhttp3.pro); they are repeated so the build does not depend on that.
-dontwarn javax.annotation.**
-dontwarn org.codehaus.mojo.animal_sniffer.*
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# Exception class names appear in log lines ("request failed: StreamResetException: ...").
-keepnames class okhttp3.** extends java.lang.Throwable
-keepnames class org.flowseal.tgwsproxy.proxy.** extends java.lang.Throwable
