// Created by ridhoae303

#include <jni.h>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <EasyObfuse.h>

static bool gVerified = false;

static bool clearJniException(JNIEnv* env) {
    if (env != nullptr && env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return true;
    }
    return false;
}

static bool isJniBad(JNIEnv* env, const void* value) {
    bool hadException = clearJniException(env);
    return value == nullptr || hadException;
}

static jstring newUtf8String(JNIEnv* env, const char* value) {
    if (env == nullptr || value == nullptr) return nullptr;

    const jsize length = static_cast<jsize>(std::strlen(value));
    jbyteArray bytes = env->NewByteArray(length);
    if (isJniBad(env, bytes)) return nullptr;

    if (length > 0) {
        env->SetByteArrayRegion(
                bytes,
                0,
                length,
                reinterpret_cast<const jbyte*>(value)
        );
        if (clearJniException(env)) {
            env->DeleteLocalRef(bytes);
            return nullptr;
        }
    }

    jclass stringClass = env->FindClass(OBFUSCATE("java/lang/String"));
    if (isJniBad(env, stringClass)) {
        env->DeleteLocalRef(bytes);
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(
            stringClass,
            OBFUSCATE("<init>"),
            OBFUSCATE("([BLjava/lang/String;)V")
    );
    if (isJniBad(env, constructor)) {
        env->DeleteLocalRef(bytes);
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }

    jstring charset = env->NewStringUTF(OBFUSCATE("UTF-8"));
    if (isJniBad(env, charset)) {
        env->DeleteLocalRef(bytes);
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }

    jstring result = static_cast<jstring>(
            env->NewObject(stringClass, constructor, bytes, charset)
    );

    env->DeleteLocalRef(charset);
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(stringClass);

    if (isJniBad(env, result)) return nullptr;
    return result;
}


static std::string jstringToStdString(JNIEnv* env, jstring value) {
    if (env == nullptr || value == nullptr) return "";
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) {
        clearJniException(env);
        return "";
    }
    std::string out(chars);
    env->ReleaseStringUTFChars(value, chars);
    return out;
}

static std::string jsonEscape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16U);
    for (unsigned char c : input) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

static std::string getStaticStringField(JNIEnv* env, const char* className, const char* fieldName) {
    if (env == nullptr || className == nullptr || fieldName == nullptr) return "";
    jclass cls = env->FindClass(className);
    if (isJniBad(env, cls)) return "";
    jfieldID field = env->GetStaticFieldID(cls, fieldName, OBFUSCATE("Ljava/lang/String;"));
    if (isJniBad(env, field)) {
        env->DeleteLocalRef(cls);
        return "";
    }
    jstring value = (jstring) env->GetStaticObjectField(cls, field);
    env->DeleteLocalRef(cls);
    if (isJniBad(env, value)) return "";
    std::string out = jstringToStdString(env, value);
    env->DeleteLocalRef(value);
    return out;
}

static bool postLeechReport(JNIEnv* env, const std::string& packageName, const char* reason) {
    if (env == nullptr || packageName.empty() || reason == nullptr) return false;

    const std::string deviceModel = getStaticStringField(env, OBFUSCATE("android/os/Build"), OBFUSCATE("MODEL"));
    const std::string androidVersion = getStaticStringField(env, OBFUSCATE("android/os/Build$VERSION"), OBFUSCATE("RELEASE"));
    const long long ts = static_cast<long long>(std::time(nullptr));

    std::string body = std::string("{")
            + "\"packageName\":\"" + jsonEscape(packageName) + "\"," 
            + "\"reason\":\"" + jsonEscape(reason) + "\"," 
            + "\"deviceModel\":\"" + jsonEscape(deviceModel) + "\"," 
            + "\"androidVersion\":\"" + jsonEscape(androidVersion) + "\"," 
            + "\"timestamp\":" + std::to_string(ts)
            + "}";

    jclass urlClass = nullptr;
    jmethodID urlCtor = nullptr;
    jmethodID openConnection = nullptr;
    jstring endpoint = nullptr;
    jobject urlObj = nullptr;
    jobject connection = nullptr;
    jclass connClass = nullptr;
    jobject outStream = nullptr;
    jclass outClass = nullptr;
    jbyteArray bodyBytes = nullptr;
    jclass byteArrayClass = nullptr;

    auto cleanup = [&]() {
        if (bodyBytes) env->DeleteLocalRef(bodyBytes);
        if (outClass) env->DeleteLocalRef(outClass);
        if (outStream) env->DeleteLocalRef(outStream);
        if (connClass) env->DeleteLocalRef(connClass);
        if (connection) env->DeleteLocalRef(connection);
        if (urlObj) env->DeleteLocalRef(urlObj);
        if (endpoint) env->DeleteLocalRef(endpoint);
        if (urlClass) env->DeleteLocalRef(urlClass);
        if (byteArrayClass) env->DeleteLocalRef(byteArrayClass);
    };

    endpoint = newUtf8String(env, OBFUSCATE("https://warden-sooty.vercel.app/api/verify"));
    if (isJniBad(env, endpoint)) {
        cleanup();
        return false;
    }

    urlClass = env->FindClass(OBFUSCATE("java/net/URL"));
    if (isJniBad(env, urlClass)) { cleanup(); return false; }

    urlCtor = env->GetMethodID(urlClass, OBFUSCATE("<init>"), OBFUSCATE("(Ljava/lang/String;)V"));
    if (isJniBad(env, urlCtor)) { cleanup(); return false; }

    openConnection = env->GetMethodID(urlClass, OBFUSCATE("openConnection"), OBFUSCATE("()Ljava/net/URLConnection;"));
    if (isJniBad(env, openConnection)) { cleanup(); return false; }

    urlObj = env->NewObject(urlClass, urlCtor, endpoint);
    if (isJniBad(env, urlObj)) { cleanup(); return false; }

    connection = env->CallObjectMethod(urlObj, openConnection);
    if (isJniBad(env, connection)) { cleanup(); return false; }

    connClass = env->GetObjectClass(connection);
    if (isJniBad(env, connClass)) { cleanup(); return false; }

    jmethodID setDoOutput = env->GetMethodID(connClass, OBFUSCATE("setDoOutput"), OBFUSCATE("(Z)V"));
    jmethodID setDoInput = env->GetMethodID(connClass, OBFUSCATE("setDoInput"), OBFUSCATE("(Z)V"));
    jmethodID setUseCaches = env->GetMethodID(connClass, OBFUSCATE("setUseCaches"), OBFUSCATE("(Z)V"));
    jmethodID setConnectTimeout = env->GetMethodID(connClass, OBFUSCATE("setConnectTimeout"), OBFUSCATE("(I)V"));
    jmethodID setReadTimeout = env->GetMethodID(connClass, OBFUSCATE("setReadTimeout"), OBFUSCATE("(I)V"));
    jmethodID setRequestProperty = env->GetMethodID(connClass, OBFUSCATE("setRequestProperty"), OBFUSCATE("(Ljava/lang/String;Ljava/lang/String;)V"));
    jmethodID setRequestMethod = env->GetMethodID(connClass, OBFUSCATE("setRequestMethod"), OBFUSCATE("(Ljava/lang/String;)V"));
    jmethodID getOutputStream = env->GetMethodID(connClass, OBFUSCATE("getOutputStream"), OBFUSCATE("()Ljava/io/OutputStream;"));
    jmethodID getResponseCode = env->GetMethodID(connClass, OBFUSCATE("getResponseCode"), OBFUSCATE("()I"));
    jmethodID disconnect = env->GetMethodID(connClass, OBFUSCATE("disconnect"), OBFUSCATE("()V"));
    if (isJniBad(env, setDoOutput) || isJniBad(env, setDoInput) || isJniBad(env, setUseCaches) ||
        isJniBad(env, setConnectTimeout) || isJniBad(env, setReadTimeout) ||
        isJniBad(env, setRequestProperty) || isJniBad(env, setRequestMethod) ||
        isJniBad(env, getOutputStream) || isJniBad(env, getResponseCode) || isJniBad(env, disconnect)) {
        cleanup();
        return false;
    }

    jstring post = newUtf8String(env, OBFUSCATE("POST"));
    jstring contentTypeName = newUtf8String(env, OBFUSCATE("Content-Type"));
    jstring contentTypeValue = newUtf8String(env, OBFUSCATE("application/json; charset=utf-8"));
    jstring acceptName = newUtf8String(env, OBFUSCATE("Accept"));
    jstring acceptValue = newUtf8String(env, OBFUSCATE("application/json"));
    if (isJniBad(env, post) || isJniBad(env, contentTypeName) || isJniBad(env, contentTypeValue) ||
        isJniBad(env, acceptName) || isJniBad(env, acceptValue)) {
        if (post) env->DeleteLocalRef(post);
        if (contentTypeName) env->DeleteLocalRef(contentTypeName);
        if (contentTypeValue) env->DeleteLocalRef(contentTypeValue);
        if (acceptName) env->DeleteLocalRef(acceptName);
        if (acceptValue) env->DeleteLocalRef(acceptValue);
        cleanup();
        return false;
    }

    env->CallVoidMethod(connection, setDoOutput, JNI_TRUE);
    env->CallVoidMethod(connection, setDoInput, JNI_TRUE);
    env->CallVoidMethod(connection, setUseCaches, JNI_FALSE);
    env->CallVoidMethod(connection, setConnectTimeout, 1200);
    env->CallVoidMethod(connection, setReadTimeout, 1200);
    env->CallVoidMethod(connection, setRequestMethod, post);
    env->CallVoidMethod(connection, setRequestProperty, contentTypeName, contentTypeValue);
    env->CallVoidMethod(connection, setRequestProperty, acceptName, acceptValue);
    env->DeleteLocalRef(post);
    env->DeleteLocalRef(contentTypeName);
    env->DeleteLocalRef(contentTypeValue);
    env->DeleteLocalRef(acceptName);
    env->DeleteLocalRef(acceptValue);
    if (clearJniException(env)) { cleanup(); return false; }

    outStream = env->CallObjectMethod(connection, getOutputStream);
    if (isJniBad(env, outStream)) { cleanup(); return false; }

    outClass = env->GetObjectClass(outStream);
    if (isJniBad(env, outClass)) { cleanup(); return false; }

    jmethodID writeBytes = env->GetMethodID(outClass, OBFUSCATE("write"), OBFUSCATE("([B)V"));
    jmethodID flush = env->GetMethodID(outClass, OBFUSCATE("flush"), OBFUSCATE("()V"));
    jmethodID close = env->GetMethodID(outClass, OBFUSCATE("close"), OBFUSCATE("()V"));
    if (isJniBad(env, writeBytes) || isJniBad(env, flush) || isJniBad(env, close)) {
        cleanup();
        return false;
    }

    bodyBytes = env->NewByteArray(static_cast<jsize>(body.size()));
    if (isJniBad(env, bodyBytes)) { cleanup(); return false; }
    env->SetByteArrayRegion(bodyBytes, 0, static_cast<jsize>(body.size()), reinterpret_cast<const jbyte*>(body.data()));
    if (clearJniException(env)) { cleanup(); return false; }

    env->CallVoidMethod(outStream, writeBytes, bodyBytes);
    if (clearJniException(env)) { cleanup(); return false; }
    env->CallVoidMethod(outStream, flush);
    clearJniException(env);
    env->CallVoidMethod(outStream, close);
    clearJniException(env);

    env->CallIntMethod(connection, getResponseCode);
    clearJniException(env);
    env->CallVoidMethod(connection, disconnect);
    clearJniException(env);

    cleanup();
    return true;
}

static char hexNibble(unsigned int value) {
    return static_cast<char>(value < 10U ? ('0' + value) : ('a' + (value - 10U)));
}

static std::string f(JNIEnv* env, jbyteArray sigBytes) {
    if (env == nullptr || sigBytes == nullptr) return "";

    jclass mdClass = env->FindClass(OBFUSCATE("java/security/MessageDigest"));
    if (isJniBad(env, mdClass)) return "";

    jmethodID getInstance = env->GetStaticMethodID(mdClass, OBFUSCATE("getInstance"), OBFUSCATE("(Ljava/lang/String;)Ljava/security/MessageDigest;"));
    if (isJniBad(env, getInstance)) return "";

    jstring sha256Str = env->NewStringUTF(OBFUSCATE("SHA-256"));
    if (isJniBad(env, sha256Str)) return "";

    jobject md = env->CallStaticObjectMethod(mdClass, getInstance, sha256Str);
    env->DeleteLocalRef(sha256Str);
    if (isJniBad(env, md)) return "";

    jmethodID update = env->GetMethodID(mdClass, OBFUSCATE("update"), OBFUSCATE("([B)V"));
    if (isJniBad(env, update)) return "";

    env->CallVoidMethod(md, update, sigBytes);
    if (clearJniException(env)) return "";

    jmethodID digest = env->GetMethodID(mdClass, OBFUSCATE("digest"), OBFUSCATE("()[B"));
    if (isJniBad(env, digest)) return "";

    jbyteArray hashBytes = (jbyteArray) env->CallObjectMethod(md, digest);
    if (isJniBad(env, hashBytes)) return "";

    jsize hashLen = env->GetArrayLength(hashBytes);
    if (hashLen <= 0 || clearJniException(env)) return "";

    jbyte* hashPtr = env->GetByteArrayElements(hashBytes, nullptr);
    if (isJniBad(env, hashPtr)) return "";

    std::string hex;
    hex.reserve((size_t) hashLen * 2U);
    for (int i = 0; i < hashLen; i++) {
        unsigned char v = (unsigned char) hashPtr[i];
        hex.push_back(hexNibble(v >> 4));
        hex.push_back(hexNibble(v & 0x0f));
    }

    env->ReleaseByteArrayElements(hashBytes, hashPtr, JNI_ABORT);
    return hex;
}

static jobject g(JNIEnv* env, jstring pkgName, jint userId) {
    (void) env;
    (void) pkgName;
    (void) userId;
    return nullptr;
}


static jint getSdkInt(JNIEnv* env) {
    if (env == nullptr) return 0;

    jclass versionClass = env->FindClass(OBFUSCATE("android/os/Build$VERSION"));
    if (isJniBad(env, versionClass)) return 0;

    jfieldID sdkField = env->GetStaticFieldID(versionClass, OBFUSCATE("SDK_INT"), OBFUSCATE("I"));
    if (isJniBad(env, sdkField)) {
        env->DeleteLocalRef(versionClass);
        return 0;
    }

    jint sdk = env->GetStaticIntField(versionClass, sdkField);
    env->DeleteLocalRef(versionClass);
    if (clearJniException(env)) return 0;
    return sdk;
}

static const int kSignatureStateMatch = 1;
static const int kSignatureStateMismatch = 0;
static const int kSignatureStateUnreadable = -1;

static std::string signatureHashFromObject(JNIEnv* env, jobject sigObj) {
    if (env == nullptr || sigObj == nullptr) return "";

    jclass sigClass = env->GetObjectClass(sigObj);
    if (isJniBad(env, sigClass)) return "";

    jmethodID toByteArray = env->GetMethodID(sigClass, OBFUSCATE("toByteArray"), OBFUSCATE("()[B"));
    if (isJniBad(env, toByteArray)) {
        env->DeleteLocalRef(sigClass);
        return "";
    }

    jbyteArray byteArray = (jbyteArray) env->CallObjectMethod(sigObj, toByteArray);
    env->DeleteLocalRef(sigClass);
    if (isJniBad(env, byteArray)) return "";

    std::string hash = f(env, byteArray);
    env->DeleteLocalRef(byteArray);
    return hash;
}

static int signatureArrayState(
        JNIEnv* env,
        jobjectArray sigsArray,
        const char* const* allowedHashes,
        size_t allowedCount,
        bool requireAll
) {
    if (env == nullptr || sigsArray == nullptr || allowedHashes == nullptr || allowedCount == 0) {
        return kSignatureStateUnreadable;
    }

    jsize count = env->GetArrayLength(sigsArray);
    if (count <= 0 || clearJniException(env)) return kSignatureStateUnreadable;

    bool anyMatch = false;
    for (jsize idx = 0; idx < count; ++idx) {
        jobject sigObj = env->GetObjectArrayElement(sigsArray, idx);
        if (isJniBad(env, sigObj)) return kSignatureStateUnreadable;

        std::string hash = signatureHashFromObject(env, sigObj);
        env->DeleteLocalRef(sigObj);
        if (hash.empty()) return kSignatureStateUnreadable;

        bool matched = false;
        for (size_t i = 0; i < allowedCount; ++i) {
            if (hash == allowedHashes[i]) {
                matched = true;
                anyMatch = true;
                break;
            }
        }

        if (requireAll && !matched) return kSignatureStateMismatch;
        if (!requireAll && matched) return kSignatureStateMatch;
    }

    return requireAll ? kSignatureStateMatch : (anyMatch ? kSignatureStateMatch : kSignatureStateMismatch);
}

static int verifyPackageSignature(
        JNIEnv* env,
        jobject pkgInfo,
        const char* const* allowedHashes,
        size_t allowedCount
) {
    if (env == nullptr || pkgInfo == nullptr || allowedHashes == nullptr || allowedCount == 0) {
        return kSignatureStateUnreadable;
    }

    const jint sdk = getSdkInt(env);
    jobjectArray sigsArray = nullptr;
    bool requireAll = false;

    if (sdk >= 28) {
        jclass pkgInfoClass = env->GetObjectClass(pkgInfo);
        if (!isJniBad(env, pkgInfoClass)) {
            jfieldID signingInfoField = env->GetFieldID(
                    pkgInfoClass,
                    OBFUSCATE("signingInfo"),
                    OBFUSCATE("Landroid/content/pm/SigningInfo;")
            );
            if (!isJniBad(env, signingInfoField)) {
                jobject signingInfo = env->GetObjectField(pkgInfo, signingInfoField);
                if (!isJniBad(env, signingInfo)) {
                    jclass signingInfoClass = env->GetObjectClass(signingInfo);
                    if (!isJniBad(env, signingInfoClass)) {
                        jmethodID hasMultipleSigners = env->GetMethodID(
                                signingInfoClass,
                                OBFUSCATE("hasMultipleSigners"),
                                OBFUSCATE("()Z")
                        );
                        if (!isJniBad(env, hasMultipleSigners)) {
                            jboolean multiple = env->CallBooleanMethod(signingInfo, hasMultipleSigners);
                            if (!clearJniException(env)) {
                                const char* methodName = (multiple == JNI_TRUE)
                                        ? OBFUSCATE("getApkContentsSigners")
                                        : OBFUSCATE("getSigningCertificateHistory");

                                jmethodID getSigners = env->GetMethodID(
                                        signingInfoClass,
                                        methodName,
                                        OBFUSCATE("()[Landroid/content/pm/Signature;")
                                );
                                if (!isJniBad(env, getSigners)) {
                                    sigsArray = (jobjectArray) env->CallObjectMethod(signingInfo, getSigners);
                                    if (!clearJniException(env) && sigsArray != nullptr) {
                                        requireAll = false;
                                        int modernState = signatureArrayState(env, sigsArray, allowedHashes, allowedCount, requireAll);
                                        env->DeleteLocalRef(sigsArray);
                                        env->DeleteLocalRef(signingInfoClass);
                                        env->DeleteLocalRef(signingInfo);
                                        env->DeleteLocalRef(pkgInfoClass);
                                        if (modernState != kSignatureStateUnreadable) {
                                            return modernState;
                                        }
                                    } else {
                                        sigsArray = nullptr;
                                    }
                                }
                            }
                        }
                        env->DeleteLocalRef(signingInfoClass);
                    }
                    env->DeleteLocalRef(signingInfo);
                }
            }
            env->DeleteLocalRef(pkgInfoClass);
        }
    }

    if (sigsArray == nullptr) {
        jclass pkgInfoClass = env->GetObjectClass(pkgInfo);
        if (isJniBad(env, pkgInfoClass)) return kSignatureStateUnreadable;

        jfieldID sigsField = env->GetFieldID(
                pkgInfoClass,
                OBFUSCATE("signatures"),
                OBFUSCATE("[Landroid/content/pm/Signature;")
        );
        if (isJniBad(env, sigsField)) {
            env->DeleteLocalRef(pkgInfoClass);
            return kSignatureStateUnreadable;
        }

        sigsArray = (jobjectArray) env->GetObjectField(pkgInfo, sigsField);
        env->DeleteLocalRef(pkgInfoClass);
        if (clearJniException(env) || sigsArray == nullptr) return kSignatureStateUnreadable;

        const jsize count = env->GetArrayLength(sigsArray);
        if (clearJniException(env) || count <= 0) {
            env->DeleteLocalRef(sigsArray);
            return kSignatureStateUnreadable;
        }
        requireAll = false;
        int legacyState = signatureArrayState(env, sigsArray, allowedHashes, allowedCount, requireAll);
        env->DeleteLocalRef(sigsArray);
        return legacyState;
    }

    return kSignatureStateUnreadable;
}

static jobject h(JNIEnv* env, jobject context, jstring pkgName) {
    if (env == nullptr || context == nullptr || pkgName == nullptr) return nullptr;

    jclass ctxClass = env->GetObjectClass(context);
    if (isJniBad(env, ctxClass)) return nullptr;

    jmethodID getPm = env->GetMethodID(ctxClass, OBFUSCATE("getPackageManager"), OBFUSCATE("()Landroid/content/pm/PackageManager;"));
    if (isJniBad(env, getPm)) {
        env->DeleteLocalRef(ctxClass);
        return nullptr;
    }

    jobject pm = env->CallObjectMethod(context, getPm);
    env->DeleteLocalRef(ctxClass);
    if (isJniBad(env, pm)) return nullptr;

    jclass pmClass = env->GetObjectClass(pm);
    if (isJniBad(env, pmClass)) {
        env->DeleteLocalRef(pm);
        return nullptr;
    }

    jmethodID getPkgInfo = env->GetMethodID(pmClass, OBFUSCATE("getPackageInfo"), OBFUSCATE("(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"));
    if (isJniBad(env, getPkgInfo)) {
        env->DeleteLocalRef(pmClass);
        env->DeleteLocalRef(pm);
        return nullptr;
    }

    jint flags = 0x00000040;
    if (getSdkInt(env) >= 28) {
        flags = 0x08000000;
    }

    jobject pkgInfo = env->CallObjectMethod(pm, getPkgInfo, pkgName, flags);
    env->DeleteLocalRef(pmClass);
    env->DeleteLocalRef(pm);
    if (clearJniException(env)) return nullptr;

    return pkgInfo;
}

static void j() {
    void* ptr = mmap(nullptr, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(ptr != MAP_FAILED) {
        memset(ptr, 0, 4096);
        munmap(ptr, 4096);
    }
    volatile int *p = nullptr;
    *p = 0;
    kill(getpid(), SIGKILL);
    _exit(0);
}

static void crashForIntegrityFailure(JNIEnv* env) {
    if (env == nullptr) {
        j();
        return;
    }

    // Give the system Toast service enough time to display the queued message.
    usleep(1400000);

    jclass exceptionClass = env->FindClass(OBFUSCATE("java/lang/SecurityException"));
    if (isJniBad(env, exceptionClass)) {
        j();
        return;
    }

    if (env->ThrowNew(
            exceptionClass,
            OBFUSCATE("Application integrity verification failed")
    ) != JNI_OK) {
        clearJniException(env);
        j();
    }
}

static const char* k() {
    const char* toasts[] = {
        OBFUSCATE("Fuck you Leech! 🍌"),
        OBFUSCATE("Asshole! Leecher detected 🤬"),
        OBFUSCATE("Mod detected, get rekt! 💀"),
        OBFUSCATE("Bastard! Get lost! 🖕"),
        OBFUSCATE("Damn leech! 🐍"),
        OBFUSCATE("Shameless thief! 😡"),
        OBFUSCATE("Pfft, code thief! 🖕🤡"),
        OBFUSCATE("Die, stinky leecher! 💩")
    };
    int idx = rand() % (sizeof(toasts)/sizeof(toasts[0]));
    return toasts[idx];
}

static void l(JNIEnv* env, jobject context, const char* msg) {
    (void) context;
    if (env == nullptr || msg == nullptr) return;

    jclass cls = env->FindClass(OBFUSCATE("com/ridhoae303/expert/Takane"));
    if (isJniBad(env, cls)) return;

    jmethodID toastMethod = env->GetStaticMethodID(cls, OBFUSCATE("c"), OBFUSCATE("(Ljava/lang/String;)V"));
    if (isJniBad(env, toastMethod)) return;

    jstring jmsg = newUtf8String(env, msg);
    if (isJniBad(env, jmsg)) return;

    env->CallStaticVoidMethod(cls, toastMethod, jmsg);
    env->DeleteLocalRef(jmsg);
    clearJniException(env);
}


static int m(JNIEnv* env, jobject context) {
    if (env == nullptr || context == nullptr) return kSignatureStateUnreadable;

    jclass ctxClass = env->GetObjectClass(context);
    if (isJniBad(env, ctxClass)) return kSignatureStateUnreadable;

    jmethodID getPkgName = env->GetMethodID(ctxClass, OBFUSCATE("getPackageName"), OBFUSCATE("()Ljava/lang/String;"));
    if (isJniBad(env, getPkgName)) {
        env->DeleteLocalRef(ctxClass);
        return kSignatureStateUnreadable;
    }

    jstring pkgName = (jstring) env->CallObjectMethod(context, getPkgName);
    env->DeleteLocalRef(ctxClass);
    if (isJniBad(env, pkgName)) return kSignatureStateUnreadable;

    jclass ctxClass2 = env->GetObjectClass(context);
    if (isJniBad(env, ctxClass2)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jmethodID getSharedPrefs = env->GetMethodID(ctxClass2, OBFUSCATE("getSharedPreferences"), OBFUSCATE("(Ljava/lang/String;I)Landroid/content/SharedPreferences;"));
    env->DeleteLocalRef(ctxClass2);
    if (isJniBad(env, getSharedPrefs)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jstring prefsName = env->NewStringUTF(OBFUSCATE("x9j3kf"));
    if (isJniBad(env, prefsName)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jobject prefs = env->CallObjectMethod(context, getSharedPrefs, prefsName, 0);
    env->DeleteLocalRef(prefsName);
    if (isJniBad(env, prefs)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jclass spClass = env->GetObjectClass(prefs);
    if (isJniBad(env, spClass)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jmethodID getBool = env->GetMethodID(spClass, OBFUSCATE("getBoolean"), OBFUSCATE("(Ljava/lang/String;Z)Z"));
    if (isJniBad(env, getBool)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jstring keyLeech = env->NewStringUTF(OBFUSCATE("ld"));
    if (isJniBad(env, keyLeech)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    jboolean isLeech = env->CallBooleanMethod(prefs, getBool, keyLeech, JNI_FALSE);
    env->DeleteLocalRef(keyLeech);
    if (clearJniException(env)) {
        env->DeleteLocalRef(pkgName);
        return kSignatureStateUnreadable;
    }

    if (isLeech) {
        env->DeleteLocalRef(pkgName);
        crashForIntegrityFailure(env);
        return kSignatureStateMismatch;
    }

    jobject pkgInfoPM = h(env, context, pkgName);
    env->DeleteLocalRef(pkgName);
    if (pkgInfoPM == nullptr) {
        return kSignatureStateUnreadable;
    }

    const char* allowedHashes[] = {
        OBFUSCATE("e4201e2e32724c1ba1ef1100d35ff9f75c5d3e888a58c68b7747808f4c87607b"),
        OBFUSCATE("1e880257852a0a8502d6234797b27f487773a30531a3c132c9e88415ea13da83"),
        OBFUSCATE("a3a97be7f77af2ab1c2226d7aeb6767e840dfb8a4fd53f6fda712e5d6bcbe224"),
        OBFUSCATE("466f3058649060cf07820b4d2b7ef1a0b05b0320fbb980128631f1b4f08f33dd")
    };

    int sigState = verifyPackageSignature(env, pkgInfoPM, allowedHashes, 4);
    env->DeleteLocalRef(pkgInfoPM);
    if (clearJniException(env)) return kSignatureStateUnreadable;

    if (sigState == kSignatureStateMatch) {
        l(env, context, OBFUSCATE("modded by ridhoae303 👻"));
        usleep(600000);
        l(env, context, OBFUSCATE("miyoshi takane best girl 💕"));
        return kSignatureStateMatch;
    }

    if (sigState == kSignatureStateUnreadable) {
        return kSignatureStateUnreadable;
    }

    jclass spEditorClass = env->FindClass(OBFUSCATE("android/content/SharedPreferences$Editor"));
    if (!isJniBad(env, spEditorClass)) {
        jmethodID edit = env->GetMethodID(spClass, OBFUSCATE("edit"), OBFUSCATE("()Landroid/content/SharedPreferences$Editor;"));
        if (!isJniBad(env, edit)) {
            jobject editor = env->CallObjectMethod(prefs, edit);
            if (!isJniBad(env, editor)) {
                jmethodID putBool = env->GetMethodID(spEditorClass, OBFUSCATE("putBoolean"), OBFUSCATE("(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;"));
                if (!isJniBad(env, putBool)) {
                    jstring key2 = env->NewStringUTF(OBFUSCATE("ld"));
                    if (!isJniBad(env, key2)) {
                        env->CallObjectMethod(editor, putBool, key2, JNI_TRUE);
                        env->DeleteLocalRef(key2);
                        clearJniException(env);
                    }
                }

                jmethodID apply = env->GetMethodID(spEditorClass, OBFUSCATE("apply"), OBFUSCATE("()V"));
                if (!isJniBad(env, apply)) {
                    env->CallVoidMethod(editor, apply);
                    clearJniException(env);
                }
            }
        }
    } else {
        clearJniException(env);
    }

    postLeechReport(env, packageName, OBFUSCATE("SIGNATURE_MISMATCH"));
    l(env, context, k());
    crashForIntegrityFailure(env);
    return kSignatureStateMismatch;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_ridhoae303_expert_Takane_b(JNIEnv* env, jclass, jobject context) {
    if (env == nullptr || context == nullptr) return JNI_FALSE;

    jclass cls = env->FindClass(OBFUSCATE("com/ridhoae303/expert/Takane"));
    if (isJniBad(env, cls)) {
        return JNI_FALSE;
    }

    jmethodID setCtx = env->GetStaticMethodID(cls, OBFUSCATE("e"), OBFUSCATE("(Landroid/content/Context;)V"));
    if (isJniBad(env, setCtx)) {
        return JNI_FALSE;
    }

    env->CallStaticVoidMethod(cls, setCtx, context);
    if (clearJniException(env)) {
        return JNI_FALSE;
    }

    if (gVerified) return JNI_TRUE;

    const int sigState = m(env, context);
    if (sigState == kSignatureStateMatch) {
        gVerified = true;
        return JNI_TRUE;
    }
    if (sigState == kSignatureStateUnreadable) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
    (void) vm;
    return JNI_VERSION_1_6;
}