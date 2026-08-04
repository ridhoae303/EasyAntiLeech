// Created by ridhoae303

#include <jni.h>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <cstring>
#include <EasyObfuse.h>

static bool gVerified = false;

static char hexNibble(unsigned int value);
static jint getSdkInt(JNIEnv* env);
static std::string signatureHashFromObject(JNIEnv* env, jobject sigObj);

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

    const char* utf = env->GetStringUTFChars(value, nullptr);
    if (utf == nullptr || clearJniException(env)) {
        return "";
    }

    std::string out(utf);
    env->ReleaseStringUTFChars(value, utf);
    return out;
}

static std::string jsonEscape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20U) {
                    static const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0x0F]);
                    out.push_back(hex[c & 0x0F]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

static long long currentTimeMillis() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static std::string randomHexBytes(size_t byteCount) {
    std::string out;
    out.reserve(byteCount * 2U);
    for (size_t i = 0; i < byteCount; ++i) {
        const unsigned int v = static_cast<unsigned int>(std::rand() & 0xFF);
        out.push_back(hexNibble((v >> 4) & 0x0FU));
        out.push_back(hexNibble(v & 0x0FU));
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

static std::string getAndroidModel(JNIEnv* env) {
    return getStaticStringField(env, "android/os/Build", "MODEL");
}

static std::string getAndroidVersion(JNIEnv* env) {
    std::string release = getStaticStringField(env, "android/os/Build$VERSION", "RELEASE");
    if (!release.empty()) return release;

    jclass versionClass = env->FindClass(OBFUSCATE("android/os/Build$VERSION"));
    if (isJniBad(env, versionClass)) return "";

    jfieldID sdkField = env->GetStaticFieldID(versionClass, OBFUSCATE("SDK_INT"), OBFUSCATE("I"));
    if (isJniBad(env, sdkField)) {
        env->DeleteLocalRef(versionClass);
        return "";
    }

    jint sdk = env->GetStaticIntField(versionClass, sdkField);
    env->DeleteLocalRef(versionClass);
    if (clearJniException(env)) return "";

    return std::to_string((int) sdk);
}

static jbyteArray makeByteArray(JNIEnv* env, const std::string& value) {
    if (env == nullptr) return nullptr;

    const jsize len = static_cast<jsize>(value.size());
    jbyteArray arr = env->NewByteArray(len);
    if (isJniBad(env, arr)) return nullptr;

    if (len > 0) {
        env->SetByteArrayRegion(arr, 0, len, reinterpret_cast<const jbyte*>(value.data()));
        if (clearJniException(env)) {
            env->DeleteLocalRef(arr);
            return nullptr;
        }
    }
    return arr;
}

static bool httpsPostJson(JNIEnv* env, const std::string& endpoint, const std::string& body) {
    if (env == nullptr || endpoint.empty()) return false;

    jclass urlClass = env->FindClass(OBFUSCATE("java/net/URL"));
    if (isJniBad(env, urlClass)) return false;

    jmethodID urlCtor = env->GetMethodID(urlClass, OBFUSCATE("<init>"), OBFUSCATE("(Ljava/lang/String;)V"));
    if (isJniBad(env, urlCtor)) {
        env->DeleteLocalRef(urlClass);
        return false;
    }

    jstring urlStr = newUtf8String(env, endpoint.c_str());
    if (isJniBad(env, urlStr)) {
        env->DeleteLocalRef(urlClass);
        return false;
    }

    jobject urlObj = env->NewObject(urlClass, urlCtor, urlStr);
    env->DeleteLocalRef(urlStr);
    if (isJniBad(env, urlObj)) {
        env->DeleteLocalRef(urlClass);
        return false;
    }

    jmethodID openConnection = env->GetMethodID(urlClass, OBFUSCATE("openConnection"), OBFUSCATE("()Ljava/net/URLConnection;"));
    if (isJniBad(env, openConnection)) {
        env->DeleteLocalRef(urlObj);
        env->DeleteLocalRef(urlClass);
        return false;
    }

    jobject connObj = env->CallObjectMethod(urlObj, openConnection);
    env->DeleteLocalRef(urlObj);
    env->DeleteLocalRef(urlClass);
    if (isJniBad(env, connObj)) return false;

    jclass httpClass = env->FindClass(OBFUSCATE("java/net/HttpURLConnection"));
    if (isJniBad(env, httpClass)) {
        env->DeleteLocalRef(connObj);
        return false;
    }

    jmethodID setConnectTimeout = env->GetMethodID(httpClass, OBFUSCATE("setConnectTimeout"), OBFUSCATE("(I)V"));
    jmethodID setReadTimeout = env->GetMethodID(httpClass, OBFUSCATE("setReadTimeout"), OBFUSCATE("(I)V"));
    jmethodID setUseCaches = env->GetMethodID(httpClass, OBFUSCATE("setUseCaches"), OBFUSCATE("(Z)V"));
    jmethodID setDoOutput = env->GetMethodID(httpClass, OBFUSCATE("setDoOutput"), OBFUSCATE("(Z)V"));
    jmethodID setRequestMethod = env->GetMethodID(httpClass, OBFUSCATE("setRequestMethod"), OBFUSCATE("(Ljava/lang/String;)V"));
    jmethodID setRequestProperty = env->GetMethodID(httpClass, OBFUSCATE("setRequestProperty"), OBFUSCATE("(Ljava/lang/String;Ljava/lang/String;)V"));
    jmethodID getOutputStream = env->GetMethodID(httpClass, OBFUSCATE("getOutputStream"), OBFUSCATE("()Ljava/io/OutputStream;"));
    jmethodID getResponseCode = env->GetMethodID(httpClass, OBFUSCATE("getResponseCode"), OBFUSCATE("()I"));
    jmethodID disconnect = env->GetMethodID(httpClass, OBFUSCATE("disconnect"), OBFUSCATE("()V"));

    if (isJniBad(env, setConnectTimeout) || isJniBad(env, setReadTimeout) || isJniBad(env, setUseCaches) ||
        isJniBad(env, setDoOutput) || isJniBad(env, setRequestMethod) || isJniBad(env, setRequestProperty) ||
        isJniBad(env, getOutputStream) || isJniBad(env, getResponseCode) || isJniBad(env, disconnect)) {
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    env->CallVoidMethod(connObj, setConnectTimeout, 1200);
    env->CallVoidMethod(connObj, setReadTimeout, 1200);
    env->CallVoidMethod(connObj, setUseCaches, JNI_FALSE);
    env->CallVoidMethod(connObj, setDoOutput, JNI_TRUE);

    jstring methodPost = env->NewStringUTF(OBFUSCATE("POST"));
    jstring headerCt = env->NewStringUTF(OBFUSCATE("Content-Type"));
    jstring headerAccept = env->NewStringUTF(OBFUSCATE("Accept"));
    jstring headerCache = env->NewStringUTF(OBFUSCATE("Cache-Control"));
    jstring valueJson = env->NewStringUTF(OBFUSCATE("application/json; charset=utf-8"));
    jstring valueJson2 = env->NewStringUTF(OBFUSCATE("application/json"));
    jstring valueNoCache = env->NewStringUTF(OBFUSCATE("no-cache"));

    if (isJniBad(env, methodPost) || isJniBad(env, headerCt) || isJniBad(env, headerAccept) ||
        isJniBad(env, headerCache) || isJniBad(env, valueJson) || isJniBad(env, valueJson2) || isJniBad(env, valueNoCache)) {
        if (methodPost) env->DeleteLocalRef(methodPost);
        if (headerCt) env->DeleteLocalRef(headerCt);
        if (headerAccept) env->DeleteLocalRef(headerAccept);
        if (headerCache) env->DeleteLocalRef(headerCache);
        if (valueJson) env->DeleteLocalRef(valueJson);
        if (valueJson2) env->DeleteLocalRef(valueJson2);
        if (valueNoCache) env->DeleteLocalRef(valueNoCache);
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    env->CallVoidMethod(connObj, setRequestMethod, methodPost);
    env->CallVoidMethod(connObj, setRequestProperty, headerCt, valueJson);
    env->CallVoidMethod(connObj, setRequestProperty, headerAccept, valueJson2);
    env->CallVoidMethod(connObj, setRequestProperty, headerCache, valueNoCache);

    env->DeleteLocalRef(methodPost);
    env->DeleteLocalRef(headerCt);
    env->DeleteLocalRef(headerAccept);
    env->DeleteLocalRef(headerCache);
    env->DeleteLocalRef(valueJson);
    env->DeleteLocalRef(valueJson2);
    env->DeleteLocalRef(valueNoCache);

    if (clearJniException(env)) {
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    jobject outStream = env->CallObjectMethod(connObj, getOutputStream);
    if (isJniBad(env, outStream)) {
        env->CallVoidMethod(connObj, disconnect);
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    jbyteArray bodyBytes = makeByteArray(env, body);
    if (isJniBad(env, bodyBytes)) {
        env->DeleteLocalRef(outStream);
        env->CallVoidMethod(connObj, disconnect);
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    jclass osClass = env->FindClass(OBFUSCATE("java/io/OutputStream"));
    if (isJniBad(env, osClass)) {
        env->DeleteLocalRef(bodyBytes);
        env->DeleteLocalRef(outStream);
        env->CallVoidMethod(connObj, disconnect);
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    jmethodID writeBytes = env->GetMethodID(osClass, OBFUSCATE("write"), OBFUSCATE("([B)V"));
    jmethodID flush = env->GetMethodID(osClass, OBFUSCATE("flush"), OBFUSCATE("()V"));
    jmethodID close = env->GetMethodID(osClass, OBFUSCATE("close"), OBFUSCATE("()V"));
    if (isJniBad(env, writeBytes) || isJniBad(env, flush) || isJniBad(env, close)) {
        env->DeleteLocalRef(osClass);
        env->DeleteLocalRef(bodyBytes);
        env->DeleteLocalRef(outStream);
        env->CallVoidMethod(connObj, disconnect);
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    env->CallVoidMethod(outStream, writeBytes, bodyBytes);
    env->CallVoidMethod(outStream, flush);
    env->CallVoidMethod(outStream, close);

    env->DeleteLocalRef(osClass);
    env->DeleteLocalRef(bodyBytes);
    env->DeleteLocalRef(outStream);

    if (clearJniException(env)) {
        env->CallVoidMethod(connObj, disconnect);
        env->DeleteLocalRef(httpClass);
        env->DeleteLocalRef(connObj);
        return false;
    }

    (void) env->CallIntMethod(connObj, getResponseCode);
    clearJniException(env);

    env->CallVoidMethod(connObj, disconnect);
    env->DeleteLocalRef(httpClass);
    env->DeleteLocalRef(connObj);
    clearJniException(env);
    return true;
}

static std::string extractPrimarySignatureHash(JNIEnv* env, jobject pkgInfo) {
    if (env == nullptr || pkgInfo == nullptr) return "";

    jobjectArray sigsArray = nullptr;
    const jint sdk = getSdkInt(env);
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
                                    if (clearJniException(env)) sigsArray = nullptr;
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
        if (isJniBad(env, pkgInfoClass)) return "";

        jfieldID sigsField = env->GetFieldID(
                pkgInfoClass,
                OBFUSCATE("signatures"),
                OBFUSCATE("[Landroid/content/pm/Signature;")
        );
        if (isJniBad(env, sigsField)) {
            env->DeleteLocalRef(pkgInfoClass);
            return "";
        }

        sigsArray = (jobjectArray) env->GetObjectField(pkgInfo, sigsField);
        env->DeleteLocalRef(pkgInfoClass);
        if (clearJniException(env) || sigsArray == nullptr) return "";
    }

    jsize count = env->GetArrayLength(sigsArray);
    if (count <= 0 || clearJniException(env)) {
        env->DeleteLocalRef(sigsArray);
        return "";
    }

    jobject sigObj = env->GetObjectArrayElement(sigsArray, 0);
    if (isJniBad(env, sigObj)) {
        env->DeleteLocalRef(sigsArray);
        return "";
    }

    std::string hash = signatureHashFromObject(env, sigObj);
    env->DeleteLocalRef(sigObj);
    env->DeleteLocalRef(sigsArray);
    return hash;
}

static bool postLeechReport(
        JNIEnv* env,
        jobject pkgInfo,
        const std::string& packageName,
        const char* reason
) {
    if (env == nullptr || reason == nullptr || packageName.empty()) return false;

    std::string signatureHash = extractPrimarySignatureHash(env, pkgInfo);
    std::string androidVersion = getAndroidVersion(env);
    std::string deviceModel = getAndroidModel(env);
    long long now = currentTimeMillis();
    std::string nonce = randomHexBytes(32U);

    std::ostringstream oss;
    oss << "{"
        << "\"packageName\":\"" << jsonEscape(packageName) << "\","
        << "\"sha256Signature\":\"" << jsonEscape(signatureHash) << "\","
        << "\"androidVersion\":\"" << jsonEscape(androidVersion) << "\","
        << "\"deviceModel\":\"" << jsonEscape(deviceModel) << "\","
        << "\"reason\":\"" << jsonEscape(reason) << "\","
        << "\"timestamp\":" << now << ","
        << "\"nonce\":\"" << nonce << "\""
        << "}";

    return httpsPostJson(env, OBFUSCATE("https://warden-sooty.vercel.app/api/verify"), oss.str());
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

static bool signatureArrayAllowed(
        JNIEnv* env,
        jobjectArray sigsArray,
        const char* const* allowedHashes,
        size_t allowedCount,
        bool requireAll
) {
    if (env == nullptr || sigsArray == nullptr || allowedHashes == nullptr || allowedCount == 0) {
        return false;
    }

    jsize count = env->GetArrayLength(sigsArray);
    if (count <= 0 || clearJniException(env)) return false;

    bool anyMatch = false;
    for (jsize idx = 0; idx < count; ++idx) {
        jobject sigObj = env->GetObjectArrayElement(sigsArray, idx);
        if (isJniBad(env, sigObj)) return false;

        std::string hash = signatureHashFromObject(env, sigObj);
        env->DeleteLocalRef(sigObj);
        if (hash.empty()) return false;

        bool matched = false;
        for (size_t i = 0; i < allowedCount; ++i) {
            if (hash == allowedHashes[i]) {
                matched = true;
                anyMatch = true;
                break;
            }
        }

        if (requireAll && !matched) return false;
        if (!requireAll && matched) return true;
    }

    return requireAll ? true : anyMatch;
}

static bool verifyPackageSignature(
        JNIEnv* env,
        jobject pkgInfo,
        const char* const* allowedHashes,
        size_t allowedCount
) {
    if (env == nullptr || pkgInfo == nullptr || allowedHashes == nullptr || allowedCount == 0) {
        return false;
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
                                        requireAll = (multiple == JNI_TRUE);
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
        if (isJniBad(env, pkgInfoClass)) return false;

        jfieldID sigsField = env->GetFieldID(
                pkgInfoClass,
                OBFUSCATE("signatures"),
                OBFUSCATE("[Landroid/content/pm/Signature;")
        );
        if (isJniBad(env, sigsField)) {
            env->DeleteLocalRef(pkgInfoClass);
            return false;
        }

        sigsArray = (jobjectArray) env->GetObjectField(pkgInfo, sigsField);
        env->DeleteLocalRef(pkgInfoClass);
        if (clearJniException(env) || sigsArray == nullptr) return false;

        const jsize count = env->GetArrayLength(sigsArray);
        if (clearJniException(env) || count <= 0) return false;
        requireAll = (count > 1);
    }

    return signatureArrayAllowed(env, sigsArray, allowedHashes, allowedCount, requireAll);
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


static bool m(JNIEnv* env, jobject context) {
    if (env == nullptr || context == nullptr) return false;

    jclass ctxClass = env->GetObjectClass(context);
    if (isJniBad(env, ctxClass)) return false;

    jmethodID getPkgName = env->GetMethodID(ctxClass, OBFUSCATE("getPackageName"), OBFUSCATE("()Ljava/lang/String;"));
    if (isJniBad(env, getPkgName)) {
        env->DeleteLocalRef(ctxClass);
        return false;
    }

    jstring pkgName = (jstring) env->CallObjectMethod(context, getPkgName);
    env->DeleteLocalRef(ctxClass);
    if (isJniBad(env, pkgName)) return false;

    jclass ctxClass2 = env->GetObjectClass(context);
    if (isJniBad(env, ctxClass2)) return false;

    jmethodID getSharedPrefs = env->GetMethodID(ctxClass2, OBFUSCATE("getSharedPreferences"), OBFUSCATE("(Ljava/lang/String;I)Landroid/content/SharedPreferences;"));
    env->DeleteLocalRef(ctxClass2);
    if (isJniBad(env, getSharedPrefs)) return false;

    jstring prefsName = env->NewStringUTF(OBFUSCATE("x9j3kf"));
    if (isJniBad(env, prefsName)) return false;

    jobject prefs = env->CallObjectMethod(context, getSharedPrefs, prefsName, 0);
    env->DeleteLocalRef(prefsName);
    if (isJniBad(env, prefs)) return false;

    jclass spClass = env->GetObjectClass(prefs);
    if (isJniBad(env, spClass)) return false;

    jmethodID getBool = env->GetMethodID(spClass, OBFUSCATE("getBoolean"), OBFUSCATE("(Ljava/lang/String;Z)Z"));
    if (isJniBad(env, getBool)) return false;

    jstring keyLeech = env->NewStringUTF(OBFUSCATE("ld"));
    if (isJniBad(env, keyLeech)) return false;

    jboolean isLeech = env->CallBooleanMethod(prefs, getBool, keyLeech, JNI_FALSE);
    env->DeleteLocalRef(keyLeech);
    if (clearJniException(env)) return false;

    if (isLeech) {
        crashForIntegrityFailure(env);
        return false;
    }

    jobject pkgInfoPM = h(env, context, pkgName);
    env->DeleteLocalRef(pkgName);
    if (pkgInfoPM == nullptr) {
        return false;
    }

    const char* allowedHashes[] = {
        OBFUSCATE("e4201e2e32724c1ba1ef1100d35ff9f75c5d3e888a58c68b7747808f4c87607b"),
        OBFUSCATE("1e880257852a0a8502d6234797b27f487773a30531a3c132c9e88415ea13da83"),
        OBFUSCATE("a3a97be7f77af2ab1c2226d7aeb6767e840dfb8a4fd53f6fda712e5d6bcbe224"),
        OBFUSCATE("466f3058649060cf07820b4d2b7ef1a0b05b0320fbb980128631f1b4f08f33dd")
    };

    bool valid = verifyPackageSignature(env, pkgInfoPM, allowedHashes, 4);
    env->DeleteLocalRef(pkgInfoPM);
    if (clearJniException(env)) return false;

    if (valid) {
        l(env, context, OBFUSCATE("modded by ridhoae303 👻"));
        usleep(600000);
        l(env, context, OBFUSCATE("miyoshi takane best girl 💕"));
        return true;
    }

    (void) postLeechReport(env, pkgInfoPM, jstringToStdString(env, pkgName), OBFUSCATE("SIGNATURE_MISMATCH"));

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

    l(env, context, k());
    crashForIntegrityFailure(env);
    return false;
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

    const bool verified = m(env, context);
    if (verified) {
        gVerified = true;
    }

    return verified ? JNI_TRUE : JNI_FALSE;
}

extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
    (void) vm;
    return JNI_VERSION_1_6;
}
