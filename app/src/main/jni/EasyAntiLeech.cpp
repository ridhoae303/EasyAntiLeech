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

static jobject h(JNIEnv* env, jobject context, jstring pkgName) {
    if (env == nullptr || context == nullptr || pkgName == nullptr) return nullptr;

    jclass ctxClass = env->GetObjectClass(context);
    if (isJniBad(env, ctxClass)) return nullptr;

    jmethodID getPm = env->GetMethodID(ctxClass, OBFUSCATE("getPackageManager"), OBFUSCATE("()Landroid/content/pm/PackageManager;"));
    if (isJniBad(env, getPm)) return nullptr;

    jobject pm = env->CallObjectMethod(context, getPm);
    if (isJniBad(env, pm)) return nullptr;

    jclass pmClass = env->GetObjectClass(pm);
    if (isJniBad(env, pmClass)) {
        env->DeleteLocalRef(pm);
        return nullptr;
    }

    jmethodID getPkgInfo = env->GetMethodID(pmClass, OBFUSCATE("getPackageInfo"), OBFUSCATE("(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"));
    if (isJniBad(env, getPkgInfo)) {
        env->DeleteLocalRef(pm);
        return nullptr;
    }

    jint flags = 0x00000040;
    jobject pkgInfo = env->CallObjectMethod(pm, getPkgInfo, pkgName, flags);
    env->DeleteLocalRef(pm);
    if (clearJniException(env)) return nullptr;

    return pkgInfo;
}

static std::string i(JNIEnv* env, jobject pkgInfo) {
    if (env == nullptr || pkgInfo == nullptr) return "";

    jclass pkgInfoClass = env->GetObjectClass(pkgInfo);
    if (isJniBad(env, pkgInfoClass)) return "";

    jfieldID sigsField = env->GetFieldID(pkgInfoClass, OBFUSCATE("signatures"), OBFUSCATE("[Landroid/content/pm/Signature;"));
    if (isJniBad(env, sigsField)) return "";

    jobjectArray sigsArray = (jobjectArray) env->GetObjectField(pkgInfo, sigsField);
    if (isJniBad(env, sigsArray)) return "";

    if (env->GetArrayLength(sigsArray) == 0 || clearJniException(env)) return "";

    jobject firstSig = env->GetObjectArrayElement(sigsArray, 0);
    if (isJniBad(env, firstSig)) return "";

    jclass sigClass = env->GetObjectClass(firstSig);
    if (isJniBad(env, sigClass)) return "";

    jmethodID toByteArray = env->GetMethodID(sigClass, OBFUSCATE("toByteArray"), OBFUSCATE("()[B"));
    if (isJniBad(env, toByteArray)) return "";

    jbyteArray byteArray = (jbyteArray) env->CallObjectMethod(firstSig, toByteArray);
    if (isJniBad(env, byteArray)) return "";

    std::string hash = f(env, byteArray);
    env->DeleteLocalRef(byteArray);
    return hash;
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
    if (isJniBad(env, getPkgName)) return false;

    jstring pkgName = (jstring) env->CallObjectMethod(context, getPkgName);
    if (isJniBad(env, pkgName)) return false;

    jmethodID getSharedPrefs = env->GetMethodID(ctxClass, OBFUSCATE("getSharedPreferences"), OBFUSCATE("(Ljava/lang/String;I)Landroid/content/SharedPreferences;"));
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

    /*
     * FIX: If the "ld" flag is already set (meaning we detected a leech before),
     * we do NOT show the random insult toast again. We just crash immediately.
     * This ensures the insult toast appears only on the very first detection.
     */
    if (isLeech) {
        crashForIntegrityFailure(env);
        return false;
    }

    jobject pkgInfoPM = h(env, context, pkgName);
    std::string pmHash;
    bool pmSuccess = false;

    if (pkgInfoPM != nullptr) {
        pmHash = i(env, pkgInfoPM);
        if (!pmHash.empty() && !clearJniException(env)) {
            pmSuccess = true;
        }
    }

    if (clearJniException(env)) return false;
    if (!pmSuccess) return false;

    std::string finalHash = pmHash;

    const char* allowedHashes[] = {
        OBFUSCATE("e4201e2e32724c1ba1ef1100d35ff9f75c5d3e888a58c68b7747808f4c87607b"),
        OBFUSCATE("1e880257852a0a8502d6234797b27f487773a30531a3c132c9e88415ea13da83"),
        OBFUSCATE("a3a97be7f77af2ab1c2226d7aeb6767e840dfb8a4fd53f6fda712e5d6bcbe224"),
        OBFUSCATE("466f3058649060cf07820b4d2b7ef1a0b05b0320fbb980128631f1b4f08f33dd")
    };
    bool valid = false;
    for (int n=0; n<4; n++) {
        if (finalHash == allowedHashes[n]) {
            valid = true;
            break;
        }
    }

    if (valid) {
        l(env, context, OBFUSCATE("modded by ridhoae303 👻"));
        usleep(600000);
        l(env, context, OBFUSCATE("miyoshi takane best girl 💕"));
        return true;
    }

    // Invalid signature: mark as leech, show the random insult toast (once), and crash.
    // The "ld" flag will cause subsequent launches to skip the toast (see above).
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

    // Show the random insult toast – this is the first and only time it appears.
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
    gVerified = true;

    return m(env, context) ? JNI_TRUE : JNI_FALSE;
}

extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
    (void) vm;
    return JNI_VERSION_1_6;
}