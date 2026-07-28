<p align="center">
  <img src="./banner/eal-banner.jpg" alt="EasyAntiLeech banner" width="100%">
</p>

<h1 align="center">EAL — EasyAntiLeech</h1>

<p align="center">
  A lightweight Android/JNI signature checker built to catch lazy repacks and fake ownership.
</p>

<p align="center">
  <a href="https://github.com/ridhoae303/EasyAntiLeech">
    <img src="https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Repository">
  </a>
  <a href="https://github.com/ridhoae303/WelcomeDialog-for-modders">
    <img src="https://img.shields.io/badge/WelcomeDialog-Modders-7B61FF?style=for-the-badge&logo=android&logoColor=white" alt="WelcomeDialog for Modders">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/License-EAL%20Community%201.0-2EA44F?style=for-the-badge" alt="EAL Community License 1.0">
  </a>
</p>

---

## About

EasyAntiLeech is a small native integrity layer for Android mods.

It checks the app's signing certificate before the mod is allowed to continue. When the signature matches one of the approved creator fingerprints, the app keeps running normally. When it does not, EAL marks the build as a repack, shows a one-time anti-leech message, and stops the app.

No huge dashboard. No buzzword soup. Just a native signature check with a bit of attitude.

## Features

- Reads the current Android package signature through JNI.
- Hashes the signing certificate with SHA-256.
- Compares the result against a local allowlist of trusted fingerprints.
- Supports multiple approved creator signatures.
- Obfuscates sensitive strings with `EasyObfuse`.
- Clears and handles JNI exceptions before they pile up.
- Displays creator confirmation messages after a successful check.
- Stores a local detection flag after an invalid signature is found.
- Shows the random anti-leech message only on the first detection.
- Stops the app after verification fails.
- Avoids repeating the full verification more than once per process.

## How It Works

```text
App starts
   ↓
Native JNI verification runs
   ↓
The signing certificate is hashed with SHA-256
   ↓
Does the fingerprint match the allowlist?
   ├─ Yes → continue normally
   └─ No  → save detection flag → show message once → terminate
```

The approved SHA-256 fingerprints are stored in `allowedHashes` inside `EasyAntiLeech.cpp`.

```cpp
const char* allowedHashes[] = {
    OBFUSCATE("your_sha256_fingerprint_here")
};
```

Replace the sample or existing values with fingerprints from builds you actually trust.

## Requirements

- Android NDK
- JNI
- C++11 or newer
- `EasyObfuse.h`
- A Java or Kotlin bridge class matching the JNI names
- CMake, ndk-build, or another compatible native build setup

## JNI Bridge

The current native entry point expects this Java/Kotlin class path:

```text
com.ridhoae303.expert.Takane
```

EAL calls the following methods from that class:

```text
b(Context)  → native verification entry point
e(Context)  → stores the application context
c(String)   → displays a Toast/message
```

The exported native function is:

```cpp
Java_com_ridhoae303_expert_Takane_b
```

## Calling EAL

Declare the native method inside `com.ridhoae303.expert.Takane`:

```java
public static native boolean b(Context ctx);
```

Make sure the native library has already been loaded, then call EAL from an `Activity`, `Service`, `Application`, or any other place where you have a valid Android `Context`:

```java
Takane.b(this);
```

You can also keep the return value when you need it:

```java
boolean verified = Takane.b(this);
```

The equivalent Smali call is:

```smali
invoke-static {p0}, Lcom/ridhoae303/expert/Takane;->b(Landroid/content/Context;)Z
move-result v0
```

The `Z` at the end is important because `b(Context)` returns a Java `boolean`. The original form without `Z` is incomplete Smali syntax.

This example assumes `p0` contains a valid `Context`, which is normally true inside an instance method of an `Activity`, `Service`, or `Application`. If your context is stored in another register, replace `p0` with that register. Also make sure `v0` exists in the method's register allocation before using `move-result v0`.

When changing the package name, class name, or method names, update both the Java/Kotlin side and the native side. JNI will not magically figure it out for you.

## Getting the Signing Fingerprint

Use the SHA-256 fingerprint of the certificate that signs the APK. This is not the same as hashing the APK file itself.

For a normal Android keystore, `keytool` can print the certificate fingerprint:

```bash
keytool -list -v -keystore your-release-key.jks -alias your_alias
```

Remove the colons and convert the value to lowercase before adding it to `allowedHashes`.

```text
AA:BB:CC:12:34...
```

becomes:

```text
aabbcc1234...
```

## Runtime Behavior

### Valid signature

EAL currently shows:

```text
modded by ridhoae303 👻
miyoshi takane best girl 💕
```

The app then continues normally.

### Invalid signature

EAL will:

1. Save a local leech-detection flag.
2. Pick one random anti-leech message.
3. Display that message once.
4. Wait briefly so the Toast has time to appear.
5. Stop the app through the integrity-failure path.

On later launches, the stored flag skips the message and shuts the app down immediately.

The current `SharedPreferences` values are:

```text
File: x9j3kf
Key:  ld
```

## Configuration

The main things you may want to change are:

- Approved SHA-256 fingerprints
- Success messages
- Anti-leech messages
- `SharedPreferences` file and key
- JNI package, class, and method names
- Delay before termination
- Failure behavior

Do not print sensitive values or signing fingerprints into production logs unless you really know why you are doing it.

## Security Notes

EAL is a deterrent, not magic. Anyone who fully controls an APK can eventually patch local checks if they are stubborn enough.

For better protection, combine it with other layers such as:

- Code obfuscation
- Split verification logic
- Server-side checks
- Per-build fingerprints
- Creator watermarks
- Integrity checks in more than one location

The current package-signature lookup uses the legacy `GET_SIGNATURES` flag (`0x00000040`). It keeps the implementation straightforward, but newer Android projects may want to add a `SigningInfo` path for modern API levels.

The failure path intentionally stops the process. Test your fingerprint setup on a throwaway build first. Shipping the wrong hash is a very efficient way to lock out your own users.

## Project Status

EasyAntiLeech is still under development. The core signature check works, but compatibility, integration, and protection layers may change between versions.

Clean fixes and useful improvements are welcome. Credit removal, fake ownership, and repack drama are not.

## Repository

Source code and updates:

**https://github.com/ridhoae303/EasyAntiLeech**

## Creator Dialog

The mod-creator dialog used alongside EAL comes from another project of mine:

**[WelcomeDialog for Modders](https://github.com/ridhoae303/WelcomeDialog-for-modders)**

It is a lightweight welcome/credit dialog made for modders who want to show the original creator name clearly inside the app. EAL handles the signature check; WelcomeDialog handles the creator intro. They work nicely together, and yes, this is absolutely a shameless plug for my own repo. 😄

## License

This project uses the **EasyAntiLeech Community License 1.0**. Read the full terms in [`LICENSE`](./LICENSE).

This is a source-available license, not an OSI-approved open-source license. You may study and modify the code under its terms, but you may not remove the creator credit, pretend the original project is yours, or redistribute a repacked copy under someone else's name.

## Credits

Created by **ridhoae303**.

© 2026 ridhoae303. All rights reserved except where permission is granted in the license.
