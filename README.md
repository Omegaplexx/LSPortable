# LSPortable

[LSPatch](https://github.com/JingMatrix/LSPatch) packed as a single dex-in-zip file that any Android app can run through `app_process`. It patches APKs (embeds Xposed modules) without the LSPatch manager app, root, or a separate process installed on the device.

## What it is

`lsportable` is a ZIP archive with a `classes.dex` inside, used as the `CLASSPATH` of `app_process`. It is not an APK and cannot be executed directly. The file name does not matter. The same technique starts the server of [scrcpy](https://github.com/Genymobile/scrcpy/blob/master/doc/develop.md): `adb shell CLASSPATH=/data/local/tmp/scrcpy-server.jar app_process / com.genymobile.scrcpy.Server`.

| Entry | Content |
|---|---|
| `classes.dex` | LSPatch classes plus `LSPortableEntry`, merged into one dex. Stored uncompressed and 4-byte aligned, so ART can map it straight from the archive. |
| `assets/*` | `assets/` of the LSPatch jar (loader dex files, `liblspatch.so` for four ABIs, and so on). |
| `assets/keystore` | Signing key for patched apps: LSPatch's default key (`key0`, password `123456`), converted from JKS to PKCS12, a format Android can read. The same key in every build. |

`LSPortableEntry` sets the keystore type to PKCS12 (ART ignores `-Djava.security.properties`) and calls `org.lsposed.patch.LSPatch.main`, so the command line is the regular LSPatch one.

## Usage

Download the `lsportable` file from the [latest release](../../releases/latest). Once downloaded, it works under any name.

Run it from an app process or from `adb shell`. No root is needed.

```
CLASSPATH=/path/to/lsportable app_process -Xmx768m /system/bin LSPortableEntry \
    -o <out_dir> -f -l 2 \
    -m <module.apk> \
    <target.apk>
```

- Options are LSPatch's own: `-m` embeds a module, `-l` is the signature bypass level, `-f` overwrites existing output, `-o` is the output folder.
- The APK is signed with the built-in key, so nothing else is needed. To use your own key, add LSPatch's `-k <keystore> <store password> <alias> <alias password>` (a real file; use PKCS12 or BKS).
- The patched APK appears in `<out_dir>`. Install it as usual.
- Set `-Xmx768m` or more: the default heap is too small for large APKs and the process is killed silently.
- Set `-Djava.io.tmpdir=<writable dir>` before the class name if `/tmp` does not exist. Android has no `/tmp`, and apkzlib needs one.

## Example: Happwner

[Happwner](https://github.com/Omegaplexx/Happwner) downloads Happ and v2RayTun, patches them and installs the result. Its integration is one class, `LSPortableRunner.kt`:

1. Gets the file from the release asset named `lsportable`, or from a bundled copy, and makes it read-only (ART refuses a writable classpath file).
2. Starts `/system/bin/app_process` with `CLASSPATH` set to the file and the arguments above. The module is Happwner's own APK (`-m`), the target is the downloaded APK.
3. Waits for the process and collects its output.
4. Takes the patched APK from the output folder and hands it to the system installer.

## Build

Requires Python 3.8+. The script downloads the latest [LSPatch release](https://github.com/JingMatrix/LSPatch/releases/latest) jar and packs it.

```
python lsportable-build/build_lsportable.py
```

Result: `build/lsportable`. It takes about a minute. JDK 21 and D8 are taken from your machine when found (D8 from the Android SDK's `build-tools`), otherwise downloaded into `build/tools`. Delete `build/` to start over.

To build LSPatch from source instead (needs git, about 7 GB of disk, 15 to 30 minutes on the first run):

```
python lsportable-build/build_lsportable.py --source
```

The script finds JDK 21, CMake, Ninja and the Android SDK on your machine first and downloads only what is missing, after printing a plan with sizes. Without an existing SDK it downloads 2.5 to 3 GB (Gradle installs two NDKs).

Options:

| Option | Meaning |
|---|---|
| `--jar FILE` | pack this lspatch jar instead of downloading the release |
| `--source` | build LSPatch from source |
| `--lspatch-ref REF` | with `--source`: LSPatch branch, tag or commit (default `master`) |
| `--gradle-home DIR` | with `--source`: Gradle cache (default `build/gradle-home`) |
| `--accept-licenses` | with `--source`: accept pending Android SDK licenses without asking |
| `--sdk DIR` | Android SDK folder |
| `--work DIR` | work folder (default `build/`) |
| `--out FILE` | output file |

SDK lookup order: `--sdk`, `ANDROID_HOME`, `ANDROID_SDK_ROOT`, the default Android Studio folder. With `--source`, if none exists, an SDK is downloaded to `build/tools/android-sdk`.

## Files

- `lsportable-build/build_lsportable.py`: full build (`build`) and packing of prebuilt parts (`assemble`, used by CI)
- `lsportable-build/LSPortableEntry.java`: entry point
- `lsportable-build/verify_lsportable.py`: check the archive layout (runs after every build)
- `.github/workflows/build-lsportable.yml`: CI build

## License

The file contains LSPatch, which is licensed under GPL-3.0. Follow its terms when you redistribute `lsportable`.
