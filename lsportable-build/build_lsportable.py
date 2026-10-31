#!/usr/bin/env python3
"""Builds lsportable: the LSPatch jar's assets, LSPatch classes + LSPortableEntry dexed together,
and LSPatch's default signing key repacked as PKCS12.

    python build_lsportable.py [build] [options]
        Downloads the latest LSPatch release jar from GitHub and packs it. Needs JDK 21 and D8:
        both are taken from this PC when found, otherwise downloaded into <work>/tools.
    python build_lsportable.py --source [options]
        Builds LSPatch from source first (clones it, needs CMake, Ninja, the Android SDK with NDK,
        about 7 GB of disk). Everything missing is downloaded. Only git and Python 3.8+ must be
        installed.
    python build_lsportable.py assemble <assets_dir> <classes.dex> <keystore.p12> <output>
        Only the last step (used by CI).

Options of build:
    --jar FILE          pack this lspatch jar instead of downloading the release
    --source            build LSPatch from source
    --lspatch-ref REF   with --source: LSPatch branch, tag or commit (default: master)
    --gradle-home DIR   with --source: Gradle cache folder (default: <work>/gradle-home)
    --accept-licenses   with --source: accept the Android SDK licenses without asking
    --sdk DIR           Android SDK folder (default: found on this PC; with --source else <work>/tools/android-sdk)
    --work DIR          working folder (default: build/ in the repository)
    --out FILE          output file (default: <work>/lsportable)

classes.dex is stored uncompressed and aligned to 4 bytes: ART maps it straight from the
classpath zip. Everything else is deflated at level 9. Only STORED and DEFLATED are used, as
java.util.zip understands nothing else.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

if sys.version_info < (3, 8):
	sys.exit("error: Python 3.8 or newer is required")

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

LSPATCH_URL = "https://github.com/JingMatrix/LSPatch.git"
LSPATCH_API = "https://api.github.com/repos/JingMatrix/LSPatch"
# the nested submodule URLs pinned by LSPatch's core are dead; these forks are alive
SUBMODULE_FIXES = {
	"https://github.com/libxposed/service.git": "https://github.com/JingMatrix/libxposed-service.git",
	"https://github.com/libxposed/api.git": "https://github.com/JingMatrix/libxposed-api.git",
}
JDK_MAJOR = 21
R8_VERSION = "9.4.27"
CMAKE_VERSION = "3.31.6"
NINJA_VERSION = "1.12.1"
CMDLINE_TOOLS_BUILD = "11076708"
# used only when the version cannot be read from LSPatch's build.gradle.kts
FALLBACK_CMAKE_MINIMUM = "3.29.8"

# the oldest D8 taken from the SDK's build-tools (older ones cannot read Java 21 classes)
R8_MIN_MAJOR = 9
# rough (download, disk) sizes in MB, used for the plan printed at the start; the SDK packages
# are the real archive sizes for Windows
SIZES = {"jdk": (200, 320), "cmake": (45, 130), "ninja": (1, 1), "cmdline": (155, 200), "r8": (20, 20),
	"lspatch": (120, 350), "gradle": (140, 200), "libs": (600, 1200), "platform": (67, 100),
	"build-tools": (61, 150), "platform-tools": (8, 30), "ndk": (822, 2500), "ndk-default": (834, 2500)}
# AGP also installs its own default NDK for the modules that name none (seen with AGP 9.3.1)
AGP_DEFAULT_NDK = "29.0.14206865"

KEY_PASSWORD = "123456"
KEY_ALIAS = "key0"
KEYSTORE_ENTRY = "assets/keystore"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)

IS_WINDOWS = sys.platform == "win32"
OS_NAME = {"win32": "windows", "linux": "linux", "darwin": "mac"}.get(sys.platform, sys.platform)
ARCH = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
EXE = ".exe" if IS_WINDOWS else ""
BAT = ".bat" if IS_WINDOWS else ""


def log(message):
	print(f"[lsportable] {message}", flush=True)


def fail(message):
	sys.exit(f"error: {message}")


def run(cmd, cwd=None, env=None, stdin=None, capture=False):
	cmd = [str(c) for c in cmd]
	log("run: " + " ".join(cmd))
	proc = subprocess.run(cmd, cwd=cwd, env=env, input=stdin, text=True, capture_output=capture)
	if proc.returncode != 0:
		if capture:
			sys.stderr.write((proc.stdout or "") + (proc.stderr or ""))
		fail(f"{Path(cmd[0]).name} failed with exit code {proc.returncode}")
	return proc.stdout if capture else ""


# ---------------------------------------------------------------- downloads

def file_digest(path, algorithm):
	digest = hashlib.new(algorithm)
	with open(path, "rb") as f:
		for block in iter(lambda: f.read(1 << 20), b""):
			digest.update(block)
	return digest.hexdigest()


def open_url(url, headers=None):
	headers = dict(headers or {}, **{"User-Agent": "lsportable-build"})
	return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)


def fetch_text(url, headers=None):
	with open_url(url, headers) as response:
		return response.read().decode("utf-8")


def download(url, dest, checksum=None):
	"""Downloads url to dest (kept as a cache). checksum is (algorithm, hex digest) or None."""
	if dest.exists() and (checksum is None or file_digest(dest, checksum[0]) == checksum[1].lower()):
		return dest
	dest.parent.mkdir(parents=True, exist_ok=True)
	part = dest.with_name(dest.name + ".part")
	log(f"downloading {url}")
	done = 0
	with open_url(url) as response, open(part, "wb") as out:
		total = int(response.headers.get("Content-Length") or 0)
		shown = -1
		while True:
			block = response.read(1 << 16)
			if not block:
				break
			out.write(block)
			done += len(block)
			if total and done * 10 // total != shown:
				shown = done * 10 // total
				print(f"  {shown * 10}%", flush=True)
	if total and done != total:
		part.unlink()
		fail(f"download of {url} ended early")
	if checksum and file_digest(part, checksum[0]) != checksum[1].lower():
		part.unlink()
		fail(f"checksum mismatch for {url}")
	part.replace(dest)
	return dest


def extract(archive, dest):
	if archive.suffix == ".zip":
		with zipfile.ZipFile(archive) as zf:
			for info in zf.infolist():
				path = Path(zf.extract(info, dest))
				if not IS_WINDOWS and (info.external_attr >> 16) & 0o111:
					path.chmod(path.stat().st_mode | 0o111)
	else:
		with tarfile.open(archive) as tf:
			if hasattr(tarfile, "data_filter"):
				tf.extractall(dest, filter="data")
			else:
				tf.extractall(dest)


def drop(path):
	try:
		path.unlink()
	except OSError:
		pass


def install_archive(archive, final_dir):
	"""Extracts archive to final_dir (dropping a single top folder). Does nothing if it exists."""
	if final_dir.exists():
		return final_dir
	tmp = final_dir.with_name(final_dir.name + ".tmp")
	shutil.rmtree(tmp, ignore_errors=True)
	tmp.mkdir(parents=True)
	extract(archive, tmp)
	entries = list(tmp.iterdir())
	root = entries[0] if len(entries) == 1 and entries[0].is_dir() else tmp
	root.replace(final_dir)
	shutil.rmtree(tmp, ignore_errors=True)
	return final_dir


# ---------------------------------------------------------------- tools

def jdk_major(home):
	try:
		match = re.search(r'JAVA_VERSION="(\d+)', (home / "release").read_text())
	except OSError:
		return None
	return int(match.group(1)) if match else None


def jdk_usable(home):
	return all((home / "bin" / (name + EXE)).exists() for name in ("java", "javac", "keytool")) \
		and jdk_major(home) == JDK_MAJOR


def find_jdk():
	candidates = []
	if os.environ.get("JAVA_HOME"):
		candidates.append(Path(os.environ["JAVA_HOME"]))
	javac = shutil.which("javac")
	if javac:
		candidates.append(Path(javac).resolve().parent.parent)
	return next((home for home in candidates if jdk_usable(home)), None)


def ensure_jdk(downloads, tools):
	home = find_jdk()
	if home:
		log(f"using JDK {JDK_MAJOR} from {home}")
		return home
	url = (f"https://api.adoptium.net/v3/assets/latest/{JDK_MAJOR}/hotspot"
		f"?architecture={ARCH}&image_type=jdk&os={OS_NAME}")
	assets = json.loads(fetch_text(url))
	if not assets:
		fail(f"no JDK {JDK_MAJOR} download for {OS_NAME}/{ARCH}, install it and set JAVA_HOME")
	package = assets[0]["binary"]["package"]
	archive = download(package["link"], downloads / package["name"], ("sha256", package["checksum"]))
	home = install_archive(archive, tools / f"jdk-{JDK_MAJOR}")
	drop(archive)
	if (home / "Contents" / "Home").is_dir():
		home = home / "Contents" / "Home"
	return home


def cmake_version(exe):
	try:
		out = subprocess.run([exe, "--version"], capture_output=True, text=True).stdout
	except OSError:
		return None
	match = re.search(r"version (\d+)\.(\d+)\.(\d+)", out)
	return tuple(int(x) for x in match.groups()) if match else None


def parse_version(text):
	return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


CMAKE_PACKAGES = {
	("windows", "x64"): ("windows-x86_64", "zip"),
	("windows", "aarch64"): ("windows-arm64", "zip"),
	("linux", "x64"): ("linux-x86_64", "tar.gz"),
	("linux", "aarch64"): ("linux-aarch64", "tar.gz"),
}
NINJA_PACKAGES = {
	("windows", "x64"): "ninja-win.zip",
	("windows", "aarch64"): "ninja-winarm64.zip",
	("linux", "x64"): "ninja-linux.zip",
	("linux", "aarch64"): "ninja-linux-aarch64.zip",
}


def find_cmake(cmake_min, tools=None):
	"""(exe, folder to put on PATH or None): CMake from PATH, else our copy in tools/."""
	found = shutil.which("cmake")
	if found and (cmake_version(found) or ()) >= cmake_min:
		return found, None
	if tools:
		own = tools / f"cmake-{CMAKE_VERSION}" / "bin"
		exe = own / ("cmake" + EXE)
		if exe.is_file() and (cmake_version(str(exe)) or ()) >= cmake_min:
			return str(exe), own
	return None, None


def find_ninja(tools=None):
	"""(exe, folder to put on PATH or None): Ninja from PATH, else our copy in tools/."""
	found = shutil.which("ninja")
	if found:
		return found, None
	if tools:
		own = tools / f"ninja-{NINJA_VERSION}"
		if (own / ("ninja" + EXE)).is_file():
			return str(own / ("ninja" + EXE)), own
	return None, None


def ensure_cmake_ninja(downloads, tools, cmake_min):
	"""Returns folders to put on PATH so that CMake (>= cmake_min) and Ninja are found."""
	dirs = []
	found, own = find_cmake(cmake_min, tools)
	if found:
		log(f"using CMake from {found}")
		if own:
			dirs.append(own)
	else:
		package = CMAKE_PACKAGES.get((OS_NAME, ARCH))
		if not package:
			fail(f"install CMake {'.'.join(map(str, cmake_min))} or newer and put it on PATH")
		suffix, ext = package
		name = f"cmake-{CMAKE_VERSION}-{suffix}.{ext}"
		base = f"https://github.com/Kitware/CMake/releases/download/v{CMAKE_VERSION}"
		sums = fetch_text(f"{base}/cmake-{CMAKE_VERSION}-SHA-256.txt")
		digest = next(line.split()[0] for line in sums.splitlines() if line.strip().endswith(name))
		archive = download(f"{base}/{name}", downloads / name, ("sha256", digest))
		final = tools / f"cmake-{CMAKE_VERSION}"
		shutil.rmtree(final, ignore_errors=True)
		dirs.append(install_archive(archive, final) / "bin")
		drop(archive)
	found, own = find_ninja(tools)
	if found:
		log(f"using Ninja from {found}")
		if own:
			dirs.append(own)
	else:
		name = NINJA_PACKAGES.get((OS_NAME, ARCH))
		if not name:
			fail("install Ninja and put it on PATH")
		url = f"https://github.com/ninja-build/ninja/releases/download/v{NINJA_VERSION}/{name}"
		archive = download(url, downloads / f"{NINJA_VERSION}-{name}")
		final = tools / f"ninja-{NINJA_VERSION}"
		shutil.rmtree(final, ignore_errors=True)
		dirs.append(install_archive(archive, final))
		drop(archive)
	return dirs


def d8_version(java, jar):
	try:
		out = subprocess.run([str(java), "-cp", str(jar), "com.android.tools.r8.D8", "--version"],
			capture_output=True, text=True, timeout=120)
	except (OSError, subprocess.TimeoutExpired):
		return None
	match = re.search(r"D8 (\d+)\.(\d+)\.(\d+)", out.stdout + out.stderr)
	return tuple(int(x) for x in match.groups()) if match else None


def find_r8(tools, sdk, java):
	"""Our own downloaded jar, else a new enough d8.jar from the SDK's build-tools."""
	own = tools / f"r8-{R8_VERSION}.jar"
	if own.is_file():
		return own
	jars = sorted((sdk / "build-tools").glob("*/lib/d8.jar"),
		key=lambda p: parse_version(p.parent.parent.name), reverse=True) if sdk else []
	for jar in jars:
		version = d8_version(java, jar)
		if version and version[0] >= R8_MIN_MAJOR:
			log(f"using D8 {'.'.join(map(str, version))} from {jar}")
			return jar
	return None


def ensure_r8(tools, sdk, java):
	found = find_r8(tools, sdk, java)
	if found:
		return found
	url = f"https://maven.google.com/com/android/tools/r8/{R8_VERSION}/r8-{R8_VERSION}.jar"
	sha1 = fetch_text(url + ".sha1").split()[0]
	return download(url, tools / f"r8-{R8_VERSION}.jar", ("sha1", sha1))


def read_cmake_minimum(src):
	"""The CMake version LSPatch's build asks for ("3.29.8+")."""
	try:
		text = (src / "build.gradle.kts").read_text(encoding="utf-8")
		return re.search(r'cmake\s*\{\s*version\s*=\s*"([\d.]+)\+?"', text).group(1)
	except (OSError, AttributeError):
		log(f"could not read the CMake version from build.gradle.kts, using {FALLBACK_CMAKE_MINIMUM}")
		return FALLBACK_CMAKE_MINIMUM


def prepend_path(env, dirs):
	key = next((k for k in env if k.upper() == "PATH"), "PATH")
	env[key] = os.pathsep.join([str(d) for d in dirs] + [env.get(key, "")])


def sdk_like(path):
	names = ("platforms", "build-tools", "platform-tools", "cmdline-tools", "licenses", "ndk")
	return path.is_dir() and any((path / name).is_dir() for name in names)


def sdk_candidates():
	"""(folder, where it came from): the environment variables, then Android Studio's default folder."""
	for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
		if os.environ.get(var):
			yield Path(os.environ[var]), var
	home = Path.home()
	defaults = {
		"windows": [Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local")) / "Android" / "Sdk"],
		"mac": [home / "Library" / "Android" / "sdk"],
		"linux": [home / "Android" / "Sdk"],
	}
	for path in defaults.get(OS_NAME, []):
		yield path, "the default folder"


def locate_sdk(explicit):
	"""(folder, source) of an installed SDK, or (None, None)."""
	if explicit:
		return Path(explicit).resolve(), "--sdk"
	for path, source in sdk_candidates():
		if sdk_like(path):
			return path, source
	return None, None


def writable(path):
	try:
		path.mkdir(parents=True, exist_ok=True)
		with tempfile.TemporaryFile(dir=path):
			return True
	except OSError:
		return False


def choose_sdk(tools, explicit):
	"""(folder, source). Our own folder when none is found or the found one cannot be written to."""
	own = tools / "android-sdk"
	sdk, source = locate_sdk(explicit)
	if sdk is not None and not writable(sdk):
		log(f"no write access to {sdk}, using a separate SDK folder instead")
		sdk = None
	return (sdk, source) if sdk else (own, None)


def find_sdkmanager(sdk, tools):
	roots = [*sorted((sdk / "cmdline-tools").glob("*"), reverse=True), tools / "cmdline-tools"]
	for root in roots:
		manager = root / "bin" / ("sdkmanager" + BAT)
		if manager.exists():
			return manager
	return None


def read_sdk_requirements(src):
	"""Platform, build-tools and NDK versions that LSPatch's build asks for, or None."""
	try:
		text = (src / "build.gradle.kts").read_text(encoding="utf-8")
		return {
			"platform": re.search(r"androidCompileSdkVersion by extra\(\"?([\d.]+)", text).group(1),
			"build-tools": re.search(r'androidBuildToolsVersion by extra\("([\d.]+)"', text).group(1),
			"ndk": re.search(r'androidCompileNdkVersion by extra\("([\d.]+)"', text).group(1),
		}
	except (OSError, AttributeError):
		return None


def sdk_part_installed(sdk, name, version):
	if name == "platform":
		return any((sdk / "platforms" / f"android-{v}").is_dir() for v in (version, f"{version}.0"))
	return (sdk / ("build-tools" if name == "build-tools" else "ndk") / version).is_dir()


def licenses_pending(sdkmanager, env):
	"""True if sdkmanager still has licenses to accept (an old license file is not enough)."""
	proc = subprocess.run([str(c) for c in sdkmanager] + ["--licenses"], env=env,
		input="n\n" * 100, text=True, capture_output=True)
	return "All SDK package licenses accepted" not in (proc.stdout or "") + (proc.stderr or "")


def ensure_sdk(downloads, tools, env, accept_licenses, sdk):
	sdk.mkdir(parents=True, exist_ok=True)
	log(f"Android SDK: {sdk}")
	manager = find_sdkmanager(sdk, tools)
	if manager is None:
		platform_name = {"windows": "win", "linux": "linux", "mac": "mac"}.get(OS_NAME)
		if not platform_name:
			fail("unsupported platform for the Android command line tools")
		url = f"https://dl.google.com/android/repository/commandlinetools-{platform_name}-{CMDLINE_TOOLS_BUILD}_latest.zip"
		archive = download(url, downloads / f"commandlinetools-{platform_name}-{CMDLINE_TOOLS_BUILD}.zip")
		install_archive(archive, sdk / "cmdline-tools" / "latest")
		drop(archive)
		manager = find_sdkmanager(sdk, tools)
	sdkmanager = [manager, f"--sdk_root={sdk}"]
	if licenses_pending(sdkmanager, env):
		if not accept_licenses and sys.stdin.isatty():
			log(f"some Android SDK licenses are not accepted yet in {sdk}")
			log(f"read them: {manager} --sdk_root={sdk} --licenses")
			accept_licenses = input("[lsportable] accept them? [y/N] ").strip().lower() == "y"
		if not accept_licenses:
			fail(f"the Android SDK licenses are not accepted in {sdk}. Run again with "
				"--accept-licenses to accept them")
		log("accepting the Android SDK licenses")
		run(sdkmanager + ["--licenses"], env=env, stdin="y\n" * 100, capture=True)
		if licenses_pending(sdkmanager, env):
			fail("the Android SDK licenses are still not accepted (is the folder writable?)")
	return sdk


# ---------------------------------------------------------------- plan

def mb(value):
	return f"{value / 1024:.1f} GB" if value >= 1024 else f"{value} MB"


def show_plan(rows):
	"""rows: (name, found text or None, SIZES key or None, where it will go).
	Returns (download MB, disk MB) still needed."""
	download = disk = 0
	for name, found, key, dest in rows:
		if found:
			log(f"  {name:<18} found: {found}")
		elif key is None:
			log(f"  {name:<18} not found, will be created in {dest}")
		else:
			d, k = SIZES[key]
			download += d
			disk += k
			log(f"  {name:<18} not found, download ~{mb(d)} (~{mb(k)} on disk) into {dest}")
	return download, disk


def show_total(download, disk):
	log(f"  total: download ~{mb(download)}, disk space ~{mb(disk)}" if download else "  nothing to download")


def folder_size(path):
	total = 0
	for d, _, files in os.walk(path):
		for f in files:
			try:
				total += os.path.getsize(os.path.join(d, f))
			except OSError:
				pass
	return total


# ---------------------------------------------------------------- LSPatch

def git_args():
	args = ["git", "-c", "core.longpaths=true"]
	for old, new in SUBMODULE_FIXES.items():
		args += ["-c", f"url.{new}.insteadOf={old}"]
	return args


def latest_release_jar():
	"""The release jar of the newest stable LSPatch release (canary builds are prereleases)."""
	try:
		# a token lifts GitHub's anonymous rate limit (CI sets it)
		token = os.environ.get("GITHUB_TOKEN")
		data = json.loads(fetch_text(LSPATCH_API + "/releases/latest",
			{"Authorization": f"Bearer {token}"} if token else None))
	except (OSError, ValueError) as e:
		fail(f"could not get the latest LSPatch release from GitHub ({e}). Try again later or pass --jar FILE")
	for asset in data.get("assets", []):
		if re.fullmatch(r"lspatch-.*-release\.jar", asset["name"]):
			digest = asset.get("digest") or ""
			return {"tag": data["tag_name"], "name": asset["name"], "url": asset["browser_download_url"],
				"size": asset["size"], "sha256": digest[7:] if digest.startswith("sha256:") else None}
	fail(f"LSPatch release {data.get('tag_name')} has no release jar. Pass --jar FILE or use --source")


def git_run(cmd, cwd=None, tries=3):
	"""Runs a git command that uses the network; retries on a flaky connection."""
	for attempt in range(1, tries + 1):
		try:
			return run(cmd, cwd=cwd)
		except SystemExit:
			if attempt == tries:
				raise
			log(f"git failed, retrying ({attempt}/{tries - 1})")
			time.sleep(5 * attempt)


def prepare_source(work, ref):
	"""Clones LSPatch (full history: its version code is the commit count). Returns (folder, commit)."""
	if not shutil.which("git"):
		fail("git is not installed (Windows: winget install Git.Git)")
	src = work / "lspatch"
	git = git_args()
	if (src / ".git").exists():
		git_run(git + ["fetch", "--tags", "--force", "origin"], cwd=src)
	else:
		src.parent.mkdir(parents=True, exist_ok=True)
		git_run(git + ["clone", LSPATCH_URL, str(src)])
	commit = None
	for candidate in (f"origin/{ref}", ref):
		probe = subprocess.run(git + ["rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}"],
			cwd=src, capture_output=True, text=True)
		if probe.returncode == 0:
			commit = probe.stdout.strip()
			break
	if not commit:
		fail(f"LSPatch has no branch, tag or commit named '{ref}'")
	run(git + ["checkout", "--force", "--detach", commit], cwd=src)
	run(git + ["submodule", "sync", "--recursive"], cwd=src)
	git_run(git + ["submodule", "update", "--init", "--recursive", "--force"], cwd=src)
	return src, commit


def rewrite_file(path, edit):
	with open(path, encoding="utf-8", newline="") as f:
		text = f.read()
	fixed = edit(text)
	if fixed != text:
		with open(path, "w", encoding="utf-8", newline="") as f:
			f.write(fixed)
		return True
	return False


def fix_windows_quotes(src):
	"""LSPatch passes -DVERSION_NAME='"1.2"' (POSIX shell quoting). On Windows the quotes get
	lost on the way to the compiler and the build fails. Pass the bare value and stringify it
	in config.h instead; this works the same on every OS. Safe to run repeatedly."""
	define = re.compile(r"""-DVERSION_NAME='\\"(.*?)\\"'""")
	changed = False
	for path in (src / "build.gradle.kts", src / "core" / "build.gradle.kts"):
		if rewrite_file(path, lambda t: define.sub(lambda m: "-DVERSION_NAME=" + m.group(1), t)):
			changed = True
			log(f"Windows quoting fix applied to {path.relative_to(src)}")
	header = src / "core" / "native" / "include" / "common" / "config.h"
	line = "const char *const kVersionName = VERSION_NAME;"
	stringify = ("#define LSPORTABLE_STR2(x) #x\n#define LSPORTABLE_STR(x) LSPORTABLE_STR2(x)\n"
		"const char *const kVersionName = LSPORTABLE_STR(VERSION_NAME);")
	if rewrite_file(header, lambda t: t.replace(line, stringify)):
		log("Windows quoting fix applied to core/native/include/common/config.h")
	elif changed and "STR2(x) #x" not in header.read_text(encoding="utf-8"):
		fail("LSPatch changed config.h: the Windows quoting fix needs updating")


def build_lspatch(src, env):
	"""Builds only the jar module, not the manager app."""
	if IS_WINDOWS:
		fix_windows_quotes(src)
	out_dir = src / "out" / "release"
	for old in out_dir.glob("lspatch-*-release.jar"):
		old.unlink()
	gradlew = src / ("gradlew.bat" if IS_WINDOWS else "gradlew")
	if not IS_WINDOWS:
		gradlew.chmod(gradlew.stat().st_mode | 0o111)
	run([gradlew, ":jar:buildRelease", "--no-daemon", "--console=plain"], cwd=src, env=env)
	jars = sorted(out_dir.glob("lspatch-*-release.jar"), key=lambda p: p.stat().st_mtime)
	if not jars:
		fail(f"no lspatch release jar found in {out_dir}")
	return jars[-1]


# ---------------------------------------------------------------- packing

def add_deflated(zf, arcname, data):
	info = zipfile.ZipInfo(arcname, FIXED_DATE)
	info.compress_type = zipfile.ZIP_DEFLATED
	info.external_attr = 0o644 << 16
	zf.writestr(info, data, compresslevel=9)


def add_aligned_stored(zf, arcname, data, alignment=4):
	"""Writes `data` as a STORED entry whose data starts at a multiple of `alignment`."""
	info = zipfile.ZipInfo(arcname, FIXED_DATE)
	info.compress_type = zipfile.ZIP_STORED
	info.external_attr = 0o644 << 16
	# local header is 30 bytes + name + extra; the extra field is a 4-byte header plus padding
	base = zf.fp.tell() + 30 + len(arcname.encode())
	pad = (-(base + 4)) % alignment
	info.extra = (0xFFFF).to_bytes(2, "little") + pad.to_bytes(2, "little") + b"\x00" * pad
	zf.writestr(info, data)


def read_bytes(path):
	with open(path, "rb") as f:
		return f.read()


def assemble(assets_dir, classes_dex_path, keystore_path, out_path):
	assets_dir = str(assets_dir).rstrip("/\\")
	if os.path.basename(assets_dir) != "assets":
		fail(f"assets_dir must be a folder named 'assets', got {assets_dir}")
	for path in (classes_dex_path, keystore_path):
		if not os.path.isfile(path):
			fail(f"no such file: {path}")
	if not os.path.isdir(assets_dir):
		fail(f"no such folder: {assets_dir}")

	parent = os.path.dirname(assets_dir)
	with zipfile.ZipFile(out_path, "w") as zf:
		for root, dirs, files in os.walk(assets_dir):
			dirs.sort()
			for name in sorted(files):
				full = os.path.join(root, name)
				arcname = os.path.relpath(full, parent).replace(os.sep, "/")
				if arcname == KEYSTORE_ENTRY:
					continue
				add_deflated(zf, arcname, read_bytes(full))
		# LSPatch signs with this entry when no -k is given; same key, PKCS12 instead of JKS
		add_deflated(zf, KEYSTORE_ENTRY, read_bytes(keystore_path))
		# last, so nothing after it shifts the alignment
		add_aligned_stored(zf, "classes.dex", read_bytes(classes_dex_path))
	log(f"wrote {out_path}")


def split_jar(jar, assets_root, classes_jar):
	"""assets/ of the jar goes to assets_root/assets, the rest into classes_jar."""
	with zipfile.ZipFile(jar) as zin, zipfile.ZipFile(classes_jar, "w", zipfile.ZIP_DEFLATED) as zout:
		for info in zin.infolist():
			if info.filename.startswith("assets/"):
				zin.extract(info, assets_root)
			else:
				zout.writestr(info, zin.read(info.filename))


def pack(jar, jdk, r8, tmp, out):
	bin_dir = jdk / "bin"
	assets_root = tmp / "assets-src"
	classes_jar = tmp / "lspatch-classes-only.jar"
	split_jar(jar, assets_root, classes_jar)
	if not (assets_root / "assets" / "keystore").is_file():
		fail("the jar has no assets/keystore, LSPatch changed its default key")

	entry_dir = tmp / "entry"
	entry_dir.mkdir()
	run([bin_dir / ("javac" + EXE), "--release", str(JDK_MAJOR), "-cp", jar, "-d", entry_dir,
		HERE / "LSPortableEntry.java"])

	dex_dir = tmp / "dex_out"
	dex_dir.mkdir()
	run([bin_dir / ("java" + EXE), "-cp", r8, "com.android.tools.r8.D8", "--release", "--min-api", "26",
		"--output", dex_dir, classes_jar, entry_dir / "LSPortableEntry.class"])

	keytool = bin_dir / ("keytool" + EXE)
	p12 = tmp / "signing.p12"
	run([keytool, "-importkeystore", "-noprompt",
		"-srckeystore", assets_root / "assets" / "keystore", "-srcstoretype", "JKS",
		"-srcstorepass", KEY_PASSWORD, "-srckeypass", KEY_PASSWORD, "-srcalias", KEY_ALIAS,
		"-destkeystore", p12, "-deststoretype", "PKCS12",
		"-deststorepass", KEY_PASSWORD, "-destkeypass", KEY_PASSWORD, "-destalias", KEY_ALIAS])

	out.parent.mkdir(parents=True, exist_ok=True)
	assemble(assets_root / "assets", dex_dir / "classes.dex", p12, out)

	from verify_lsportable import check
	problems = check(str(out))
	if problems:
		fail("the result failed its checks:\n  - " + "\n  - ".join(problems))
	log("checks passed")


# ---------------------------------------------------------------- commands

def cmd_build(args):
	work = Path(args.work).resolve()
	tmp = work / "tmp"
	# downloads used to live in work/downloads
	shutil.rmtree(work / "downloads", ignore_errors=True)
	shutil.rmtree(tmp, ignore_errors=True)
	try:
		build(args, work, tmp)
	finally:
		shutil.rmtree(tmp, ignore_errors=True)


def build(args, work, tmp):
	downloads, tools = tmp / "downloads", work / "tools"
	out = Path(args.out).resolve() if args.out else work / "lsportable"
	tmp.mkdir(parents=True)
	if args.jar and args.source:
		fail("--jar and --source cannot be used together")
	if not args.source and (args.lspatch_ref or args.gradle_home or args.accept_licenses):
		fail("--lspatch-ref, --gradle-home and --accept-licenses only work with --source")
	log(f"working folder: {work}")
	local = str(tools)

	log("looking for installed tools")
	jdk = find_jdk()
	r8_own = tools / f"r8-{R8_VERSION}.jar"
	r8_row = ("R8 / D8", r8_own if r8_own.is_file() else None, "r8", local + " (skipped if the SDK has D8 9+)")
	rows = [("JDK 21", jdk, "jdk", local)]
	release = None
	if not args.source:
		if args.jar:
			jar = Path(args.jar).resolve()
			if not jar.is_file():
				fail(f"no such file: {jar}")
		else:
			release = latest_release_jar()
			jar = downloads / release["name"]
			ready = jar.is_file() and (not release["sha256"] or file_digest(jar, "sha256") == release["sha256"])
			megabytes = max(1, round(release["size"] / (1 << 20)))
			SIZES["jar"] = (megabytes, megabytes)
			rows.append((f"LSPatch {release['tag']}", jar if ready else None, "jar", str(downloads)))
		rows.append(r8_row)
		show_total(*show_plan(rows))
		sdk, _ = locate_sdk(args.sdk)
		commit = None
	else:
		if not shutil.which("git"):
			fail("git is not installed (Windows: winget install Git.Git)")
		sdk, source = choose_sdk(tools, args.sdk)
		manager = find_sdkmanager(sdk, tools)
		gradle_home = Path(args.gradle_home).resolve() if args.gradle_home else work / "gradle-home"
		dists, modules = gradle_home / "wrapper" / "dists", gradle_home / "caches" / "modules-2"
		rows += [
			("git", shutil.which("git"), None, ""),
			("CMake", find_cmake(parse_version(FALLBACK_CMAKE_MINIMUM), tools)[0], "cmake", local),
			("Ninja", find_ninja(tools)[0], "ninja", local),
			("Android SDK", f"{sdk} (from {source})" if source else (str(sdk) if sdk_like(sdk) else None), None, str(sdk)),
			("SDK cmdline-tools", manager, "cmdline", str(sdk / "cmdline-tools" / "latest")),
			r8_row,
			("LSPatch sources", work / "lspatch" if (work / "lspatch" / ".git").exists() else None,
				"lspatch", str(work / "lspatch")),
			("Gradle", next(dists.glob("gradle-*"), None) if dists.is_dir() else None, "gradle", str(gradle_home)),
			("Gradle libraries", modules if modules.is_dir() else None, "libs", str(gradle_home)),
		]
		if not source:
			log("  tip: to reuse an SDK you already have, set the ANDROID_HOME variable")
		need_mb, need_disk = show_plan(rows)
		log("  SDK licenses       checked before the build, you are asked if any are pending")
		log(f"  so far: download ~{mb(need_mb)}, disk ~{mb(need_disk)}; the SDK parts are added after LSPatch is cloned")

	jdk = ensure_jdk(downloads, tools)
	if not args.source:
		commit = None
		if release:
			checksum = ("sha256", release["sha256"]) if release["sha256"] else None
			jar = download(release["url"], jar, checksum)
	else:
		src, commit = prepare_source(work, args.lspatch_ref or "master")
		need = read_sdk_requirements(src)
		if need:
			parts = [("platform", sdk_part_installed(sdk, "platform", need["platform"]), f"platform {need['platform']}"),
				("build-tools", sdk_part_installed(sdk, "build-tools", need["build-tools"]), f"build-tools {need['build-tools']}"),
				("platform-tools", (sdk / "platform-tools").is_dir(), "platform-tools"),
				("ndk", sdk_part_installed(sdk, "ndk", need["ndk"]), f"NDK {need['ndk']}"),
				("ndk-default", sdk_part_installed(sdk, "ndk", AGP_DEFAULT_NDK), f"NDK {AGP_DEFAULT_NDK} (AGP default)")]
			log("SDK parts for the build (Gradle installs the missing ones into the SDK):")
			for key, present, label in parts:
				if present:
					log(f"  {label:<34} installed")
				else:
					d, k = SIZES[key]
					need_mb += d
					need_disk += k
					log(f"  {label:<34} missing, download ~{mb(d)} (~{mb(k)} on disk)")
		show_total(need_mb, need_disk)
		log("the first build can take 15-30 minutes" if need_mb else "this can take several minutes")
		# by default Gradle keeps its cache in the work folder instead of the user profile
		env = dict(os.environ, JAVA_HOME=str(jdk), GRADLE_USER_HOME=str(gradle_home),
			ANDROID_USER_HOME=str(work / "android-home"))
		sdk = ensure_sdk(downloads, tools, env, args.accept_licenses, sdk)
		path_dirs = [jdk / "bin"] + ensure_cmake_ninja(downloads, tools, parse_version(read_cmake_minimum(src)))
		env.update(ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk))
		prepend_path(env, path_dirs)
		jar = build_lspatch(src, env)
	log(f"LSPatch jar: {jar}")

	pack(jar, jdk, ensure_r8(tools, sdk, jdk / "bin" / ("java" + EXE)), tmp, out)
	log(f"done: {out} ({out.stat().st_size} bytes)")
	log(f"sha256: {file_digest(out, 'sha256')}")
	if release:
		log(f"LSPatch release: {release['tag']} ({release['name']})")
	if commit:
		log(f"LSPatch commit: {commit}")
	sizes = ", ".join(f"{name} {mb(folder_size(work / name) // (1 << 20))}"
		for name in ("tools", "gradle-home", "lspatch") if (work / name).exists())
	log(f"disk used in {work}: {sizes}")


def cmd_assemble(args):
	assemble(args.assets_dir, args.classes_dex, args.keystore, args.output)


def parse_args(argv):
	parser = argparse.ArgumentParser(prog="build_lsportable.py", description="Builds lsportable.")
	sub = parser.add_subparsers(dest="command")
	build = sub.add_parser("build", help="pack the latest LSPatch release (default)")
	build.add_argument("--source", action="store_true", help="build LSPatch from source instead")
	build.add_argument("--lspatch-ref", help="with --source: LSPatch branch, tag or commit (default: master)")
	build.add_argument("--jar", help="pack this lspatch jar instead of downloading the release")
	build.add_argument("--work", default=str(REPO / "build"), help="working folder")
	build.add_argument("--out", help="output file (default: <work>/lsportable)")
	build.add_argument("--gradle-home", help="with --source: Gradle cache folder (default: <work>/gradle-home; "
		"~/.gradle reuses the cache of your other projects)")
	build.add_argument("--sdk", help="Android SDK folder (default: found on this PC; with --source else <work>/tools/android-sdk)")
	build.add_argument("--accept-licenses", action="store_true", help="with --source: accept the Android SDK licenses")
	asm = sub.add_parser("assemble", help="pack ready parts into lsportable")
	asm.add_argument("assets_dir", help="the 'assets' folder unpacked from the lspatch jar")
	asm.add_argument("classes_dex", help="output of D8")
	asm.add_argument("keystore", help="PKCS12 keystore for signing patched apps")
	asm.add_argument("output", help="where to write lsportable")
	if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
		argv = ["build"] + argv
	return parser.parse_args(argv)


def main():
	args = parse_args(sys.argv[1:])
	if args.command == "assemble":
		cmd_assemble(args)
	else:
		cmd_build(args)


if __name__ == "__main__":
	main()
