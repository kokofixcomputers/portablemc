from urllib import parse as url_parse
from zipfile import ZipFile
from pathlib import Path
from io import BytesIO
import subprocess
import shutil
import json
import os

from .standard import parse_download_entry, LIBRARIES_URL, \
    Context, VersionHandle, Version, Watcher, VersionNotFoundError
from .util import calc_input_sha1, LibrarySpecifier
from .http import http_request, HttpError

from typing import Dict, Optional, List, Tuple

_FORGE_REPO_URL = "https://maven.minecraftforge.net/"
_FORGE_GROUP = "net.minecraftforge"
_FORGE_ARTIFACT = "forge"

_NEO_FORGE_REPO_URL = "https://maven.neoforged.net/releases/"
_NEO_FORGE_GROUP = "net.neoforged"
_NEO_FORGE_ARTIFACT = "neoforge"
_NEOFORGE_VERSIONS_API = "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge"

class ForgeVersion(Version):
    def __init__(self, forge_version: str = "release", *, context: Optional[Context] = None, prefix: str = "forge") -> None:
        super().__init__("", context=context)
        self.forge_version = forge_version
        self.prefix = prefix
        self._forge_repo_url: Optional[str] = None
        self._forge_installer_spec: Optional[LibrarySpecifier] = None
        self._forge_post_info: Optional[_ForgePostInfo] = None

    def _resolve_version(self, watcher: Watcher) -> None:
        self.forge_version = self.manifest.filter_latest(self.forge_version)[0]
        if "-" not in self.forge_version:
            self.forge_version = f"{self.forge_version}-recommended"
        if self.forge_version.endswith(("-latest", "-recommended")):
            alias_version, alias = self.forge_version.rsplit("-", maxsplit=1)
            watcher.handle(ForgeResolveEvent(self.forge_version, True))
            promo_versions = request_promo_versions()
            loader_version = promo_versions.get(self.forge_version)
            if loader_version is None:
                alias = {"latest": "recommended", "recommended": "latest"}[alias]
                self.forge_version = f"{alias_version}-{alias}"
                watcher.handle(ForgeResolveEvent(self.forge_version, True))
                loader_version = promo_versions.get(self.forge_version)
            if loader_version is None:
                raise VersionNotFoundError(f"{self.prefix}-{alias_version}-???")
            self.forge_version = f"{alias_version}-{loader_version}"
            watcher.handle(ForgeResolveEvent(self.forge_version, False))
        self.version = f"{self.prefix}-{self.forge_version}"
        self._forge_repo_url = _FORGE_REPO_URL
        self._forge_installer_spec = LibrarySpecifier(_FORGE_GROUP, _FORGE_ARTIFACT, self.forge_version, classifier="installer")

    def _load_version(self, version: VersionHandle, watcher: Watcher) -> bool:
        if version.id == self.version:
            return version.read_metadata_file()
        else:
            return super()._load_version(version, watcher)

    def _fetch_version(self, version: VersionHandle, watcher: Watcher) -> None:
        if version.id != self.version:
            return super()._fetch_version(version, watcher)
        assert self._forge_repo_url is not None
        assert self._forge_installer_spec is not None
        game_version = self.forge_version.split("-", 1)[0]
        suffixes = [""] + {
            "1.11": ["-1.11.x"],
            "1.10.2": ["-1.10.0"],
            "1.10": ["-1.10.0"],
            "1.9.4": ["-1.9.4"],
            "1.9": ["-1.9.0", "-1.9"],
            "1.8.9": ["-1.8.9"],
            "1.8.8": ["-1.8.8"],
            "1.8": ["-1.8"],
            "1.7.10": ["-1.7.10", "-1710ls", "-new"],
            "1.7.2": ["-mc172"],
        }.get(game_version, [])
        install_jar = None
        original_version = self._forge_installer_spec.version
        for suffix in suffixes:
            try:
                self._forge_installer_spec.version = f"{original_version}{suffix}"
                install_jar_url = f"{self._forge_repo_url}{self._forge_installer_spec.file_path()}"
                install_jar_res = http_request("GET", install_jar_url, accept="application/java-archive")
                install_jar = ZipFile(BytesIO(install_jar_res.data))
                break
            except HttpError as error:
                if error.res.status != 404:
                    raise
        if install_jar is None:
            raise VersionNotFoundError(version.id)
        with install_jar:
            try:
                info = install_jar.getinfo("install_profile.json")
                with install_jar.open(info) as fp:
                    install_profile = json.load(fp)
            except KeyError:
                raise ForgeInstallError(self.forge_version, ForgeInstallError.INSTALL_PROFILE_NOT_FOUND)
            if "json" in install_profile:
                info = install_jar.getinfo(install_profile["json"].lstrip("/"))
                with install_jar.open(info) as fp:
                    version.metadata = json.load(fp)
                post_info = _ForgePostInfo(self.context.gen_bin_dir())
                for i, processor in enumerate(install_profile["processors"]):
                    processor_sides = processor.get("sides", [])
                    if not isinstance(processor_sides, list):
                        raise ValueError(f"forge profile: /json/processors/{i}/sides must be an array")
                    if len(processor_sides) and "client" not in processor_sides:
                        continue
                    processor_jar_name = processor.get("jar")
                    if not isinstance(processor_jar_name, str):
                        raise ValueError(f"forge profile: /json/processors/{i}/jar must be a string")
                    processor_spec = LibrarySpecifier.from_str(processor_jar_name)
                    post_info.processors.append(_ForgePostProcessor(
                        processor_spec,
                        [LibrarySpecifier.from_str(raw_spec) for raw_spec in processor.get("classpath", [])],
                        processor.get("args", []),
                        processor.get("outputs", {})
                    ))
                forge_spec_raw = install_profile.get("path")
                if forge_spec_raw is not None:
                    lib_spec = LibrarySpecifier.from_str(forge_spec_raw)
                    lib_path = self.context.libraries_dir / lib_spec.file_path()
                    zip_extract_file(install_jar, f"maven/{lib_spec.file_path()}", lib_path)
                for i, install_lib in enumerate(install_profile["libraries"]):
                    lib_name = install_lib["name"]
                    lib_spec = LibrarySpecifier.from_str(lib_name)
                    lib_artifact = install_lib["downloads"]["artifact"]
                    lib_path = self.context.libraries_dir / lib_spec.file_path()
                    if lib_spec in post_info.libraries:
                        continue
                    post_info.libraries[lib_spec] = lib_path
                    if len(lib_artifact["url"]):
                        self._dl.add(parse_download_entry(lib_artifact, lib_path, "forge profile: /json/libraries/"), verify=True)
                    else:
                        zip_extract_file(install_jar, f"maven/{lib_spec.file_path()}", lib_path)
                install_data = install_profile["data"]
                if isinstance(install_data, dict):
                    for data_key, data_val in install_data.items():
                        data_val = str(data_val["client"])
                        if data_val.startswith("/"):
                            dst_path = post_info.tmp_dir / data_val[1:]
                            zip_extract_file(install_jar, data_val[1:], dst_path)
                            data_val = str(dst_path.absolute())
                        post_info.variables[data_key] = data_val
                self._forge_post_info = post_info
            else:
                version.metadata = install_profile.get("versionInfo")
                if not isinstance(version.metadata, dict):
                    raise ForgeInstallError(self.forge_version, ForgeInstallError.VERSION_METADATA_NOT_FOUND)
                for version_lib in version.metadata["libraries"]:
                    if "serverreq" in version_lib:
                        del version_lib["serverreq"]
                    if "clientreq" in version_lib:
                        del version_lib["clientreq"]
                    if "checksums" in version_lib:
                        del version_lib["checksums"]
                    if not version_lib.get("url"):
                        version_lib["url"] = LIBRARIES_URL
                if "inheritsFrom" not in version.metadata:
                    version.metadata["inheritsFrom"] = install_profile["install"]["minecraft"]
                jar_entry_path = install_profile["install"]["filePath"]
                jar_spec = LibrarySpecifier.from_str(install_profile["install"]["path"])
                jar_path = self.context.libraries_dir / jar_spec.file_path()
                zip_extract_file(install_jar, jar_entry_path, jar_path)
        version.metadata["id"] = version.id
        version.write_metadata_file()

    def _resolve_jar(self, watcher: Watcher) -> None:
        super()._resolve_jar(watcher)
        self._finalize_forge(watcher)

    def _finalize_forge(self, watcher: Watcher) -> None:
        try:
            self._finalize_forge_internal(watcher)
        except:
            try:
                self._hierarchy[0].metadata_file().unlink()
            except FileNotFoundError:
                pass
            raise

    def _finalize_forge_internal(self, watcher: Watcher) -> None:
        info = self._forge_post_info
        if info is None:
            return
        assert self._jvm_path is not None, "_resolve_jvm(...) missing"
        assert self._jar_path is not None, "_resolve_jar(...) missing"
        self._download(watcher)
        info.variables["SIDE"] = "client"
        info.variables["MINECRAFT_JAR"] = str(self._jar_path.absolute())
        info.variables.setdefault("ROOT", str(self.context.work_dir.absolute()))
        def replace_install_args(txt: str) -> str:
            txt = txt.format_map(info.variables)
            if txt[0] == "[" and txt[-1] == "]":
                spec = LibrarySpecifier.from_str(txt[1:-1])
                txt = str((self.context.libraries_dir / spec.file_path()).absolute())
            elif txt[0] == "'" and txt[-1] == "'":
                txt = txt[1:-1]
            return txt
        for processor in info.processors:
            jar_path = info.libraries[processor.spec].absolute()
            main_class = None
            with ZipFile(jar_path) as jar_fp:
                with jar_fp.open("META-INF/MANIFEST.MF") as manifest_fp:
                    for manifest_line in manifest_fp.readlines():
                        if manifest_line.startswith(b"Main-Class: "):
                            main_class = manifest_line[12:].decode().strip()
                            break
            if main_class is None:
                raise ValueError(f"cannot find main class in {jar_path}")
            if len(processor.args) >= 2 and processor.args[0] == "--task":
                task = processor.args[1].lower()
            else:
                task = {
                    "jarsplitter": "split_jar",
                    "ForgeAutoRenamingTool": "forge_auto_renaming",
                    "binarypatcher": "patch_binary",
                    "SpecialSource": "special_source_renaming",
                }.get(processor.spec.artifact, f"unknown({processor.spec})")
            args = [
                str(self._jvm_path.absolute()),
                "-cp", os.pathsep.join([str(jar_path), *(str(info.libraries[lib_spec].absolute()) for lib_spec in processor.class_path)]),
                main_class,
                *(replace_install_args(arg) for arg in processor.args)
            ]
            watcher.handle(ForgePostProcessingEvent(task))
            completed = subprocess.run(args, cwd=self.context.work_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if completed.returncode != 0:
                raise ValueError("ERROR", completed.stdout)
            for lib_name, expected_sha1 in processor.sha1.items():
                lib_name = replace_install_args(lib_name)
                expected_sha1 = replace_install_args(expected_sha1)
                with open(lib_name, "rb") as fp:
                    actual_sha1 = calc_input_sha1(fp)
                    if actual_sha1 != expected_sha1:
                        raise ValueError(f"invalid sha1 for '{lib_name}', got {actual_sha1}, expected {expected_sha1}")
        shutil.rmtree(info.tmp_dir, ignore_errors=True)
        watcher.handle(ForgePostProcessedEvent())

class _NeoForgeVersion(ForgeVersion):

    def __init__(self, neoforge_version: str = "release", *, context: Optional[Context] = None, prefix: str = "neoforge") -> None:
        super().__init__(neoforge_version, context=context, prefix=prefix)

    def _resolve_version(self, watcher: Watcher) -> None:
        if '-' in self.forge_version and '.' in self.forge_version.split('-')[-1]:
            self.version = f"{self.prefix}-{self.forge_version}"
        else:
            watcher.handle(ForgeResolveEvent(self.forge_version, True, _api="neoforge"))
            full_version = _resolve_latest_neoforge_version(self.forge_version)
            if full_version is None:
                raise VersionNotFoundError(f"{self.prefix}-{self.forge_version}-???")
            self.forge_version = full_version
            watcher.handle(ForgeResolveEvent(self.forge_version, False, _api="neoforge"))
            self.version = f"{self.prefix}-{self.forge_version}"
        forge_artifact = _FORGE_ARTIFACT if self.forge_version.startswith("1.20.1-") else _NEO_FORGE_ARTIFACT
        self._forge_repo_url = _NEO_FORGE_REPO_URL
        self._forge_installer_spec = LibrarySpecifier(_NEO_FORGE_GROUP, forge_artifact, self.forge_version, classifier="installer")

def _resolve_latest_neoforge_version(minecraft_version: str) -> Optional[str]:
    try:
        resp = http_request("GET", _NEOFORGE_VERSIONS_API, accept="application/json").json()
        parts = minecraft_version.split(".")
        if len(parts) != 3:
            return None
        base = f"{int(parts[1])}.{int(parts[2])}"
        candidates = [v for v in resp["versions"] if v.startswith(base + ".") or v.startswith(base + "-")]
        if not candidates:
            return None
        def sortkey(v):
            main = v.replace('-beta','')
            return tuple(int(x) if x.isdigit() else 0 for x in main.split('.'))
        best = sorted(candidates, key=sortkey)[-1]
        return f"{best}"
    except Exception:
        return None

class _ForgePostProcessor:
    __slots__ = "spec", "class_path", "args", "sha1"
    def __init__(self, spec: LibrarySpecifier, class_path: List[LibrarySpecifier], args: List[str], sha1: Dict[str, str]) -> None:
        self.spec = spec
        self.class_path = class_path
        self.args = args
        self.sha1 = sha1

class _ForgePostInfo:
    def __init__(self, tmp_dir: Path) -> None:
        self.tmp_dir = tmp_dir
        self.variables: Dict[str, str] = {}
        self.libraries: Dict[LibrarySpecifier, Path] = {}
        self.processors: List[_ForgePostProcessor] = []

class ForgeInstallError(Exception):
    INSTALL_PROFILE_NOT_FOUND = "install_profile_not_found"
    VERSION_METADATA_NOT_FOUND = "version_meta_not_found"
    def __init__(self, version: str, code: str):
        self.version = version
        self.code = code
    def __str__(self) -> str:
        return repr((self.version, self.code))

class ForgeResolveEvent:
    __slots__ = "forge_version", "alias", "_api"
    def __init__(self, forge_version: str, alias: bool, *, _api="forge") -> None:
        self.forge_version = forge_version
        self.alias = alias
        self._api = _api

class ForgePostProcessingEvent:
    __slots__ = "task",
    def __init__(self, task: str) -> None:
        self.task = task

class ForgePostProcessedEvent:
    __slots__ = tuple()

def request_promo_versions() -> Dict[str, str]:
    return http_request("GET", "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json",
        accept="application/json").json()["promos"]

def request_maven_versions() -> List[str]:
    text = http_request("GET", f"{_FORGE_REPO_URL}/net/minecraftforge/forge/maven-metadata.xml",
        accept="application/xml").text()
    versions = []
    last_idx = 0
    while True:
        start_idx = text.find("<version>", last_idx)
        if start_idx == -1:
            break
        end_idx = text.find("</version>", start_idx + 9)
        if end_idx == -1:
            break
        versions.append(text[(start_idx + 9):end_idx])
        last_idx = end_idx + 10
    return versions

def request_install_jar(version: str) -> ZipFile:
    res = http_request("GET", f"{_FORGE_REPO_URL}/net/minecraftforge/forge/{version}/forge-{version}-installer.jar",
        accept="application/java-archive")
    return ZipFile(BytesIO(res.data))

def zip_extract_file(zf: ZipFile, entry_path: str, dst_path: Path):
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(entry_path) as src, dst_path.open("wb") as dst:
        shutil.copyfileobj(src, dst)

class ForgePostProcessor:
    __slots__ = "jar_name", "class_path", "args", "sha1"
    def __init__(self, jar_name: str, class_path: List[str], args: List[str], sha1: Dict[str, str]) -> None:
        self.jar_name = jar_name
        self.class_path = class_path
        self.args = args
        self.sha1 = sha1

class ForgePostInfo:
    def __init__(self, tmp_dir: Path) -> None:
        self.tmp_dir = tmp_dir
        self.variables: Dict[str, str] = {}
        self.libraries: Dict[str, Path] = {}
        self.processors: List[ForgePostProcessor] = []
