import json
import logging
import os
import re
import sys
from datetime import date
from enum import Enum
from pathlib import Path
from subprocess import CalledProcessError, check_output

import click
from semver import VersionInfo

from metadater import exe, git

logger = logging.getLogger(__name__)

ERROR_NO_GIT = """

    Make sure that:
        - Your project has a Git repository (git init)
        - Your repository has at least one commit (git add && git commit)
        - Your repository has at least one tag following the SemVer specification (https://semver.org/) (git tag)
        - There is a Git user.name configured (git config user.name "John Doe")
"""


class Source(Enum):
    GIT = 1
    PE = 2
    JSON = 3


class MetaData:
    repo = None
    name = None
    description = None
    author = None
    email = None
    copyright = None
    semver = None
    version_info = None
    version = None
    prerelease = None
    build = None
    file_version = None
    product_version = None
    version_prerelease = None

    def __init__(self, dictionary=None):
        if dictionary:
            for k, v in dictionary.items():
                setattr(self, k, v)


class MetaDater:
    _source: Source = None
    _full_repo_path: Path = None
    _json_meta_file: Path = None

    metadata: MetaData = MetaData()

    def __init__(
        self, semantic_version=None, refresh_version=True, refresh_copyright=True
    ):
        self._determine_source()
        self._init_metadata_from_source()
        if self._source == Source.JSON:
            if refresh_version:
                self._refresh_version(semantic_version)
            if refresh_copyright:
                self._refresh_copyright()
            self.to_disk()

    def _determine_source(self):
        if hasattr(sys, "frozen"):
            self._source = Source.PE
        else:
            self._find_full_repo_path()
            self._find_json_meta_file()
            if self._json_meta_file:
                self._source = Source.JSON
            else:
                self._source = Source.GIT

    def _find_full_repo_path(self):
        try:
            self._full_repo_path = Path(
                check_output(["git", "rev-parse", "--show-toplevel"])
                .decode("utf-8")
                .strip()
            )
        except CalledProcessError:
            logger.error(ERROR_NO_GIT)
            exit(1)

    def _find_json_meta_file(self):
        _json_meta_file = self._full_repo_path / "metadata.json"
        if _json_meta_file.is_file():
            self._json_meta_file = _json_meta_file

    def _init_metadata_from_source(self):
        if self._source == Source.PE:
            self._init_metadata_from_pe()
        elif self._source == Source.GIT:
            self._init_metadata_from_git()
            self._interactively_ask_for_metadata()
            self._write_metadata_to_json()
        elif self._source == Source.JSON:
            self._init_metadata_from_json()

    def _init_metadata_from_pe(self):
        _exe_info = exe.get_info()
        if _exe_info:
            self.metadata.repo = _exe_info["InternalName"]
            self.metadata.name = _exe_info["ProductName"]
            self.metadata.description = _exe_info["FileDescription"]
            self.metadata.author = _exe_info["CompanyName"]
            self.metadata.copyright = _exe_info["LegalCopyright"]
            self.metadata.semver = _exe_info["PrivateBuild"]
            self.metadata.version_info = VersionInfo.parse(self.metadata.semver)
            self.metadata.version = f"{self.metadata.version_info.major}.{self.metadata.version_info.minor}.{self.metadata.version_info.patch}"
            self.metadata.prerelease = self.metadata.version_info.prerelease
            self.metadata.build = self.metadata.version_info.build
            self.metadata.file_version = _exe_info["FileVersion"]
            self.metadata.product_version = _exe_info["ProductVersion"]
            if self.metadata.prerelease:
                self.metadata.version_prerelease = (
                    f"{self.metadata.version}-{self.metadata.prerelease}"
                )
            else:
                self.metadata.version_prerelease = self.metadata.version

    def _init_metadata_from_git(self):
        _git_info = git.get_info()
        if _git_info:
            self._set_basic_fields(_git_info)
            _semantic_version = _git_info["describe"].replace(
                _git_info["last_tag"] + "-", _git_info["last_tag"] + "+"
            )
            self._set_version_fields(_semantic_version)

    def _set_basic_fields(self, _git_info):
        self.metadata.repo = os.path.basename(os.path.normpath(_git_info["full_path"]))
        self.metadata.author = _git_info["author"]
        self.metadata.email = _git_info["email"]
        self.metadata.copyright = self.metadata.author + ", " + str(date.today().year)

    def _set_version_fields(self, _semantic_version):
        self.metadata.semver = _semantic_version
        self.metadata.version_info = VersionInfo.parse(self.metadata.semver)
        self.metadata.version = f"{self.metadata.version_info.major}.{self.metadata.version_info.minor}.{self.metadata.version_info.patch}"
        self.metadata.prerelease = self.metadata.version_info.prerelease
        self.metadata.build = self.metadata.version_info.build
        self.metadata.file_version = f"{self.metadata.version}.0"
        self.metadata.product_version = self.metadata.semver
        if self.metadata.prerelease:
            self.metadata.version_prerelease = (
                f"{self.metadata.version}-{self.metadata.prerelease}"
            )
        else:
            self.metadata.version_prerelease = self.metadata.version

    def _refresh_version(self, _semantic_version):
        if not _semantic_version:
            _git_info = git.get_info()
            if _git_info:
                _semantic_version = _git_info["describe"].replace(
                    _git_info["last_tag"] + "-", _git_info["last_tag"] + "+"
                )
        self._set_version_fields(_semantic_version)

    def _refresh_copyright(self):
        self.metadata.copyright = self.metadata.author + ", " + str(date.today().year)

    def _init_metadata_from_json(self):
        _path = Path(self._full_repo_path) / "metadata.json"
        with _path.open() as _f:
            _metadata = json.load(_f)
            self.metadata = MetaData(_metadata)
            self.metadata.version_info = VersionInfo.parse(self.metadata.semver)

    def _interactively_ask_for_metadata(self):
        _name = re.sub("[^0-9a-zA-Z]+", " ", self.metadata.repo).title()
        self.metadata.name = click.prompt(
            "Please enter a name for your app", default=_name
        )
        self.metadata.description = click.prompt(
            "Please enter a description for your app",
            default="Lorem ipsum this app dolor sit amet",
        )

    def _write_metadata_to_json(self):
        if click.confirm(
            "Do you want to create a metadata.json file. "
            "This prevents you from having to answer these questions again."
        ):
            self.to_disk()

    def to_disk(self, _path: Path = None):
        """ Write the metadata as JSON to disk """
        if not _path:
            _path = self._full_repo_path / "metadata.json"
        if not type(_path) == Path:
            _path = Path(_path)
        _metadata = self.get().copy()
        del _metadata["version_info"]  # VersionInfo is not JSON serializable
        _path.parent.mkdir(parents=True, exist_ok=True)
        with _path.open("w") as _f:
            json.dump(_metadata, _f, indent=4, sort_keys=True)

    def get(self):
        """ Get all the application's metadata as a dictionary """
        return self.metadata.__dict__


if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)

    metadata = MetaDater().metadata
    print(metadata.version)

    metadata = MetaDater("2.0.5-rc.1+0-g1d1757c-dirty").get()
    for field in metadata:
        print(field, metadata[field])
