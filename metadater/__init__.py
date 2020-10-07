import glob
import logging
import os
import re
import sys
from datetime import date
from subprocess import CalledProcessError
from subprocess import check_output

import click
from semver import VersionInfo

from metadater import exe
from metadater import git

logger = logging.getLogger(__name__)

ERROR_NO_GIT = """

    Make sure that:
        - Your project has a Git repository (git init)
        - Your repository has at least one commit (git add && git commit)
        - Your repository has at least one tag following the SemVer specification (https://semver.org/) (git tag)
        - There is a Git user.name configured (git config user.name "John Doe")
"""


class MetaData:

    def __init__(self):
        self._determine_source()
        self._init_metadata_from_source()

    def _determine_source(self):
        if hasattr(sys, 'frozen'):
            # The program is frozen with PyInstaller
            logger.debug("I think I'm frozen")
            self._source = "pe"
        else:
            logger.debug("I think I'm a script")
            self._find_full_path()
            if self._full_path:
                self._source = "git"
                self._has_app_meta_file = self._find_app_meta_file()

    def _find_full_path(self):
        try:
            self._full_path = check_output(["git", "rev-parse", "--show-toplevel"]).decode("utf-8").strip()
        except CalledProcessError:
            logger.error(ERROR_NO_GIT)
            exit(1)

    def _find_app_meta_file(self):
        if glob.glob(os.path.join(self._full_path, "APP_META")):
            return True
        else:
            return False

    def _init_metadata_from_source(self):
        if self._source == "pe":
            self._init_metadata_from_pe()
        elif self._source == "git":
            self._init_metadata_from_git()
            if self._has_app_meta_file:
                self._override_metadata_from_file()
            else:
                self._interactively_ask_for_metadata()
                self._write_metadata_to_file()

    def _init_metadata_from_pe(self):
        _exe_info = exe.get_info()
        if _exe_info:
            self._repo = _exe_info['InternalName']
            self._author = _exe_info['CompanyName']
            self._semver = _exe_info['PrivateBuild']
            self._version_info = VersionInfo.parse(self._semver)
            self._version = f"{self._version_info.major}.{self._version_info.minor}.{self._version_info.patch}"
            self._prerelease = self._version_info.prerelease
            self._build = self._version_info.build
            self._version_4_parts = f"{self._version}.0"
            self._file_version = _exe_info['FileVersion']
            self._product_version = _exe_info['ProductVersion']
            self._org_filename = _exe_info['OriginalFilename']
            self._name = _exe_info['ProductName']
            self._description = _exe_info['FileDescription']
            self._copyright = _exe_info['LegalCopyright']

    def _init_metadata_from_git(self):
        _git_info = git.get_info()
        if _git_info:
            self._repo = os.path.basename(os.path.normpath(_git_info["full_path"]))
            self._author = _git_info['author']
            self._semver = _git_info['describe'].replace(_git_info["last_tag"] + "-", _git_info["last_tag"] + "+")
            self._version_info = VersionInfo.parse(self._semver)
            self._version = f"{self._version_info.major}.{self._version_info.minor}.{self._version_info.patch}"
            self._prerelease = self._version_info.prerelease
            self._build = self._version_info.build
            self._version_4_parts = f"{self._version}.0"
            self._file_version = self._version_4_parts
            if self._prerelease:
                self._product_version = f"{self._version}-{self._prerelease}"
            else:
                self._product_version = self._version_4_parts
            self._org_filename = self._repo + "-" + self._semver
            self._copyright = self._author + ", " + str(date.today().year)

    def _override_metadata_from_file(self):
        app_meta_file = glob.glob(os.path.join(self._full_path, "APP_META*"))[0]
        with open(app_meta_file) as _f:
            for _line in _f:
                (_key, _val) = _line.split(" = ")
                setattr(self, "_{}".format(_key.strip()), _val.strip())
                if _key.strip() == "author":
                    # Since author is part of copyright, reset copyright too
                    self._copyright = self._author + ", " + str(date.today().year)

    def _interactively_ask_for_metadata(self):
        _name = re.sub('[^0-9a-zA-Z]+', ' ', self._repo).title()
        self._name = click.prompt("Please enter a name for your app", default=_name)

        self._description = click.prompt("Please enter a description for your app",
                                         default="Lorem ipsum this app dolor sit amet")

    def _write_metadata_to_file(self):
        if click.confirm('Do you want to create an APP_META file. '
                         'It will spare you these questions next time.'):
            with open(os.path.join(self._full_path, "APP_META"), 'w') as f:
                f.write("name = {}\n".format(self._name))
                f.write("description = {}\n".format(self._description))

    @property
    def repo(self):
        return self._repo

    @property
    def author(self):
        return self._author

    @property
    def semver(self):
        return self._semver

    @property
    def version_info(self):
        return self._version_info

    @property
    def version(self):
        return self._version

    @property
    def prerelease(self):
        return self._prerelease

    @property
    def build(self):
        return self._build

    @property
    def version_4_parts(self):
        return self._version_4_parts

    @property
    def file_version(self):
        return self._file_version

    @property
    def product_version(self):
        return self._product_version

    @property
    def org_filename(self):
        return self._org_filename

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def copyright(self):
        return self._copyright

    def get(self):
        """ Get all the application's metadata as a dictionary """
        return {
            'repo': self.repo,
            'author': self.author,
            'semver': self.semver,
            'version_info': self.version_info,
            'version': self.version,
            'prerelease': self.prerelease,
            'build': self.build,
            'version_4_parts': self.version_4_parts,
            'file_version': self.file_version,
            'product_version': self.product_version,
            'org_filename': self.org_filename,
            'name': self.name,
            'description': self.description,
            'copyright': self.copyright,
        }


if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG)

    metadata = MetaData()

    version = metadata.version
    print(version)

    version_4_parts = metadata.version_4_parts
    print(version_4_parts)

    version_dict = metadata.version_info.to_dict()
    print(version_dict)

    version = metadata.version_info.build
    print(version)

    metadata = metadata.get()
    for field in metadata:
        print(field, metadata[field])
