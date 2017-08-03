import sys
import os.path
import click
import re
import glob
from datetime import date
from subprocess import check_output
from subprocess import CalledProcessError

from metadater import exe
from metadater import git


class MetaData:

    """
    Python (meta)   Exe (exe_info)      GIT	(git_info)	Example values
    ------------------------------------------------------------------
    repo		    InternalName		repo			my-app
    author		    CompanyName			author			John Doe
    version		    FileVersion     	version			0.0.1.0
    build		    PrivateBuild		build			master-0.0.1.0-1-00a00a00
    org_filename    OriginalFilename	repo+build		my-app-master-0.0.1.0-1-00a00a00

    name		    ProductName			-				My App
    description	    FileDescription		-				Lorem ipsum this app dolor sit amet
    copyright	    LegalCopyright     	-       		John Doe, 2017

    full_path       -                   full_path       /path/to/my-app
    tags            -                   tags            ['1.0.2', '1.0.3', '1.0.4']

    """

    def __init__(self):

        self._metadata = {}

        self._repo = "my-app"
        self._author = "John Doe"
        self._version = "0.0.1.0"
        self._build = "master-0.0.1.0-1-00a00a00"
        self._org_filename = "my-app-master-0.0.1.0-1-00a00a00"

        self._name = "My App"
        self._description = "Lorem ipsum this app dolor sit amet"
        self._copyright = "John Doe, " + str(date.today().year)

        self._full_path = None
        self._tags = None

        self._source = None
        self._has_app_meta_file = None

        self._init_source()
        self._init_metadata_from_source()

    def _init_source(self):
        if sys.argv[0].endswith(".exe"):  # sys.argv[0] contains filename
            self._source = "pe"
        else:
            self._find_full_path()
            if self._full_path:
                self._source = "git"
                self._has_app_meta_file = self._find_app_meta_file()

    def _find_full_path(self):
        try:
            self._full_path = check_output(["git", "rev-parse", "--show-toplevel"]).decode("utf-8").strip()
        except CalledProcessError:
            self._full_path = False

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
            self._version = _exe_info['FileVersion']
            self._build = _exe_info['PrivateBuild']
            self._org_filename = _exe_info['OriginalFilename']

            self._name = _exe_info['ProductName']
            self._description = _exe_info['FileDescription']
            self._copyright = _exe_info['LegalCopyright']

    def _init_metadata_from_git(self):
        _git_info = git.get_info()
        if _git_info:
            self._repo = _git_info['repo']
            self._author = _git_info['author']
            self._version = _git_info['version']
            self._build = _git_info['build']
            self._org_filename = _git_info['repo'] + "-" + _git_info['build']

            self._copyright = self._author + ", " + str(date.today().year)

            self._full_path = _git_info['full_path']
            self._tags = _git_info['tags']

    def _override_metadata_from_file(self):
        app_meta_file = glob.glob(os.path.join(self._full_path, "APP_META*"))[0]
        with open(app_meta_file) as _f:
            for _line in _f:
                (_key, _val) = _line.split(" = ")
                setattr(self, "_{}".format(_key.strip()), _val.strip())
                if _key.strip() == "author":
                    # since author is part of copyright, reset copyright too
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

    def get(self):
        """ Get all the applications metadata as a dictionary """
        self._metadata['repo'] = self._repo
        self._metadata['author'] = self._author
        self._metadata['version'] = self._version
        self._metadata['build'] = self._build
        self._metadata['org_filename'] = self._org_filename
        self._metadata['name'] = self._name
        self._metadata['description'] = self._description
        self._metadata['copyright'] = self._copyright
        self._metadata['tags'] = self._tags

        return self._metadata

    @property
    def repo(self):
        """ Get the applications repo from metadata """
        return self._repo

    @property
    def author(self):
        """ Get the applications author from metadata """
        return self._author

    @property
    def version(self):
        """ Get the applications version from metadata """
        return self._version

    @property
    def build(self):
        """ Get the applications build from metadata """
        return self._build

    @property
    def org_filename(self):
        """ Get the applications original filename from metadata """
        return self._org_filename

    @property
    def name(self):
        """ Get the applications name from metadata """
        return self._name

    @property
    def description(self):
        """ Get the applications description from metadata """
        return self._description

    @property
    def copyright(self):
        """ Get the applications copyright from metadata """
        return self._copyright

    @property
    def tags(self):
        """ Get the applications tags as a list """
        return self._tags


if __name__ == '__main__':

    metadata = MetaData()

    version = metadata.version
    print(version)

    metadata = metadata.get()
    for field in metadata:
        print(field, metadata[field])
