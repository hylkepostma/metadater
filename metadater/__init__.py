import sys
import os.path
import click
import re
import glob
from datetime import date

from . import exe
from . import git


class MetaData:

    def __init__(self):

        """
        Python (meta)   Exe (exe_info)      GIT	(git_info)	Example values
        ------------------------------------------------------------------
        version		    FileVersion     	version			2016.10.10.0
        name		    ProductName			?				Remote for Yamaha Receiver
        repo		    InternalName		repo			yamaha
        author		    CompanyName			author			Hylke Postma
        org_filename    OriginalFilename	repo+build		yamaha-master-2016.10.10-1-g658a581
        build		    PrivateBuild		build			master-2016.10.10-1-g658a581
        description	    FileDescription		?				Simple program that let's you control your Yamaha receiver
        copyright	    LegalCopyright     	?				Hylke Postma, 2016

        """

        # save information in our meta dict
        self.meta = {}

        if sys.argv[0].strip().endswith(".exe"):  # sys.argv[0] contains filename

            exe_info = exe.get_info()

            if exe_info:
                # fill self.meta with the values from the exe
                self.meta["version"] = exe_info['FileVersion']
                self.meta["name"] = exe_info['ProductName']
                self.meta["repo"] = exe_info['InternalName']
                self.meta["author"] = exe_info['CompanyName']
                self.meta["org_filename"] = exe_info['OriginalFilename']
                self.meta["build"] = exe_info['PrivateBuild']
                self.meta["description"] = exe_info['FileDescription']
                self.meta["copyright"] = exe_info['LegalCopyright']

        else:

            git_info = git.get_info()

            if git_info:
                # fill self.meta with the values from git that we can know of
                self.meta["version"] = git_info['version']
                self.meta["repo"] = git_info['repo']
                self.meta["full_path"] = git_info['full_path']
                self.meta["author"] = git_info['author']
                self.meta["org_filename"] = git_info['repo'] + "-" + git_info['build']
                self.meta["build"] = git_info['build']
                self.meta["tags"] = git_info['tags']

            # overwrite self.meta with self.meta data from APP_META in applications root folder
            if glob.glob(os.path.join(self.meta["full_path"], "APP_META*")):
                print("Found APP_META file. Using this:")
                print("\n----------------------\n")
                # if click.confirm('Do you want to use it?'):
                app_meta_file = glob.glob(os.path.join(self.meta["full_path"], "APP_META*"))[0]
                with open(app_meta_file) as f:
                    for line in f:
                        print(line.strip())
                        (key, val) = line.split(" = ")
                        # possible to overwrite all values with the APP_META values
                        self.meta[key] = val.strip()
                    print("\n----------------------\n")

            if "version" not in self.meta:
                self.meta["version"] = click.prompt("Version", default="0.0.1.0")

            if "repo" not in self.meta:
                self.meta["repo"] = click.prompt("Repository", default="my-app")

            if "name" not in self.meta:
                if "repo" in self.meta:
                    name = re.sub("[^0-9a-zA-Z]+", ' ', self.meta["repo"]).title()
                    self.meta["name"] = click.prompt("Application Name", default=name)
                else:
                    self.meta["name"] = click.prompt("Application Name", default="My App")

            if "author" not in self.meta:
                self.meta["author"] = click.prompt("Author", default="Hylke Postma")

            if "org_filename" not in self.meta:
                self.meta["org_filename"] = click.prompt("Original Filename", default="my-app-master-0.0.1.0-0-a101a101")

            if "build" not in self.meta:
                self.meta["build"] = click.prompt("Build", default="master-0.0.1.0-0-a101a101")

            if "description" not in self.meta:
                try:
                    description = src.main.__doc__
                    self.meta["description"] = click.prompt("Description", default=description)
                except:
                    self.meta["description"] = click.prompt("Description", default="Lorem ipsum this app dolor sit amet")

            if "copyright" not in self.meta:
                if "author" in self.meta:
                    self.meta["copyright"] = self.meta["author"] + ", " + str(date.today().year)
                else:
                    click.prompt("Copyright", default="Hylke Postma, " + str(date.today().year))

            if not glob.glob(os.path.join(self.meta["full_path"], "APP_META*"))\
                    and not sys.argv[0].endswith(".exe"):
                if click.confirm('Do you want to create an APP_META.txt file. '
                                 'It will save you some questions next time.'):
                    with open(os.path.join(self.meta["full_path"], "APP_META.txt"), 'w') as f:
                        for key, value in self.meta.items():
                            # only save not changing values in APP_META
                            if key not in ["version", "org_filename", "build", "tags", "full_path", "copyright"]:
                                f.write(key + " = " + value + "\n")

    def get(self):
        """ Get all the meta data """
        return self.meta

    def get_version(self):
        """ Get the applications version from meta data """
        return self.meta["version"]

    def get_name(self):
        """ Get the applications name from meta data """
        return self.meta["name"]

    def get_repo(self):
        """ Get the applications repo from meta data """
        return self.meta["repo"]

    def get_author(self):
        """ Get the applications author from meta data """
        return self.meta["author"]

    def get_org_filename(self):
        """ Get the applications original filename from meta data """
        return self.meta["org_filename"]

    def get_build(self):
        """ Get the applications build from meta data """
        return self.meta["build"]

    def get_description(self):
        """ Get the applications description from meta data """
        return self.meta["description"]

    def get_copyright(self):
        """ Get the applications copyright from meta data """
        return self.meta["copyright"]


if __name__ == '__main__':

    app_meta = MetaData()

    version = app_meta.get_version()
    print(version)

    meta = app_meta.get()
    for key in meta:
        print(key, meta[key])
