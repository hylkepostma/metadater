import sys
import os.path
import click
import re
import glob
from datetime import date

from metadater import exe
from metadater import git


class MetaData:

    def __init__(self):

        """
        Python (meta)   Exe (exe_info)      GIT	(git_info)	Example values
        ------------------------------------------------------------------
        repo		    InternalName		repo			yamaha
        author		    CompanyName			author			Hylke Postma
        version		    FileVersion     	version			2016.10.10.0
        build		    PrivateBuild		build			master-2016.10.10-1-g658a581        
        org_filename    OriginalFilename	repo+build		yamaha-master-2016.10.10-1-g658a581

        name		    ProductName			?				Remote for Yamaha Receiver
        description	    FileDescription		?				Simple program that let's you control your Yamaha receiver
        copyright	    LegalCopyright     	?       		Hylke Postma, 2016

        full_path       ?                   full_path       /path/to/yamaha
        tags            ?                   tags            ['1.0.2', '1.0.3', '1.0.4']
        
        """

        # save information in our metadata dict
        self.metadata = {}

        if sys.argv[0].strip().endswith(".exe"):  # sys.argv[0] contains filename

            exe_info = exe.get_info()

            if exe_info:
                # fill self.metadata with the values from the exe

                self.metadata["repo"] = exe_info['InternalName']
                self.metadata["author"] = exe_info['CompanyName']
                self.metadata["version"] = exe_info['FileVersion']
                self.metadata["build"] = exe_info['PrivateBuild']
                self.metadata["org_filename"] = exe_info['OriginalFilename']

                self.metadata["name"] = exe_info['ProductName']
                self.metadata["description"] = exe_info['FileDescription']
                self.metadata["copyright"] = exe_info['LegalCopyright']

        else:

            git_info = git.get_info()

            if git_info:
                # fill self.metadata with the values from git that we can know of
                self.metadata["repo"] = git_info['repo']
                self.metadata["author"] = git_info['author']
                self.metadata["version"] = git_info['version']
                self.metadata["build"] = git_info['build']
                self.metadata["org_filename"] = git_info['repo'] + "-" + git_info['build']

                self.metadata["full_path"] = git_info['full_path']
                self.metadata["tags"] = git_info['tags']

                # overwrite self.metadata with self.metadata data from APP_META in applications root folder
                if glob.glob(os.path.join(self.metadata["full_path"], "APP_META*")):
                    print("Found APP_META file. Using this:")
                    print("\n----------------------\n")
                    # if click.confirm('Do you want to use it?'):
                    app_meta_file = glob.glob(os.path.join(self.metadata["full_path"], "APP_META*"))[0]
                    with open(app_meta_file) as f:
                        for line in f:
                            print(line.strip())
                            (key, val) = line.split(" = ")
                            # possible to overwrite all values with the APP_META values
                            self.metadata[key] = val.strip()
                        print("\n----------------------\n")

                if "name" not in self.metadata:
                    name = re.sub("[^0-9a-zA-Z]+", ' ', self.metadata["repo"]).title()
                    self.metadata["name"] = click.prompt("Please enter a name for your app", default=name)

                if "description" not in self.metadata:
                    try:
                        description = src.main.__doc__
                        self.metadata["description"] = click.prompt("Please enter a description for your app",
                                                                    default=description)
                    except:
                        self.metadata["description"] = click.prompt("Please enter a description for your app",
                                                                    default="Lorem ipsum this app dolor sit amet")

                if "copyright" not in self.metadata:
                    self.metadata["copyright"] = self.metadata["author"] + ", " + str(date.today().year)

                if not glob.glob(os.path.join(self.metadata["full_path"], "APP_META*"))\
                        and not sys.argv[0].endswith(".exe"):
                    if click.confirm('Do you want to create an APP_META file. '
                                     'It will spare you these questions next time.'):
                        with open(os.path.join(self.metadata["full_path"], "APP_META"), 'w') as f:
                            for key, value in self.metadata.items():
                                # only save not changing values in APP_META
                                if key not in ["version", "org_filename", "build", "tags", "full_path", "copyright"]:
                                    f.write(key + " = " + value + "\n")

            else:
                print("This is not a frozen executable (with metadata) "
                      "and there is no GIT repository (that fits the requirements).")
                print("Metadater will now seed the application "
                      "with some default metadata values for developing purposes.")
                print("Don't use it this way in production.")

                self.metadata["repo"] = "my-app"
                self.metadata["author"] = "John Doe"
                self.metadata["version"] = "0.0.1.0"
                self.metadata["build"] = "master-0.0.1.0-1-00a00a00"
                self.metadata["org_filename"] = "my-app-master-0.0.1.0-1-00a00a00"

                self.metadata["name"] = "My App"
                self.metadata["description"] = "Lorem ipsum this app dolor sit amet"
                self.metadata["copyright"] = "John Doe, " + str(date.today().year)

    def get(self):
        """ Get all the metadata """
        return self.metadata

    def get_repo(self):
        """ Get the applications repo from metadata """
        return self.metadata["repo"]

    def get_author(self):
        """ Get the applications author from metadata """
        return self.metadata["author"]

    def get_version(self):
        """ Get the applications version from metadata """
        return self.metadata["version"]

    def get_build(self):
        """ Get the applications build from metadata """
        return self.metadata["build"]

    def get_org_filename(self):
        """ Get the applications original filename from metadata """
        return self.metadata["org_filename"]

    def get_name(self):
        """ Get the applications name from metadata """
        return self.metadata["name"]

    def get_description(self):
        """ Get the applications description from metadata """
        return self.metadata["description"]

    def get_copyright(self):
        """ Get the applications copyright from metadata """
        return self.metadata["copyright"]


if __name__ == '__main__':

    app_meta = MetaData()

    version = app_meta.get_version()
    print(version)

    meta = app_meta.get()
    for key in meta:
        print(key, meta[key])
