Metadater
=========
Package for Python providing an easy way to get a (Windows) app's version and other metadata from GIT (during development) or PE (Portable Executable) (after freezing).

https://github.com/hylkepostma/metadater

When building a Portable Executable (PE) we add metadata like the app's name and version. Most of this metadata is already available when using GIT.

Metadater provides an easy way to get this metadata from GIT and to use it in your application during development. 
When you inject these metadata fields to the PE (headers) (e.g. using Verpatch) after the freezing process (e.g. using PyInstaller) you can also retrieve this metadata after freezing your application using the same methods. See also the mapping below.

Prerequisites
-------------
1. Your project should be under version control using GIT
2. Your GIT repository should have at least one GIT commit
3. Your GIT repository should have at least one GIT tag (using SemVer)
4. There should be a valid configured GIT user.name


Installation
------------

Install package with pip:
	`pip install metadater`

Uninstall package with pip:
	`pip uninstall metadater`


Usage
-----
To get a specific metadata field
```	
$ python
>>> from metadater import MetaData
>>> metadata = MetaData()
>>> metadata.get_version() 
0.0.0.0
```
To get all metadata fields
```
$ python
>>> from metadater import MetaData
>>> metadata = MetaData().get()
>>> for field in metadata:
>>>     print(field, metadata[field])
repo my-app
author John Doe
version 0.0.1.0
build master-0.0.1.0-1-00a00a00
org_filename my-app-master-0.0.1.0-1-00a00a00
name My App
description Lorem ipsum this app dolor sit amet
copyright John Doe, 2017
```


Available methods
-----------------
* get()
* get_repo()
* get_author()
* get_version()
* get_build()
* get_org_filename()
* get_name()
* get_description()
* get_copyright()


Override using APP_META file
----------------------------
You can override or expand the GIT values using an APP_META file in your repository's root.
The file should contain the fields (and values) you want to override, like so:
```
name = Fancy Company Name - My App
author = Fancy Company Name
```


Mapping
-------

Metadater uses a Python package called `pefile` for finding metadata in the PE headers and makes it available using the following mapping:

| Metadater | PE | GIT | Example values |
| :--- | :--- | :--- | :--- |
| repo | InternalName | repo | my-app
| author | CompanyName | author | John Doe
| version | FileVersion | version | 0.0.1.0
| build | PrivateBuild | build | master-0.0.1.0-1-00a00a00
| org_filename | OriginalFilename | repo+build | my-app-master-0.0.1.0-1-00a00a00
| name | ProductName | - | My App
| description | FileDescription | - | Lorem ipsum this app dolor sit amet
| copyright | LegalCopyright | - | John Doe, 2017


Acknowledgements
----------------
https://github.com/erocarrera/pefile
https://github.com/pallets/click