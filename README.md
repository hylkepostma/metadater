# Metadater

[![Downloads](https://pepy.tech/badge/metadater)](https://pepy.tech/project/metadater)

A Python package providing an easy way to get a Windows app's version and other metadata from Git during development or from the executable after freezing.

<https://github.com/hylkepostma/metadater>

When building a portable executable (for example using [PyInstaller](https://github.com/pyinstaller/pyinstaller)) we add metadata like the app's name and version. Most of this metadata is already available when using Git.
Think for example of version numbering in Git tags and the author's name in the Git user.name setting.

Metadater provides an easy way to get this metadata from Git and to use it in your application during development.
When you inject these metadata fields to your executable after the freezing process (for example using [Verpatch](https://github.com/pavel-a/ddverpatch)) you can also retrieve this metadata after freezing your application using the same methods. See also the mapping below.

## Prerequisites

- Your project has a Git repository
- Your repository has at least one commit
- Your repository has at least one tag following the [SemVer specification](https://semver.org/)
- There is a Git user.name configured

## Installation

Using pip:

```PowerShell
pip install metadater
```

## Usage

To get a specific metadata field:

```PowerShell
$ python
>>> from metadater import MetaData
>>> metadata = MetaData()
>>> metadata.version
1.2.3
```

To get all metadata fields:
```PowerShell
$ python
>>> from metadater import MetaData
>>> metadata = MetaData().get()
>>> for field in metadata:
>>>     print(field, metadata[field])
repo metadater
author John Doe
build 1.1.0+1-g9d1df92
version_info 1.1.0+1-g9d1df92
version 1.1.0
version_4_parts 1.1.0.0
file_version 1.1.0.0
product_version 1.1.0.0
org_filename metadater-1.1.0+1-g9d1df92
name Metadater
description Lorem ipsum this app dolor sit amet
copyright John Doe, 2020
```

## Available getters

- get()
- repo
- author
- build
- version_info (returning a [VersionInfo](https://python-semver.readthedocs.io/en/latest/api.html#semver.VersionInfo) object)
- version
- version_4_parts
- file_version
- product_version
- org_filename
- name
- description
- copyright

## Override using APP_META file

You can override or expand the Git values using an APP_META file in your repository's root.
The file should contain the fields (and values) you want to override, like so:

```APP_META
name = Fancy Company Name - My App
author = Fancy Company Name
```

## Mapping

Metadater uses a Python package called `pefile` for finding metadata in the PE headers and makes it available using the following mapping:

| Metadater       | Frozen executable (PE)                | As script in Git repository                  | Example values                                                                |
|-----------------|---------------------------------------|----------------------------------------------|-------------------------------------------------------------------------------|
| repo            | InternalName                          | Name of the repository folder                | my-app                                                                        |
| author          | CompanyName                           | Git user.name                                | John Doe                                                                      |
| version_info    | [VersionInfo](https://python-semver.readthedocs.io/en/latest/api.html#semver.VersionInfo) object from parsed build  | [VersionInfo](https://python-semver.readthedocs.io/en/latest/api.html#semver.VersionInfo) object from parsed build         | VersionInfo(major=1, minor=2, patch=3, prerelease='None', build='1-00a00a00') |
| build           | PrivateBuild                          | Variation of Git describe (in SemVer format) | 1.2.3+1-00a00a00 / 1.2.3-rc1+1-00a00a00                                       |
| version         | Major.Minor.Patch from version_info   | Major.Minor.Patch from version_info          | 1.2.3                                                                         |
| version_4_parts | Major.Minor.Patch.0 from version_info | Major.Minor.Patch.0 from version_info        | 1.2.3.0                                                                       |
| file_version    | FileVersion                           | Major.Minor.Patch.0 from version_info        | 1.2.3.0                                                                       |
| product_version | ProductVersion                        | Major.Minor.Patch.0 from version_info        | 1.2.3.0                                                                       |
| org_filename    | OriginalFilename                      | repo+build                                   | my-app-1.2.3+1-00a00a00                                                       |
| name            | ProductName                           | interactive / APP_META file                  | My App                                                                        |
| description     | FileDescription                       | interactive / APP_META file                  | Lorem ipsum this app dolor sit amet                                           |
| copyright       | LegalCopyright                        | interactive / APP_META file                  | John Doe, 2017                                                                |

## Acknowledgements

- <https://github.com/erocarrera/pefile>
- <https://github.com/pallets/click>
- <https://github.com/python-semver/python-semver/>
