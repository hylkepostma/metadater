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
- There is a Git `user.name` and `user.email` configured

## Installation

Using pip:

```console
pip install metadater
```

## Usage

To get a specific metadata field:

```python
from metadater import MetaDater
metadata = MetaDater().metadata
print(metadata.version)
```

```stdout
1.2.3
```

```python
print(metadata.author)
```

```stdout
John Doe
```

To get all metadata fields:

```python
from metadater import MetaDater
metadata = MetaDater().get()
for field in metadata:
    print(field, metadata[field])
```

```stdout
author John Doe
build 0-g1d1757c-dirty
copyright John Doe, 2020
description Lorem ipsum this app dolor sit amet
email john@example.com
file_version 2.0.5.0
name Metadater
prerelease rc.1
product_version 2.0.5-rc.1+0-g1d1757c-dirty
repo metadater
semver 2.0.5-rc.1+0-g1d1757c-dirty
version 2.0.5
version_prerelease 2.0.5-rc.1
version_info 2.0.5-rc.1+0-g1d1757c-dirty
```

## API

### class `MetaDater`

- `metadata` contains the `MetaData` object
- `get()` returns a dictionary with all the attributes of the `MetaData` object

### class `MetaData`

- `repo`
- `name`
- `description`
- `author`
- `email` is only available in unfrozen state
- `copyright`
- `semver`
- `version_info` contains a `VersionInfo` object [(more info)](https://python-semver.readthedocs.io/en/latest/api.html#semver.VersionInfo) 
- `version`
- `prerelease`
- `build`
- `file_version`
- `product_version`
- `version_prerelease`

## Override using `metadata.json` file

You can override the Git values using an `metadata.json` file in your repository's root.
The file should contain the fields (and values) you want to override (or add), like so:

```json
{
    "author": "John Doe",
    "license": "MIT",
    "foo": "bar"
}
```

Please note that newly added values (like `license` and `foo`) are only available in unfrozen state because they lack a mapping with the PE header.

## Mapping

Metadater uses a Python package called `pefile` for finding metadata in the PE headers and makes it available using the following mapping:

| Metadater       | Frozen executable (PE)                                                                                              | As script in Git repository                                                                                         | Example values                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| repo            | InternalName                                                                                                        | Name of the repository folder                                                                                       | my-app                                                                        |
| author          | CompanyName                                                                                                         | Git user.name                                                                                                       | John Doe                                                                      |
| email          | Not available                                                                                                         | Git user.email                                                                                                       | john@example.com                                                                      |
| semver          | PrivateBuild                                                                                                        | Variation of Git describe (in SemVer format)                                                                        | 1.2.3+1-00a00a00 / 1.2.3-rc.1+1-00a00a00                                      |
| version_info    | [VersionInfo](https://python-semver.readthedocs.io/en/latest/api.html#semver.VersionInfo) object from parsed semver | [VersionInfo](https://python-semver.readthedocs.io/en/latest/api.html#semver.VersionInfo) object from parsed semver | VersionInfo(major=1, minor=2, patch=3, prerelease='rc.1', build='1-00a00a00') |
| version         | major.minor.patch from version_info                                                                                 | major.minor.patch from version_info                                                                                 | 1.2.3                                                                         |
| prerelease      | prerelease from version_info                                                                                        | prerelease from version_info                                                                                        | rc.1                                                                          |
| version_prerelease      | version-prerelease                                                                                        | version-prerelease                                                                                        | 1.2.3-rc.1                                                                          |
| build           | build from version_info                                                                                             | build from version_info                                                                                             | 1-00a00a00                                                                    |
| file_version    | FileVersion                                                                                                         | major.minor.patch.0 from version_info                                                                               | 1.2.3.0                                                                       |
| product_version | ProductVersion                                                                                                      | major.minor.patch-prerelease from version_info                                                                      | 1.2.3.0 / 1.2.3-rc.1                                                          |
| name            | ProductName                                                                                                         | interactive / APP_META file                                                                                         | My App                                                                        |
| description     | FileDescription                                                                                                     | interactive / APP_META file                                                                                         | Lorem ipsum this app dolor sit amet                                           |
| copyright       | LegalCopyright                                                                                                      | interactive / APP_META file                                                                                         | John Doe, 2020                                                                |

## Acknowledgements

- <https://github.com/erocarrera/pefile>
- <https://github.com/pallets/click>
- <https://github.com/python-semver/python-semver/>
