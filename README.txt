Metadater
==========================

Easy way to get an app's version and other metadata from GIT (development) or PEFILE (frozen exe)


Install package with pip:
	pip install metadater

Uninstall package with pip:
	pip uninstall metadater

Usage:
	$ python
	>>> from metadater import MetaData
	>>> metadata = MetaData()
	>>> metadata.get_version() 
	'0.0.0.0'  

    	>>> metadata = MetaData().get()
   	>>> for field in metadata:
    	>>>     print(field, metadata[field])
    	'repo repo-name
     	name Repo Name
     	build master-5f26241-dirty
     	etc...'