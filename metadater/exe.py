import logging
import sys

import pefile

logger = logging.getLogger(__name__)


def get_info():
    """ Get information from an executable """
    try:
        pe = pefile.PE(sys.argv[0])
        # Access a StingTable entry like FileVersion:
        file_version = pe.FileInfo[0][0].StringTable[0].entries[b'FileVersion'].decode('utf-8')
        logger.debug(f"The FileVersion of the PE is: {file_version}")
        exe_info = {}
        for entry in pe.FileInfo[0]:
            if hasattr(entry, 'StringTable'):
                for st_entry in entry.StringTable:
                    for item in st_entry.entries.items():
                        exe_info[item[0].decode()] = item[1].decode()
        logger.debug("Entries in the StringTable: %s" % exe_info)
        return exe_info
    except Exception as e:
        logger.debug(e)
        return False


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    info = get_info()
    for k in info:
        print(k, info[k])
