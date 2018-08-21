import sys
import logging
import pefile  # for portable executable

logger = logging.getLogger(__name__)

def get_info():
    """ This takes information from your executable and makes it usable """

    try:

        pe = pefile.PE(sys.argv[0])  # sys.argv[0]

        # It is possible to access StingTable entries like this:
        logger.debug("The FileVersion of the PE is: %s" % pe.FileInfo[0][0].StringTable[0].entries[b'FileVersion'].decode('utf-8'))

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
    for key in info:
        print(key, info[key])
