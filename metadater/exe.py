import sys
import pefile  # for portable executable


def get_info():
    """ This takes information from your executable and makes it usable """

    try:

        pe = pefile.PE(sys.argv[0])  # sys.argv[0]

        exe_info = {}
        for entry in pe.FileInfo:
            if hasattr(entry, 'StringTable'):
                for st_entry in entry.StringTable:
                    for item in st_entry.entries.items():
                        exe_info[item[0].decode()] = item[1].decode()

        return exe_info

    except Exception as e:
        return False


if __name__ == '__main__':

    for key in get_info():
        print(key, get_info()[key])
