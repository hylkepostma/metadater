import sys
import pefile  # for portable executable


def get_info():
    """ This takes information from your executable and makes it usable """

    try:

        pe = pefile.PE(sys.argv[0])  # sys.argv[0]
        exe_info = {}
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        exe_info[entry[0]] = entry[1]

        return exe_info

    except Exception as e:
        return False


if __name__ == '__main__':

    for key in get_info():
        print(key, get_info()[key])
