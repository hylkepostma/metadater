import logging
from subprocess import CalledProcessError
from subprocess import check_output
from typing import Dict

logger = logging.getLogger(__name__)


def get_info() -> Dict[str, str]:
    """ Get information from the local git repository """
    try:
        git_info = {
            "author": check_output(["git", "config", "user.name"]),
            "branch": check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
            "tags": check_output(["git", "tag"]),
            "last_tag": check_output(["git", "describe", "--tags", "--abbrev=0", "--always"]),
            "describe": check_output(["git", "describe", "--tags", "--long", "--dirty", "--always"]),
            "full_path": check_output(["git", "rev-parse", "--show-toplevel"])
        }
        # All subprocess.check_output output is in bytes, let's decode it to utf-8 ánd strip \n
        for key in git_info:
            git_info[key] = git_info[key].decode("utf-8").strip()
        logger.debug("Information from Git: %s" % git_info)
        return git_info
    except CalledProcessError as e:
        logger.debug(e)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    info = get_info()
    for k in info:
        print(k, info[k])
