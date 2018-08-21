import os
import logging
from subprocess import check_output
from subprocess import CalledProcessError

logger = logging.getLogger(__name__)

def get_info():
    """ This takes information from your local git repo and makes it usable """

    try:

        # save information in our git dict
        git_info = {}

        # gituser               Hylke Postma
        git_info["author"] = check_output(["git", "config", "user.name"])

        # branch			    master
        git_info["branch"] = check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])

        # version (tmp)		    1.0.2 / 2016.9.10
        git_info["version"] = check_output(["git", "describe", "--tags", "--abbrev=0", "--always"])

        # describe			    0.0.6-0-g38700ee-dirty / 2016.9.10-0-g38700ee-dirty
        git_info["describe"] = check_output(["git", "describe", "--tags", "--long", "--dirty", "--always"])

        # tags (tmp)	        1.0.2 \n 1.0.3 \n 1.0.4 / 2016.9.10 \n  2016.9.15 \n 2016.11.5
        git_info["tags"] = check_output(["git", "tag"])

        # repo (tmp)            now /path/path/boostrap-python-exe, later boostrap-python-exe
        git_info["repo"] = check_output(["git", "rev-parse", "--show-toplevel"])
        # full_path             /path/path/boostrap-python-exe
        git_info["full_path"] = git_info["repo"]  # because we want to keep the full_path

    except CalledProcessError as e:
        logger.debug(e)
        return False

    # all subprocess.check_output output is in bytes, let's decode it to utf-8 ánd strip \n
    for key in git_info:
        git_info[key] = git_info[key].decode("utf-8").strip()

    git_info["tags"] = git_info["tags"].split()

    # version   			1.0.2 --> 1.0.2.0 / 2016.9.10 --> 2016.9.10.0
    git_info["version"] += ".0.0.0.0"  # add up to four positions
    git_info["version"] = ".".join(git_info["version"].split(".")[0:4])

    # build 			    master-1.0.2-3-g6e44e35 / master-2016.9.10.0-3-g6e44e35
    git_info["build"] = git_info["branch"] + "-" + git_info["describe"]

    # repo 		            boostrap-python-exe
    git_info["repo"] = os.path.basename(os.path.normpath(git_info["repo"]))

    logger.debug("Information from Git: %s" % git_info)
    return git_info


if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG)

    info = get_info()
    for key in info:
        print(key, info[key])
