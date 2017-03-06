#!/usr/bin/python3
"""This is a small command line utility to automatically perform some
actions on mailman lists through the webinterface. See :func:`help`
for the usage..

.. module:: mailman-auto
   :synopsis: Poor man's mailman web interface automation.

.. moduleauthor:: Sebastian Schmittner <sebastian@schmittner.pw>


Copyright 2017 Sebastian Schmittner

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import requests
import re
from getpass import getpass
import logging
import json
import sys


class Action(object):
    """Enum of possible actions on lists. (Local problems with enum
    package...)
    """

    class NONE(object):
        pass

    class CHANGE_FOOTER:
        pass


def password_field_in_response(text):
    """Scannes a string (html response) for the occurence of a password
    prompt.

    :param str text: The (html) response to be scanned.
    :return: whether a prompt was found
    :rtype: bool
    """
    password_needed = re.search(r"([\w ]+) Password:", text)
    if password_needed:
        logging.info(
            "Need {} Password to continue.".format(password_needed.group(1)))
        return True
    return False


def login(session, list_url, password=None):
    """Read passwd from stdin if not given and login.

    :param requests.Session session: Use this session for the connection.
    :param str list_url: The url to log in to.
    :param str password: The password to be used.
    :return: success
    :rtype: bool

    """
    if not password:
        password = getpass()
    r = session.post(
        list_url, data={"adminpw": password,
                        "admlogin": "Let+me+in..."})

    if password_field_in_response(r.text):
        logging.error("Login failed")
        return False

    return True


def connect(session, base_url, list_name, password=None):
    """Connect to a list and login.

    :param requests.Session session: Use this session for the connection.
    :param str base_url: Base for the list url.
    :param str list_name: This is the list url postfix.
    :param str password: The password to be used.
    :return: success, list url
    :rtype: bool, string

    """

    list_url = base_url
    if base_url[-1] != '/':
        list_url += "/"
    list_url += list_name

    r = session.get(list_url)
    logging.info("Connected to List {}: {} {}".format(list_name, r.status_code,
                                                      r.reason))
    if password_field_in_response(r.text):
        success = login(session, list_url, password)
        if not success:
            logging.error("Log in to List {} failed.".format(list_name))
            return False

    logging.info("Logged in to list {}".format(list_name))

    return True, list_url


def change_footer(session, list_url, new_footer):
    """Change the nondigest msg_footer for the given list. Needs to be
    logged in with sufficient privilidges.

    :param requests.Session session: Use this session for the connection.
    :param str list_url: The url to log in to.
    :param str new_footer: The new footer value.
    :rtype: None

    """

    url = list_url
    if url[-1] != '/':
        url += "/"
    url += "nondigest"

    r = session.get(url)
    token_match = re.search(r'name="csrf_token"\s*value="([^"]+)"', r.text)
    if token_match:
        token = token_match.groups(1)
    else:
        raise Exception("Could not finde csrf_token in {}".format(r.text))

    post_data = {"msg_footer": new_footer, "csrf_token": token}
    r = session.post(url, data=post_data)

    logging.info("Footer changed")
    logging.debug("to '{}'".format(new_footer))


def help():
    """Print the usage message."""


def main():
    """The main function gets a list of all mailing lists on the given
    server and performs (an) action(s) on all lists.

    """
    import argparse

    logger_cfg = {
        "level":
        logging.INFO,
        "format":
        "%(asctime)s %(funcName)s (%(lineno)d) [%(levelname)s]:    %(message)s"
    }

    parser = argparse.ArgumentParser(
        description="Perform some action on all lists " +
        "at a given mailman site.")
    parser.add_argument("-u", "--url", help="The site's base url.")
    parser.add_argument(
        "-g",
        "--global-passwd",
        action='store_true',
        help="Use a global password (e.g. site admin) for all lists.")
    parser.add_argument(
        "-a",
        "--action",
        help="Which action to perform. " + "Default: CHANGE_FOOTER",
        choices=["CHANGE_FOOTER"],
        default="CHANGE_FOOTER")
    parser.add_argument(
        "-v", "--value", help="Value for the action, e.g. new footer msg.")
    parser.add_argument(
        "-l",
        "--log",
        help="Set the log level. Default: INFO.",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO")
    parser.add_argument(
        "-c",
        "--config",
        help="Read config from JSON file. " +
        "Command line arguments override parameters from this file.")

    args = parser.parse_args()

    logger_cfg["level"] = getattr(logging, args.log)
    logging.basicConfig(**logger_cfg)

    print("Log messages above level: {}".format(logger_cfg["level"]))

    config = {}

    if args.config:
        with open(args.config, "r") as cfg_file:
            config = json.load(cfg_file)

    if args.url:
        config["base_url"] = args.url

    if not config.get("base_url", None):
        logging.critical("No base url given.")
        parser.print_help()
        sys.exit(1)
    else:
        logging.info("base_url: '{}'".format(config["base_url"]))

    if args.global_passwd:
        config["use_global_passwd"] = args.global_passwd

    logging.info("use_global_passwd: '{}'".format(
        config.get("use_global_passwd", False)))

    if config.get("use_global_passwd", None)\
       and not config.get("global_passwd", None):
        config["global_passwd"] = getpass()

    if args.value:
        config["value"] = args.value

    logging.info("value: '{}'".format(config.get("value", None)))

    action = Action.NONE
    if args.action == "CHANGE_FOOTER":
        action = Action.CHANGE_FOOTER()
    elif config.get("action", None) == "CHANGE_FOOTER":
        action = Action.CHANGE_FOOTER()

    logging.info("action: '{}'".format(action))

    session = requests.Session()
    r = session.get(config["base_url"])
    list_names = re.finditer(r'href="admin/([^"]+)"', r.text)

    for match in list_names:
        # mailman polutes cookies until 400 cookies too large...
        # ->clear
        session.cookies.clear()
        list_name = match.group(1)
        logging.info("Connecting to List '{}'".format(list_name))
        success, list_url = connect(session, config["base_url"], list_name,
                                    config.get("global_passwd", None))
        if not success:
            logging.error("Could not connect to list '{}'".format(list_name))
            continue

        if isinstance(action, Action.CHANGE_FOOTER):
            change_footer(session, list_url, config["value"])
        else:
            logging.error("Action {} is not supported.".format(action))

        logging.debug("Finished actions on list {}\n".format(list_name))

    logging.info("{} lists processed.".format(len(list_names)))


# goto main
if __name__ == "__main__":
    main()
