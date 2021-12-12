#!/usr/bin/python3 -u

# Author Joachim Baumann

from argparse import ArgumentParser, Namespace
from configparser import ConfigParser
import logging
import os
from pathlib import Path
import socket
import shlex
import subprocess
import sys
import time
import threading
from typing import Tuple, Dict, Any, Callable

MAJOR = 1
MINOR = 0
PATCH = 3
version = "%i.%i.%i" % (MAJOR, MINOR, PATCH)

# Defaults for values in the general section
GENERAL_SECTION = "general"
PRIMED = "primed"
FALLBACK_ACTION = "fallback action"
LOG_LEVEL = "loglevel"
SLEEP_TIME = "sleep time"
TIME_OUT = "timeout"
TYPE = "type"
COMMAND = "command"
REPAIR = "repair"
VERSION = "version"
general_config = {
    PRIMED : 0,
    FALLBACK_ACTION : "sudo reboot",
    LOG_LEVEL : "DEBUG",
    SLEEP_TIME : 20,
    TIME_OUT : 120,
    VERSION : -1,
}

# Values for mapping the different primed levels to numerical values
UNPRIMED = "unprimed"
CHECK_ONLY = "check"
REPAIR_ONLY = "repair"
FULLY_PRIMED = "fully primed"
primed_level = {
    UNPRIMED : 0,
    CHECK_ONLY : 1,
    REPAIR_ONLY : 2,
    FULLY_PRIMED : 3,
}

def main(*args: Tuple[str]):
    # Startup of the daemon

    args = parse_cmdline(args)
    setup_logger(args.nodaemon)
    logging.debug("Setup complete")

    config = ConfigParser(allow_no_value=True)
    if args.cfgfile:
        configfile_name = args.cfgfile
    else:
        configfile_name = str(Path(__file__).parent.absolute()) + "/system_watchdog.cfg"
        logging.debug("Path to config file %s" % configfile_name)

    if not os.path.isfile(configfile_name):
            logging.info("No Config File. Aborting.")
            quit(1)
    else:
        try:
            config.read(configfile_name)
            logging.debug("Config has been read.")
        except Exception as err:
            logging.error(err)
            logging.error("Cannot read config file. Aborting.")
            quit(1)

    # Now interpret the config file
    # We should have one section that configures general values.
    if GENERAL_SECTION in config:
        for entry in config[GENERAL_SECTION]:
            general_config[entry] = config[GENERAL_SECTION][entry]
    else:
        logging.error("No [%s] section in config file %s. Aborting." % (GENERAL_SECTION, configfile_name))
        quit(1)
    logging.getLogger().setLevel(general_config[LOG_LEVEL])
    if int(general_config[VERSION]) != MAJOR:
        logging.error("Version mismatch in config file. Need version '%i'. Aborting." % MAJOR)
        quit(1)

    # Convert the entries in the [general] section into entries in
    # general_config that can be used directly
    try:
        error = PRIMED
        if general_config[PRIMED] in primed_level:
            general_config[PRIMED] = primed_level[general_config[PRIMED]]
        else:
            general_config[PRIMED] = int(general_config[PRIMED])
        error = SLEEP_TIME
        general_config[SLEEP_TIME] = int(general_config[SLEEP_TIME])
        error = TIME_OUT
        general_config[TIME_OUT] = int(general_config[TIME_OUT])
    except Exception as err:
        logging.error("Config option %s has the wrong format. Aborting.", error)
        quit(1)
    # Go through all sections and start a thread for each configuration,
    # ignoring the general section.
    for section in config.sections():
        if section == GENERAL_SECTION: continue

        #a few sanity checks for the current configuration
        if TYPE not in config[section]:
            logging.warning("%s: No type defined in section. Ignoring section." % section)
            continue
        if FALLBACK_ACTION not in config[section]:
            config[section][FALLBACK_ACTION] = general_config[FALLBACK_ACTION]

        section_type = config[section][TYPE]
        if section_type in entry_type_implementation:
            # We have an implementation for the current entry
            entry = entry_type_implementation[section_type]
            if callable(entry):
                # we have a single function as entry
                new_thread = threading.Thread(target=entry, name=section, 
                                args=(section, config[section]))
                new_thread.start()
            elif type(entry) is str:
                # we have a string to print
                logging.warning("Type '%s' in section '%s': '%s'." % (config[section][TYPE], section, entry))
            elif type(entry) is dict:
                # we have a dictionary using the standard thread function
                new_thread = threading.Thread(target=thread_impl, name=section, 
                                args=(section, entry, config[section]))
                new_thread.start()

            else:
                # this should never happen
                logging.error("Internal error: unknown type entry '%s' in command table in section '%s': '%s'." % (config[section][TYPE], section, entry))
        else:
            logging.warning("Type '%s' in section '%s' unknown." % (config[section][TYPE], section))

    # We have started all configurations, in the main thread we regularly
    # log the list of active threads as DEBUG statements. If we are interrupted
    # by Ctrl-C we terminate this thread, the others will see that the main
    # thread no longer runs and will terminate themselvers as well.
    try:
        # the main thread is always part of the active threads
        while threading.active_count() > 1:
            thread_names = ""
            for thread in threading.enumerate():
                if thread.name != "MainThread":
                    thread_names = thread_names + "'" + thread.name + "' "
            logging.debug("Active Configurations: %i - %s" % (threading.active_count() - 1, thread_names) )
            time.sleep(general_config[SLEEP_TIME])
    except KeyboardInterrupt:
        logging.info("Terminating: cleaning up and exiting - configurations will exit after sleep time")

# Helper Functions and Classes
def parse_cmdline(args: Tuple[str]) -> Namespace:
    arg_parser = ArgumentParser(description='System Watchdog v' + version)
    arg_parser.add_argument('--cfgfile', metavar='file', required=False,
                            help='full path and name of the configfile')
    arg_parser.add_argument('--nodaemon', required=False, action='store_true',
                            help='use normal output formatting')
    return arg_parser.parse_args(args)

def setup_logger(nodaemon: bool) -> None:
    root_log = logging.getLogger()
    root_log.setLevel("DEBUG")
    if not nodaemon:
        root_log.addHandler(SystemdHandler())

# This is the Log Handler that prints the messages to /var/log/syslog
# if we run as a daemon
class SystemdHandler(logging.Handler):
    # http://0pointer.de/public/systemd-man/sd-daemon.html
    PREFIX = {
        # EMERG <0>
        # ALERT <1>
        logging.CRITICAL: "<2>",
        logging.ERROR: "<3>",
        logging.WARNING: "<4>",
        # NOTICE <5>
        logging.INFO: "<6>",
        logging.DEBUG: "<7>",
        logging.NOTSET: "<7>"
    }
    def __init__(self, stream=sys.stdout):
        self.stream = stream
        logging.Handler.__init__(self)

    def emit(self, record):
        try:
            msg = self.PREFIX[record.levelno] + self.format(record)
            msg = msg.replace("\n", "\\n")
            self.stream.write(msg + "\n")
            self.stream.flush()
        except Exception:
            self.handleError(record)

# Generic thread implementations for the different watchdog entries
# This is used if a dict of callbacks is used in the entry_type_implementation
def thread_impl(section: str, callback: Dict[str, Callable], config: ConfigParser) -> None:
    last_success = 0
    tried_fix = False
    fix_available = True

    if TIME_OUT in config:
        timeout = int(config[TIME_OUT])
    else:
        timeout = general_config[TIME_OUT]
    
    # verify the command and repair option are set in the config
    msg = "%s: No '%s' option given."
    if config[TYPE] not in config:
        logging.warning((msg + " Aborting.") % (section, config[TYPE]))
        return
    if REPAIR not in config:
        fix_available = False
        logging.info((msg + " Using global fallback.") % (section, REPAIR))

    # main loop for the thread. Runs indefinitely
    while True:
        # Check until the timeout whether the check command can be
        # executed successfully
        while last_success < timeout:
            # Check whether main thread still runs. If not, terminate.
            main_alive = threading.main_thread().is_alive()
            if not main_alive:
                logging.info("Configuration '%s' terminating." % section)
                return
            # As long as the callback for the check command
            # returns 0 everything is hunky dory

            return_code = 0
            if general_config[PRIMED] >= primed_level[CHECK_ONLY]:
                logging.debug("%s: Executing '%s'" % (section, config[config[TYPE]]))
                return_code = callback[COMMAND](section, config)
            else:
                logging.debug("%s: Not executing '%s'. Primed value too low." % (section, config[config[TYPE]]))

            if return_code != 0:
                last_success += general_config[SLEEP_TIME]
                logging.debug("%s: check %s unsuccessful. Last success: %i" 
                        % (section, config[TYPE], last_success))
            else:
                last_success = 0
                tried_fix = False
                logging.debug("%s: check %s successful." 
                        % (section, config[TYPE]))

            time.sleep(general_config[SLEEP_TIME])

        # Timeout has been reached. If we haven't tried to repair the
        # service yet, then we try the given repair statement
        # After executing this statement timers are set back to 0 and
        # we try the check command again until another timeout is reached
        if not tried_fix and fix_available:
            last_success = 0
            tried_fix = True
            logging.warning("%s: Trying to repair with '%s'" % (section, config[REPAIR]))
            return_code = 0
            if general_config[PRIMED] >= primed_level[REPAIR_ONLY]:
                logging.debug("%s: Executing '%s'" % (section, config[REPAIR]))
                return_code = callback[REPAIR](section, config)
            else:
                logging.debug("%s: Not executing '%s'. Primed value too low." % (section, config[REPAIR]))

            if return_code != 0:
                logging.warning("%s: repair '%s' unsuccessful" % (section, config[REPAIR]))
            else:
                logging.info("%s: repair '%s' successful" % (section, config[REPAIR]))

        else:
            # Timeout has been reached twice, the repair was unsuccessful,
            # and now we try the fallback action.
            last_success = 0
            tried_fix = False
            logging.warning("%s: Trying fallback action '%s'" 
                        % (section, config[FALLBACK_ACTION]))

            if general_config[PRIMED] >= primed_level[FULLY_PRIMED]:
                cp = subprocess.run(shlex.split(config[FALLBACK_ACTION]), capture_output=True)
                if cp.returncode != 0:
                    logging.warning("%s: Fallback action '%s' unsuccessful" 
                                % (section, config[FALLBACK_ACTION]))
            else:
                logging.debug("%s: Not executing '%s'. Primed value too low." % (section, config[FALLBACK_ACTION]))

# Implementation of the Callbacks
def generic_repair(section: str, config: ConfigParser) -> int:
    cp = subprocess.run(shlex.split(config[REPAIR]), capture_output=True)
    return cp.returncode

# Implementation of the Command Callbacks
def command_check(section: str, config: ConfigParser) -> int:
    cp = subprocess.run(shlex.split(config[COMMAND]), capture_output=True)
    return cp.returncode

# Implementation of the Network Callbacks
def network_check(section: str, config: ConfigParser) -> int:
    interfaces = config[config[TYPE]].split();

    result = 1
    for if_name in interfaces:
        # This implementation is Linux-specific.
        # We could use netiface, but that would need an installation via pip
        if_path = "/sys/class/net/" + if_name + "/flags"
        if os.path.exists(if_path):
            logging.debug("%s: Interface %s exists." % (section, if_name))
            try:
                with open(if_path, 'r') as file:
                    data = file.read().rstrip()
                    if int(data, 16) & 0x1:
                        logging.debug("%s: Interface %s is active." % (section, if_name))
                        result = 0
                        break
            except IOError:
                pass
        else:
            logging.debug("%s: Interface %s does not exist." % (section, if_name))

    return result

# Implementation of the Connectivity Callbacks
def connectivity_check(section: str, config: ConfigParser) -> int:
    # This implementation is Linux-specific
    ip_address = config[config[TYPE]];

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip_address, 1))  # connect() for UDP doesn't send packets
    local_ip_address = s.getsockname()[0]
    if local_ip_address != "0.0.0.0":
        # success
        logging.debug("%s: Local ip address is %s" % (section, local_ip_address))
        return 0
    # we could not get a local ip address
    logging.debug("%s: No local ip address can be acquired." % section)
    return 1

# Implementation mapping
# This table provides the mapping from the type of the configuration to
# the implementation of either the callbacks (in a dict), 
# a function (function pointer), 
# or a string to print
entry_type_implementation = {
    "command" : { COMMAND : command_check, REPAIR : generic_repair },
    "script"  : { COMMAND : command_check, REPAIR : generic_repair },
    "network" : { COMMAND : network_check, REPAIR : generic_repair },
    "connectivity" : { COMMAND : connectivity_check, REPAIR : generic_repair },
    "device"  : "Entry type not implemented yet",
}

if __name__ == '__main__':
    main(*sys.argv[1:])
