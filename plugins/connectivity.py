from configparser import ConfigParser
import logging
import socket
from typing import Tuple, Dict, Any, Callable, List

# Values for the dictionary that provides implementations for
# preparation, check and repair action. Direct copy from system_watchdog.py
PREP   = "prep"
CHECK  = "check"
REPAIR = "repair"
FALLBACK = "fallback"

# Values for general options
TYPE = "type"
TIME_OUT = "timeout"

# The name of our configuration type as it has been loaded by the system_watchdog
config_name = ""
general_config = None

# This function is called by the system_watchdog to register the functions
# this configuration implementation provides.
def register(config_type: str, g_conf: Dict[str, Any]) -> Dict[str, Callable]:
    global config_name, general_config
    config_name = config_type
    general_config = g_conf
    logging.debug("registering implementation for '%s'", config_name)
    return { CHECK: check_configuration }

# The actual check of the configuration should be implemented as efficient
# as possible, since it will be executed every 'sleep time' seconds.
# Different return values can be used to signal the time interval that
# had to be used to verify that the check was not successful.
# Return values:
# 0    the check was successful
# 1    the check was not successful and took no relevant time
# 2    the check was not successful and took 'sleep time' seconds
# 3    the check was not sucessful and took 'timeout' seconds
#
# This function is mandatory
def check_configuration(section: str, config: ConfigParser) -> int:
    logging.debug("%s: Checking configuration with option '%s'"
            % (config_name, config[config_name]))
    # This implementation is Linux-specific
    ip_address = config[config[TYPE]]

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        s.connect((ip_address, 1))  # connect() for UDP doesn't send packets
        local_ip_address = s.getsockname()[0]
        if local_ip_address != "0.0.0.0":
            # success
            logging.debug("%s: Local ip address is %s" % (section, local_ip_address))
            return 0
    except:
        pass
    # we could not get a local ip address
    logging.debug("%s: No local ip address can be acquired." % section)
    return 1
