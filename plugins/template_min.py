from configparser import ConfigParser
import logging
from typing import Tuple, Dict, Any, Callable, List

# Values for the dictionary that provides implementations for
# preparation, check and repair action. Direct copy from system_watchdog.py
PREP   = "prep"
CHECK  = "check"
REPAIR = "repair"
FALLBACK = "fallback"

# The name of our configuration type as it has been loaded by the system_watchdog
config_name = ""

# This function is called by the system_watchdog to register the functions
# this configuration implementation provides.
def register(config_type: str) -> Dict[str, Callable]:
    global config_name 
    config_name = config_type
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
    return 0
