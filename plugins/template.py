from configparser import ConfigParser
import logging
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
    return {
        PREP: prepare_configuration,
        CHECK: check_configuration,
        REPAIR: repair,
        FALLBACK: fallback,
    }

# After the configuration has been loaded we check whether the general
# necessary prerequisites have been satisfied using the function
# check_prerquisites() which stores the result in the global
# variable prerequisistes_satisfied. This variable is then checked
# in the function prepare_configuration() to determine whether the
# configuration can be executed.
# Optional: If no prerequisites have to satisfied, you can remove this 
# function and its call at the end of the file.
prerequisites_satisfied = False
def check_prerequisites() -> None:
    global prerequisites_satisfied

    # Example for checking the availability of the
    # Paho MQTT package
    # try:
    #     import paho.mqtt.subscribe as subscribe
    #     prerequisites_satisfied = True
    #     logging.debug("Optional MQTT package found.")
    # except ImportError or ModuleNotFoundError:
    #     logging.debug("No MQTT implementation found. Use 'pip3 install paho-mqtt' to install.")
    #     logging.debug("Continuing without MQTT support.")
    #     pass
    prerequisites_satisfied = True

# Prepare the specific configuration to be executed. This function checks
# whether necessary options are available and set in a correct manner,
# can convert values for better handling and generally prepares the
# configuration for an efficient execution in the check phase.
# Optional: If no preparation is necessary, you can remove this function
# and its reference in the dictionary that the function register() returns.
def prepare_configuration(section: str, config: ConfigParser) -> None:
    logging.debug("Prepare configuration %s" % config_name)
    return True

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
    # Example for executing a shell command
    # cp = subprocess.run(shlex.split(config[COMMAND]), capture_output=True)
    # return cp.returncode
    return 0

# The repair command is executed when checking the configuration hasn't been
# sucessful for more than 'timeout' seconds. This function implements the
# repair action.
# Optional: If no repair function is given in the dictionary that registers
# this configuration then the repair command will be executed as a shell
# command.
def repair(section: str, config: ConfigParser) -> int:
    logging.debug("%s: Repairing configuration with '%s'" % (config_name, config[REPAIR]))
    return 0

# If the timeout has been reached again after executing the repair command
# without the check command being successful, then the fallback action will
# be executed.
# Optional: If no falback function is given in the dictionary that registers
# this configuration then the fallback command will be executed as a shell
# command.
def fallback(section: str, config: ConfigParser) -> int:
    logging.debug("%s: Execute fallback for configuration with '%s'"
            % (config_name, config[FALLBACK]))
    return 0

###############################################################
# After the configuration has been loaded we check whether the
# necessary prerequisites have been satisfied using this call
check_prerequisites()
