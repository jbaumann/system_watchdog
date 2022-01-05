from configparser import ConfigParser
import logging
from pathlib import Path
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

# Values for the mqtt options
SERVER = "server"
PORT = "port"
TOPIC = "topic"
CREDENTIALS = "credentials"
USER = "user"
PASSWORD = "password"

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
    }

# Check whether we can import paho.mqtt.subscribe
prerequisites_satisfied = False
def check_prerequisites() -> None:
    global prerequisites_satisfied

    # Check Paho MQTT package
    try:
        import paho.mqtt.subscribe as subscribe
        prerequisites_satisfied = True
        logging.debug("Optional MQTT package found.")
    except ImportError or ModuleNotFoundError:
        logging.debug("No MQTT implementation found. Use 'pip3 install paho-mqtt' to install.")
        logging.debug("Continuing without MQTT support.")
        pass

# Prepare the specific configuration to be executed. This function checks
# whether necessary options are available and set in a correct manner,
# can convert values for better handling and generally prepares the
# configuration for an efficient execution in the check phase.
# Optional: If no preparation is necessary, you can remove this function
# and its reference in the dictionary that the function register() returns.
def prepare_configuration(section: str, config: ConfigParser) -> None:
    if not prerequisites_satisfied:
        logging.warning("%s: No MQTT implementation found. Use 'pip3 install paho-mqtt' to install." % section)
        return False
    if not SERVER in config:
        logging.warning("%s: No '%s' option given. Aborting." % (section, SERVER))
        return False
    try:
        server_ip = socket.getaddrinfo(config[SERVER], 1883)
    except:
        logging.warning("%s: Server name '%s' cannot be found. Aborting." % (section, config[SERVER]))
        return False

    if not TOPIC in config:
        logging.warning("%s: No '%s' option given. Aborting." % (section, TOPIC))
        return False
    # config[TYPE] has already been checked
    if not config[config[TYPE]] in config:
        logging.warning("%s: No '%s' option given. Aborting." % (section, config[config[TYPE]]))
        return False
    # Do we have a credentials file?
    if CREDENTIALS in config:
        credentials = str(Path(__file__).parent.absolute()) + "/" + config[CREDENTIALS]
        try:
            with open (credentials, "r") as cred:
                lines = []
                for line in cred:
                    line = line.partition(";")[0].strip(" \n\t");
                    if line != "":
                        lines.append(line)
                config[USER] = lines[0]
                config[PASSWORD] = lines[1]
        except:
            pass
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
    import my_mqtt_subscribe as subscribe

    logging.debug("%s: Checking configuration with option '%s'" 
            % (config_name, config[config_name]))

    port = 1883
    if PORT in config:
        try:
            port = int(config[port])
        except:
            pass

    if TIME_OUT in config:
        timeout = int(config[TIME_OUT])
    else:
        timeout = general_config[TIME_OUT]

    if ',' in config[TOPIC]:
        topics = [ s.strip() for s in config[TOPIC].split(',')]
    else:
        topics = config[TOPIC]

    auth = None
    if USER in config:
        auth = []
        auth['username'] = config[USER]
        if PASSWORD in config:
            auth['password'] = config[PASSWORD]

    try:
        logging.debug("Connecting to MQTT server %s:%i" %(config[SERVER], port))
        m = subscribe.simple(topics, hostname=config[SERVER], retained=True, timeout=timeout, auth=auth)
        if m != None:
            logging.debug("%s: Received MQTT message: '%s'" % (section, m.payload))
            return 0
        else:
            logging.debug("%s: Received no MQTT message until timeout of %is" % (section, timeout))
    except Exception as e:
        logging.warning("%s: MQTT error occurred: %s" % (section, e))
        raise
    return 3

###############################################################
# After the configuration has been loaded we check whether the
# necessary prerequisites have been satisfied using this call
check_prerequisites()
