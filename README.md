# System Watchdog
A watchdog service for Linux that monitors applications,services network connections and other things.
See the [Wiki](../../wiki) for detailed explanations.

# A short Walkthrough for the Impatient
[Walkthrough:-Installing-the-System_Watchdog-in-8-easy-steps](../../wiki/Walkthrough:-Installing-the-System_Watchdog-in-8-easy-steps)

# How does it work?
A python daemon installed as a system service checks different system aspects according to a configuration file. 
The file contains different configuration that each define commands to check that something still runs as needed, 
and if this is not the case, defines a command to be executed to repair it.

# The Configuration file
In the configuration file you have different types of configuration that can be used to implement the checks, two are used in
the following example (*command* and *network*):
```
[cmd]
type = command
command = /bin/ping -c 1 -t 10 8.8.8.8
repair = sudo systemctl restart networking
fallback action = sudo reboot
timeout = 60

[network]
type = network
network = eth0 wlan0
repair = sudo systemctl restart networking
```
The *command* type allows to define a command that is used to check whether something works.
In our example we use a ping to an IP address, and as long as that works, the service
is ok. If this does not work for the defined *timeout*, the *repair* action is executed i.e., 
the network is restarted.

The *network* type allows to check that at least one of the given network interfaces is
up and running. If none of the interfaces is up, then the *repair* action is executed.

For other types see the [Wiki](../../wiki).

# The [general] Section
In addition to the specific configurations one general section allows to define default values e.g., for the
*fallback action*, the *timeout* or the *sleep time*. Here is a simple example:
```
[general]
; This is the version of the config file syntax. This has to be
; the same as the major version of the script
version = 1
; Decides which actions are actually executed
; "unprimed" or 0 - no action
; "check" or 1 - only check action
; "repair" or 2 - check and repair action
; "fully primed" or 3 - all actions
primed = unprimed
; This is the fallback action that is executed if repairing
; was unsuccessful. Can be overwritten in specific configurations
fallback action = sudo reboot
loglevel = DEBUG
; The daemon sleeps between checks for this time in seconds
sleep time = 20
; The default timeout for determining whether repair is necessary.
; Can be overwritten in individual configurations.
timeout = 60
```

# Limitations
Currently the script is limited to Linux-type operating systems. Getting rid of this limitation would mean that we have to install additional python packages with 'pip3', which I try to avoid for the time being.
