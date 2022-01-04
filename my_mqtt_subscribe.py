# Copyright (c) 2016 Roger Light <roger@atchoo.org>
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License v2.0
# and Eclipse Distribution License v1.0 which accompany this distribution.
#
# The Eclipse Public License is available at
#    http://www.eclipse.org/legal/epl-v10.html
# and the Eclipse Distribution License is available at
#   http://www.eclipse.org/org/documents/edl-v10.php.
#
# Contributors:
#    Roger Light - initial API and implementation
#    Joachim Baumann - added timeout to simple()
# JB added timeout to simple() function and the callback
#    and implemented communication between _on_message_simple()
#    and callback via a lock in userdata

from __future__ import absolute_import

from paho import mqtt
from paho.mqtt import client as paho
from paho.mqtt.subscribe import _on_connect, _on_connect_v5
from threading import Lock
import time

LOCK = 'lock'

def _on_message_callback(client, userdata, message):
    """Internal callback"""
    userdata['callback'](client, userdata['userdata'], message, userdata[LOCK])

def _on_message_simple(client, userdata, message, lock):
    """Internal callback"""


    if userdata['msg_count'] == 0:
        return

    # Don't process stale retained messages if 'retained' was false
    if message.retain and not userdata['retained']:
        return

    userdata['msg_count'] = userdata['msg_count'] - 1

    if userdata['messages'] is None and userdata['msg_count'] == 0:
        userdata['messages'] = message
        client.disconnect()
        if lock:
            lock.release()
        return

    userdata['messages'].append(message)
    if userdata['msg_count'] == 0:
        if lock:
            lock.release()
        client.disconnect()

def callback(callback, topics, qos=0, userdata=None, hostname="localhost",
             port=1883, client_id="", keepalive=60, will=None, auth=None,
             tls=None, protocol=paho.MQTTv311, transport="tcp",
             clean_session=True, proxy_args=None, timeout=None):

    if qos < 0 or qos > 2:
        raise ValueError('qos must be in the range 0-2')

    lock = None
    if not timeout is None:
        lock = Lock()

    callback_userdata = {
        'callback':callback,
        'topics':topics,
        'qos':qos,
        LOCK:lock,
        'userdata':userdata}

    client = paho.Client(client_id=client_id, userdata=callback_userdata,
                         protocol=protocol, transport=transport,
                         clean_session=clean_session)
    client.on_message = _on_message_callback
    if protocol == mqtt.client.MQTTv5:
        client.on_connect = _on_connect_v5
    else:
        client.on_connect = _on_connect

    if proxy_args is not None:
        client.proxy_set(**proxy_args)

    if auth:
        username = auth.get('username')
        if username:
            password = auth.get('password')
            client.username_pw_set(username, password)
        else:
            raise KeyError("The 'username' key was not found, this is "
                           "required for auth")

    if will is not None:
        client.will_set(**will)

    if tls is not None:
        if isinstance(tls, dict):
            insecure = tls.pop('insecure', False)
            client.tls_set(**tls)
            if insecure:
                # Must be set *after* the `client.tls_set()` call since it sets
                # up the SSL context that `client.tls_insecure_set` alters.
                client.tls_insecure_set(insecure)
        else:
            # Assume input is SSLContext object
            client.tls_set_context(tls)

    client.connect(hostname, port, keepalive)

    if timeout == None:
        client.loop_forever()
    else:
        lock.acquire()
        client.loop_start()
        lock.acquire(timeout=timeout)
        client.loop_stop()
        client.disconnect()


def simple(topics, qos=0, msg_count=1, retained=True, hostname="localhost",
           port=1883, client_id="", keepalive=60, will=None, auth=None,
           tls=None, protocol=paho.MQTTv311, transport="tcp",
           clean_session=True, proxy_args=None, timeout=None):

    if msg_count < 1:
        raise ValueError('msg_count must be > 0')

    # Set ourselves up to return a single message if msg_count == 1, or a list
    # if > 1.
    if msg_count == 1:
        messages = None
    else:
        messages = []

    userdata = {'retained':retained, 'msg_count':msg_count, 'messages':messages}

    callback(_on_message_simple, topics, qos, userdata, hostname, port,
             client_id, keepalive, will, auth, tls, protocol, transport,
             clean_session, proxy_args, timeout)

    return userdata['messages']