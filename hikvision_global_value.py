#!/usr/bin/env python
# -*- coding=utf-8 -*-

"""
@version: 0.0.1
@author: lee
@license: Apache Licence
@contact: shida23577@hotmail.com
@software: PyCharm
@file: hikvision_global_value.py
@time: 2016/4/27 15:31
"""

import vistek_util.PTZParser as PTZParser
import collections, base64
import os, logging, logging.handlers

try:
    from hikvision_types import *
except:
    from .hikvision_types import *

try:
    import Queue
except:
    import queue.Queue as Queue

try:
    import xml.etree.cElementTree as ET
except:
    import xml.etree.ElementTree as ET

if sys.platform == 'win32':
    DllHandle = None
else:
    DllHandle = cdll

file_name = "{0}-{1}.log".format(__name__, os.getpid())
file_path = os.path.join("log", str(os.getpid()))
try:
    if not os.path.exists(file_path):
        os.makedirs(file_path)
except:
    traceback.print_exc()
dest_file_name = os.path.join(file_path, file_name)
log_file = dest_file_name
log_level = logging.DEBUG

logger = logging.getLogger(file_name)
handler = logging.handlers.TimedRotatingFileHandler(log_file, when="H", interval=5,backupCount=1)
formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] [%(name)s] [%(filename)s:%(funcName)s:%(lineno)s]  %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(log_level)
def do_exception(event_type, user_id, handle, user):
    dev_list = get_device_lists()
    dev_status_list = get_device_status_lists()
    except_dev_list = [item for item in dev_list.values() if item.session_id == user_id]
    for item in except_dev_list:
        login_session = item
        dev_id = login_session.device_id
        logger.warn("exceptions eventtype:{0} user_id:{1} handle:{2} user:{3}".format(str(event_type), str(user_id), str(handle),
                                                                                  dev_id))
        if login_session is not None:
            device_status_node = ET.Element("device_status")
            err_code = DllHandle.NET_DVR_GetLastError()
            device_status_node.set('ip', str(login_session.ip))
            device_status_node.set('port', str(login_session.port))
            device_status_node.set('device_id', str(dev_id))
            device_status_node.set('status_id', "{0}:{1}".format(str(dev_id), str("0")))
            device_status_node.set('channel', str("0"))
            device_status_node.set('error_node', str(err_code))
            if event_type == EXCEPTION_EVENT_TYPE.EXCEPTION_RELOGIN and str(dev_status_list.get(dev_id)).lower() == 'true':
                device_status_node.text = 'false'
                dev_status_list[dev_id] = 'false'
            elif event_type == EXCEPTION_EVENT_TYPE.EXCEPTION_LOGIN_SUCCESS and not str(dev_status_list.get(dev_id)).lower() == 'false':
                device_status_node.text = 'true'
                dev_status_list[dev_id] = 'true'
            elif event_type == EXCEPTION_EVENT_TYPE.EXCEPTION_EXCHANGE and str(dev_status_list.get(dev_id)).lower() == 'false':
                device_status_node.text = 'false'
                dev_status_list[dev_id] = 'false'
            elif event_type == EXCEPTION_EVENT_TYPE.EXCEPTION_RESUME_EXCHANGE and not str(dev_status_list.get(dev_id)).lower() == 'true':
                device_status_node.text = 'true'
                dev_status_list[dev_id] = 'true'
            status_xml = ET.tostring(device_status_node, encoding='UTF-8', method='xml')
            status_queue = get_status_queue()
            logger.info("outxml:{0}".format(status_xml))
            status_queue.put(status_xml)
        else:
            return
def do_data_callback(real_handle, data_type, buffer, buffer_size, user):
    url_obj = cast(user, c_char_p)
    if V_STREAM_VALUE_TYPE.NET_DVR_SYSHEAD == data_type:
        out_str = base64.encodestring(string_at(buffer, buffer_size))
        memmove(url_obj, out_str, len(out_str))

exception_obj = ExceptionCallback(do_exception)
data_callback_obj = DataCallback(do_data_callback)

class StreamUrlC(Structure):
    _fields_ = [('url_id', c_char_p),
                ('dev_id', c_char_p),
                ('user_name', c_char_p),
                ('password', c_char_p),
                ('third_party', c_bool),
                ('stream_url_value', c_char_p),
                ('ext', c_char_p)]
    def __str__(self):
        return "{0}:{1}:{2}:{3}:{4}:{5}".format(self.url_id, self.dev_id, self.user_name, self.password\
                                                , self.third_party, self.stream_url_value, self.ext)
class StreamUrl():
    def __init__(self, id, dev_id, user_name, pwd, third_party, stream_url):
        self._url_id = id
        self._dev_id = dev_id
        self._user_name = user_name
        self._pwd = pwd
        self._third_party = third_party
        self._stream_url_value = stream_url
        self._ext = ""
    @property
    def url_id(self):
        return self._url_id

    @property
    def dev_id(self):
        return self._dev_id

    @property
    def user_name(self):
        return self._user_name

    @property
    def password(self):
        return self._pwd

    @property
    def third_party(self):
        return self._third_party

    @property
    def stream_url_value(self):
        return self._stream_url_value

    @property
    def ext(self):
        return self._ext

    @ext.setter
    def ext(self, ext):
        self._ext = base64.b64encode(ext)

device_urls = dict()# device_id urls_obj
def get_device_stream_urls():
    global device_urls
    return device_urls

device_lists = dict()#注册的设备列表 {"device_id":login_session(namedtuple)}
def get_device_lists():
    global device_lists
    return device_lists
offline_device_lists = set()#注册的设备列表 {"device_id":login_session(namedtuple)}
def get_offline_device_lists():
    global offline_device_lists
    return offline_device_lists
device_status_lists = dict()# deviceID+channel status   {"device_id/status_id":"false/true"}
def get_device_status_lists():
    global device_status_lists
    return device_status_lists

device_info_lists = dict() #deviceid deviceinfo   注册成功{"device_id":hik_device_info(struct)}
def get_device_info_list():
    global device_info_lists
    return device_info_lists

relogin_device_lists = dict()#{"device_id":login_session(namedtuple)}
def get_relogin_device_lists():
    global relogin_device_lists
    return relogin_device_lists

status_queue = Queue.Queue()
def get_status_queue():
    global status_queue
    return status_queue

cur_status_queue = Queue.Queue()
def get_cur_status_queue():
    global cur_status_queue
    return cur_status_queue

device_status_cache = dict()
def get_device_status_cache():
    global device_status_cache
    return device_status_cache

class hik_status():
    def __init__(self, ip, port, device_id):
        self._ip = ip
        self._port = port
        self._dev_id = device_id
is_start = False
device_xml_node = ET.Element('devices')

register_success_list = {}#{"device_id":login_session(namedtuple)}
def get_register_success_list():
    global register_success_list
    return register_success_list

def getCurrentDeviceInfo():
    """
    :rtype tuple all_device_count, register_success_count, reigster_faile_count, register_success_list, register_faile_list
    """
    all_device = get_device_lists()
    register_success_device = get_register_success_list()
    register_faile_device = get_relogin_device_lists()
    success_count = len(register_success_device)
    fail_count = len(register_faile_device)
    register_success_device_id_list = list((item.device_id) for item in register_success_device.values())
    if 0 < len(register_success_list):
        register_success_str = ":".join(register_success_device_id_list)
    else:
        register_success_str = ""
    register_fail_device_id_list = list((item.device_id) for item in register_faile_device.values())
    if 0 < len(register_fail_device_id_list):
        register_fail_str = ":".join(register_fail_device_id_list)
    else:
        register_fail_str = ""
    return (len(all_device), success_count, fail_count, register_success_str, register_fail_str)
