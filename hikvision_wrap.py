#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, os, collections, threading, time, traceback, os
import logging, os, logging.handlers
import Vistek.Data as v_data
import Vistek.Data as v_device
import hikvision_global_value
import threadpool
import eventlet
import objgraph, gc
import line_profiler

import vistek_util.workTemplate as work_template

from eventlet import greenpool
from hikvision_types import *
from ctypes import *

try:
    import xml.etree.cElementTree as ET
except:
    import xml.etree.ElementTree as ET

try:
    import Queue
except:
    import queue as Queue

def get_ptz_cmd_map():
    global ptz_cmd_map
    return ptz_cmd_map
#from memory_profiler import profile
file_name = "{0}-{1}.log".format(__name__, os.getpid())
file_path = os.path.join("log", str(os.getpid()))
try:
    if not os.path.exists(file_path):
        os.makedirs(file_path)
except:
    traceback.print_exc()
dest_file_name = os.path.join(file_path, file_name)
log_file = dest_file_name
#log_level = logging.DEBUG
log_level = logging.INFO

logger = logging.getLogger(file_name)
handler = logging.handlers.TimedRotatingFileHandler(log_file, when="H", interval=5,backupCount=1)
formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] [%(name)s] [%(filename)s:%(funcName)s:%(lineno)s]  %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(log_level)

DeviceCategory=collections.namedtuple('DeviceCategory','CategoryID CategoryCode CategoryName BasicFlag')
IPTYPE=DeviceCategory(CategoryID="dc7031cb-3230-11e3-8a00-000af7160515",CategoryCode="IPC",CategoryName="网络摄像机(IPC)",BasicFlag=102)
DVRTYPE=DeviceCategory(CategoryID="59f9c9cf-3230-11e3-8a00-000af7160515",CategoryCode="DVR",CategoryName="硬盘刻录机(DVR)",BasicFlag=110)
NVRTYPE=DeviceCategory(CategoryID="dc5458f3-3230-11e3-8a00-000af7160515",CategoryCode="NVR",CategoryName="网络录像机(NVR)",BasicFlag=110)
BAYONETTYPE=DeviceCategory(CategoryID="4169188a-39a1-4ef4-9b6e-f798e292c1d1",CategoryCode="BAYNOET",CategoryName="交通卡口(Bayonet)",BasicFlag=118)
DEFAULTTYPE=DeviceCategory(CategoryID="59f9c9cf-3230-11e3-8a00-000af7160515",CategoryCode="DVR",CategoryName="硬盘刻录机(DVR)",BasicFlag=110)
DEVICE_CATEGORY={"IP CAMERA":IPTYPE,"DVR":DVRTYPE,"Network Video Recorder":NVRTYPE,"IP CAPTURE CAMERA":BAYONETTYPE,"DEFAULT":IPTYPE}

class HikvisionStatus(object):
    def __init__(self, device_id, ip, port, username, password):
        self._device_id = device_id
        self._ip = ip
        self._port = port
        self._username = username
        self._password = password
        self._status_list = {}

    def add_status(self, status):
        """
        :param status dict  channel:tuple(status_info)(status:error_code)
        :rtype int status_count
        """
        if status is not None:
            self._status_list.update(status)
        return len(self._status_list)

    def pop_status(self, status):
        """
        :param status dict  channel:tuple(status_info)(status:error_code)
        :rtype dict current status count
        """
        if status is not None and isinstance(status, dict):
            for key, item in status.items():
                pop_items[key] = item
                self._status_list.pop(key)
        return len(self._status_list)

def get_all_status_callback(request, result):
    insert_list = []
    insert_list.append(result)
    # print ("result:{0}".format(result))
    # logger.info("result:{0}".format(result))
    hikvision_global_value.get_cur_status_queue().put(insert_list)


def load_dll(dll_name):
    DllHandle = hikvision_global_value.DllHandle
    if DllHandle is not None:
        return DllHandle
    else:
        if sys.platform == 'win32':
            other_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'HCNetSDKCom'))
            other_lib = os.path.abspath(os.path.join(os.path.dirname(__file__), 'HCCore'))
            sys.path.append(other_path)
            other_dll_handle = WinDLL(other_lib)
            dll_handle = WinDLL(dll_name)
        else:
            dll_handle = CDLL(dll_name)

    b_init = dll_handle.NET_DVR_Init()
    if b_init:
        return dll_handle
    else:
        logger.debug("init fail")
        return None


class ReLoginThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def run(self):
        DllHandle = hikvision_global_value.DllHandle
        device_lists = hikvision_global_value.get_device_lists()
        relogin_device_lists = hikvision_global_value.get_relogin_device_lists()
        is_start = hikvision_global_value.is_start
        while True:
            try:
                if sys.platform == 'win32':
                    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'HCNetSDK'))
                    DllHandle = load_dll(dll_path)
                relogin_dev_lists = hikvision_global_value.get_relogin_device_lists()
                for id, device in relogin_dev_lists.items():
                    hik_login_info = NET_DVR_USER_LOGIN_INFO()
                    hik_device_info = NET_DVR_DEVICEINFO_V40()
                    memset(addressof(hik_device_info), 0, sizeof(NET_DVR_DEVICEINFO_V40))
                    memset(addressof(hik_login_info), 0, sizeof(NET_DVR_USER_LOGIN_INFO))
                    hik_login_info.s_DeviceAddress = device.ip
                    hik_login_info.wPort = device.port
                    hik_login_info.sUserName = device.user
                    hik_login_info.sPassword = device.pwd
                    login_id = DllHandle.NET_DVR_Login_V40(pointer(hik_login_info), pointer(hik_device_info))
                    if login_id != -1:
                        relogin_device_lists.pop(id)
                        old_device = device_lists.get(id)
                        status_list = hikvision_global_value.get_device_status_lists()
                        if id not in status_list:
                            status_list[id] = "true"
                        else:
                            status_list.update({id:"true"})
                        login_session = Session(device_id=id, session_id=login_id, ip=device.ip, port=device.port\
                                                , user=device.user, pwd=device.pwd)
                        #old_device.session_id = login_id
                        device_lists.update({id:login_session})
                        dev_info_list = hikvision_global_value.get_device_info_list()
                        if id not in dev_info_list:
                            dev_info_list[id] = hik_device_info
                        user_obj = cast(id, c_char_p)
                        exception_obj = hikvision_global_value.exception_obj
                        # exception_ret = DllHandle.NET_DVR_SetExceptionCallBack_V30(0, None, exception_obj, user_obj)
                        logger.warn("relogin success id:{0} ip:{1} port:{2} user:{3} pwd:{4} pid:{5} threadid:{6}"\
                                    .format(str(id)\
                                    , str(device.ip)\
                                    , str(device.port)\
                                    , str(device.user)\
                                    , str(device.pwd)\
                                    , os.getpid()\
                                    , threading.currentThread().ident))
                        DllHandle.NET_DVR_SetConnectTime(5000, 3)
                        DllHandle.NET_DVR_SetReconnect(5000, 1)

                        result_xml = get_device_status(device_id=device.device_id)
                        cur_queue = hikvision_global_value.get_status_queue()
                        if isinstance(result_xml, tuple) and 0 < len(result_xml[0]):
                            device_status_list_node = ET.fromstring(result_xml[0])
                            if device_status_list_node is not None:
                                for device_status_node in device_status_list_node.iterfind("device_status"):
                                    if device_status_node is not None:
                                        node_str = ET.tostring(device_status_node, encoding="UTF-8", method="xml")
                                        if node_str is not None and 0 < len(node_str):
                                            logger.info("put device status ip:{0} pid:{1} threadid:{2}".format(device.ip\
                                                                                                               , os.getpid()\
                                                                                                               , threading.currentThread().ident))
                                            cur_queue.put(node_str)
                time.sleep(5)
            except:
                traceback.print_exc()

#@profile
def push_channel_status_of_offline_device(device_id,device_channel_list):
    device_lists = hikvision_global_value.get_device_lists()
    device_status_queue=hikvision_global_value.get_status_queue()
    dev_status_list_node = ET.Element("device_status_list")
    device_login_info=device_lists.get(device_id)
    dev_status_list_node.set("dev_count", str(len(device_channel_list)))
    for channel in device_channel_list:
        device_status_node = ET.SubElement(dev_status_list_node, "device_status")
        device_status_node.text = 'false'
        device_status_node.set('ip', str(device_login_info.ip))
        device_status_node.set('port', str(device_login_info.port))
        device_status_node.set('device_id', str(device_id))
            # device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(dest_channel)))
            # device_status_node.set('channel', str(dest_channel))
        device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(channel.ChannelIndex)))
        device_status_node.set('channel', str(channel.ChannelIndex))
        device_status_node.set('error_node', "110")
    for channel in dev_status_list_node.iterfind("device_status"):
        if channel is not None:
            node_str = ET.tostring(channel, encoding="UTF-8", method="xml")
            if node_str is not None and 0 < len(node_str):
                device_status_queue.put(node_str)

def register_device(device_id, ip, port, user_name, user_pwd,device_channel_list):
    """
注册设备，登录到device_id,如果登录成功，则注册设备成功，{"device_id":login_session(namedtuple)} 放入到register_success_device_list中
同时将{"device_id":hik_device_info(struct)}写入到device_info_list字典中
如果设备注册失败，将{"device_id":login_session(namedtuple)}为device_id放入到再次待注册的设备列表中relogin_device_lists中
无论注册失败成功，都将{"device_id":login_seddion(namedtuple)}放入到设备列表中device_list
将注册信息，将{"devi ce_id/status_id":"false/true"}写入到device_status_lists

生成的XML文档
<?xml version='1.0' encoding='UTF-8'?>
<devices counts="1">
	<device belogin="True" dev_id="xxxx" ip="172.16.1.192" manfacture="hikvision" name="xxxx" port="8000" />
	......
</devices>

<register>
	<ip>172.16.1.192</ip>
	<session>session_id</session>
</register>
.....


<device_status_list dev_count='IPChanNum'>
	<device_status ip="";port="";device_id:"";status_id:"IPChanNum+i";channel:"IPChanNum+i";error_code:"">true/false</device_status>
	.........
</device_status_List>
    """
    """ register a hikvision device"""
    DllHandle = hikvision_global_value.DllHandle
    register_success_device_list = hikvision_global_value.get_register_success_list()
    device_lists = hikvision_global_value.get_device_lists()
    is_start = hikvision_global_value.is_start
    exception_obj = hikvision_global_value.exception_obj
    relogin_device_lists = hikvision_global_value.get_relogin_device_lists()
    status_lists = hikvision_global_value.get_device_status_lists()
    dev_info_list = hikvision_global_value.get_device_info_list()
    device_xml_node = hikvision_global_value.device_xml_node

    if sys.platform == 'win32':
        dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'HCNetSDK'))
        DllHandle = load_dll(dll_path)
        if DllHandle is not None:
            hikvision_global_value.DllHandle = DllHandle
    register_node = ET.Element('register')
    ip_node = ET.SubElement(register_node, 'ip')
    ip_node.text = ip
    session_node = ET.SubElement(register_node, 'session')
    if device_id not in device_lists:
        hik_login_info = NET_DVR_USER_LOGIN_INFO()
        hik_device_info = NET_DVR_DEVICEINFO_V40()
        memset(addressof(hik_device_info), 0, sizeof(NET_DVR_DEVICEINFO_V40))
        memset(addressof(hik_login_info), 0, sizeof(NET_DVR_USER_LOGIN_INFO))
        hik_login_info.s_DeviceAddress = ip
        hik_login_info.wPort = port
        hik_login_info.sUserName = user_name
        hik_login_info.sPassword = user_pwd
        login_id = DllHandle.NET_DVR_Login_V40(pointer(hik_login_info), pointer(hik_device_info))
        login_session = Session(device_id=device_id, session_id=login_id, ip=ip, port=port, user=user_name,
                                pwd=user_pwd)
        device_lists[device_id] = login_session
        hikvision_global_value.device_xml_node.set("counts", str(len(device_lists)))
        device_node = ET.SubElement(device_xml_node, 'device')
        device_node.set('name', device_id)
        device_node.set('dev_id', device_id)
        device_node.set('manfacture', 'hikvision')
        device_node.set('ip', ip)
        device_node.set('port', str(port))
        tree = ET.ElementTree(device_xml_node)
        if login_id == -1:
            device_node.set("belogin", str(False))
            logger.error("device_id:{0} ip{1} user:{2} pwd:{3} register failed error:{4} pid:{5} threadid:{6}."\
                         .format(device_id\
                         , ip\
                         , user_name\
                         , user_pwd \
                         , DllHandle.NET_DVR_GetLastError()\
                         , os.getpid()\
                         , threading.currentThread().ident))
            if device_id not in relogin_device_lists:
                relogin_device_lists[device_id] = login_session
            status_lists[device_id] = "false"
            #若登录失败，获取设备通道列表，将通道状态都置为false
            push_channel_status_of_offline_device(device_id,device_channel_list)
        else:
            device_node.set("belogin", str(True))
            DllHandle.NET_DVR_SetConnectTime(5000, 3)
            DllHandle.NET_DVR_SetReconnect(5000, 1)
            #exception_ret = DllHandle.NET_DVR_SetExceptionCallBack_V30(0, None, exception_obj, None)
            #user_obj = cast(device_id, c_char_p)
            # exception_ret = DllHandle.NET_DVR_SetExceptionCallBack_V30(0, None, exception_obj, None)
            if device_id not in register_success_device_list:
                register_success_device_list[device_id] = login_session
            if 0 < hik_device_info.struDeviceV30.byIPChanNum:
                for item in xrange(0, hik_device_info.struDeviceV30.byIPChanNum):
                    status_id = "{0}:{1}".format(device_id, item)
                    if status_id not in status_lists:
                        status_lists[status_id] = "true"
            elif 0 < hik_device_info.struDeviceV30.byChanNum:
                for item in xrange(0, hik_device_info.struDeviceV30.byChanNum):
                    status_id = "{0}:{1}".format(device_id, item)
                    if status_id not in status_lists:
                        status_lists[status_id] = "true"
            if device_id not in dev_info_list:
                dev_info_list[device_id]= hik_device_info
            logger.info(
                "device_id:{0} ip:{1} user:{2} pwd:{3} id:{4} count:{5} pid:{6} threadid:{7} register success."\
                    .format(device_id\
                    , ip\
                    , user_name\
                    , user_pwd\
                    , login_id\
                    , len(device_lists)\
                    , os.getpid()\
                    , threading.currentThread().ident))

        session_node.text = str(login_id)
        tree.write('device_lists.xml', encoding="UTF-8")

    else:
        login_session = device_lists.get(device_id)
        session_node.text = str(login_session.session_id)
    session_xml = ET.tostring(register_node, encoding="UTF-8", method="xml")
    ####
    result_xml = get_device_status(device_id=device_id)
    cur_queue = hikvision_global_value.get_status_queue()
    if isinstance(result_xml, tuple) and 0 < len(result_xml[0]):
        device_status_list_node = ET.fromstring(result_xml[0])
        if device_status_list_node is not None:
            for device_status_node in device_status_list_node.iterfind("device_status"):
                if device_status_node is not None:
                    node_str = ET.tostring(device_status_node, encoding="UTF-8", method="xml")
                    if node_str is not None and 0 < len(node_str):
                        logger.info("put device status id:{0} ip:{1}".format(device_id, ip))
                        cur_queue.put(node_str)
        else:
            logger.warn("deviceid:{0} ip:{1} parser string fail!!".format(device_id, ip))
    else:
        logger.warn("deviceid:{0} ip:{1} get status fail!!".format(device_id, ip))
    ####
    if not hikvision_global_value.is_start:
        t = StartServerThread()
        t.start()
        offline_thrd=OfflineDeviceStatus()
        offline_thrd.start()
        relogin_thrd = ReLoginThread()
        relogin_thrd.start()
        t_check_change = StartCheckThread()
        t_check_change.start()
        hikvision_global_value.is_start = True
    return (session_xml, len(session_xml))

def _make_hik_stream_url(dev_id, ip, port, username, password, channel, stream_type):
    protocol_name = "hikdvr"
    url = "{0}://{1}:{2}/realplay?did={3}&un={4}&pw={5}&ch={6}&si={7}".format(protocol_name, ip, port, dev_id\
                                                                              , username, password, channel, stream_type)
    url_id = "{0}:{1}:{2}".format(dev_id, channel, stream_type)
    return {url_id:url}

#@profile
def get_stream_url(device_id, channel=None):
    """
    根据device_id从device_lists中获取登录信息，然后获取每个通道的流地址，放入到全局device_urls中
    :param device_id:设备ID
    :param channel: URL
    :return: (urls.xml,strlen(urls.xml)
    """
    device_lists = hikvision_global_value.get_device_lists()
    DllHandle = hikvision_global_value.DllHandle
    dev_info_list = hikvision_global_value.get_device_info_list()
    cur_urls = hikvision_global_value.device_urls

    if not device_lists.has_key(device_id):
        return ('', 0)

    if device_id in cur_urls:
        urls = ET.Element('stream_url_lists')
        urls.set("counts", str(len(cur_urls)))
        for url_id, url_item in cur_urls.get(device_id).items():
            url = ET.SubElement(urls, 'stream_url')
            url.text = url_item.stream_url_value
            url.set("id", str(url_id))
            url.set("user_name", str(url_item.user_name))
            url.set("password", str(url_item.password))
            url.set("third_party", str(url_item.third_party))
        urls_xml = ET.tostring(urls, encoding='UTF-8', method='xml')
        return (urls_xml, len(urls_xml))

    login_session = device_lists.get(device_id)
    hik_rtsp = NET_DVR_RTSPCFG()
    memset(addressof(hik_rtsp), 0 , sizeof(NET_DVR_RTSPCFG))
    # ret = DllHandle.NET_DVR_GetRtspConfig(login_session.session_id, 0, byref(hik_rtsp), sizeof(NET_DVR_RTSPCFG))
    ret = DllHandle.NET_DVR_GetRtspConfig(login_session.session_id, 0, pointer(hik_rtsp), sizeof(NET_DVR_RTSPCFG))
    if not ret:
        err_code = DllHandle.NET_DVR_GetLastError()
        logger.error("get rtsp port error device_id:{0} sessionId:{1} errcode:{2} pid:{3} threadid:{4}."\
                     .format(device_id, login_session.session_id, err_code, os.getpid(), threading.currentThread().ident))
        hik_rtsp.wPort = 554
    stream_urls = dict()
    hik_stream_urls = dict()
    dev_info = dev_info_list.get(device_id)
    if device_id in dev_info_list:
        ip_access_cfg = NET_DVR_IPPARACFG_V40()
        memset(addressof(ip_access_cfg), 0, sizeof(NET_DVR_IPPARACFG_V40))
        dw_ret = c_ulong()
        ret = DllHandle.NET_DVR_GetDVRConfig(login_session.session_id, 1062, 0, pointer(ip_access_cfg),
                                             sizeof(NET_DVR_IPPARACFG_V40), pointer(dw_ret))
        if 1 < dev_info.struDeviceV30.byIPChanNum:  # nvr or dvr.
            for item in xrange(0, dev_info.struDeviceV30.byIPChanNum):
                if ip_access_cfg.struStreamMode[item].uGetStream.struChanInfo.byEnable:
                    channel_index = dev_info.struDeviceV30.byStartDChan + item
                    if dev_info.struDeviceV30.bySupport &0x80 == 0:#not support rtsp over rtp.
                        if  dev_info.struDeviceV30.byMultiStreamProto &0x40 ==1:#support main stream.
                            main_hik_url = _make_hik_stream_url(device_id, login_session.ip, login_session.port,\
                                                                login_session.user, login_session.pwd, channel_index, 0)
                            #stream_urls.update(main_hik_url)
                            hik_stream_urls.update(main_hik_url)
                        if dev_info.struDeviceV30.byMultiStreamProto &0x80 ==1:#support sub stream.
                            sub_hik_url = _make_hik_stream_url(device_id, login_session.ip, login_session.port \
                                                                , login_session.user, login_session.pwd, channel_index, 1)
                            #stream_urls.update(sub_hik_url)
                            hik_stream_urls.update(sub_hik_url)
                    else:

                        url_main = "rtsp://{0}:{1}@{2}:{3}/h264/ch{4}/main/av_stream".format(str(login_session.user),
                                                                                             str(login_session.pwd),
                                                                                             str(login_session.ip),
                                                                                             str(hik_rtsp.wPort),
                                                                                             str(channel_index))
                        #url_main_id = "{0}:{1}:{2}".format(device_id, channel_index, "0")
                        url_main_id = "{0}:{1}:{2}".format(device_id, item, "0")
                        if url_main_id not in stream_urls:
                            stream_urls[url_main_id] = url_main
                        url_sub = "rtsp://{0}:{1}@{2}:{3}/h264/ch{4}/sub/av_stream".format(str(login_session.user),
                                                                                           str(login_session.pwd),
                                                                                           str(login_session.ip),
                                                                                           str(hik_rtsp.wPort),
                                                                                           str(channel_index))
                        #url_sub_id = "{0}:{1}:{2}".format(device_id, channel_index, "1")
                        url_sub_id = "{0}:{1}:{2}".format(device_id, item, "1")
                        if url_sub_id not in stream_urls:
                            stream_urls[url_sub_id] = url_sub
            logger.debug('get_stream_url success dvr dev_id:{0} ip:{1} urls:{2}'.format(device_id, login_session.ip,
                                                                                        str(stream_urls)))
        elif 1 < dev_info.struDeviceV30.byChanNum:
            for item in xrange(0, dev_info.struDeviceV30.byChanNum):
                channel_index = dev_info.struDeviceV30.byStartChan + item
                if 0 == ret:#not support ip access
                    if dev_info.struDeviceV30.bySupport &0x80 == 0:#not support rtsp over rtp.
                        #if  dev_info.struDeviceV30.byMultiStreamProto &0x40 ==1:#support main stream.
                        main_hik_url = _make_hik_stream_url(device_id, login_session.ip, login_session.port, \
                                                            login_session.user, login_session.pwd, channel_index, 0)
                        #stream_urls.update(main_hik_url)
                        hik_stream_urls.update(main_hik_url)
                        #if dev_info.struDeviceV30.byMultiStreamProto &0x80 ==1:#support sub stream.
                        sub_hik_url = _make_hik_stream_url(device_id, login_session.ip, login_session.port \
                                                           , login_session.user, login_session.pwd, channel_index, 1)
                        #stream_urls.update(sub_hik_url)
                        hik_stream_urls.update(sub_hik_url)
                else:
                    if ip_access_cfg.byAnalogChanEnable[item]:
                        if dev_info.struDeviceV30.bySupport &0x80 == 0:#not support rtsp over rtp.
                            if  dev_info.struDeviceV30.byMultiStreamProto &0x40 ==1:#support main stream.
                                main_hik_url = _make_hik_stream_url(device_id, login_session.ip, login_session.port, \
                                                                    login_session.user, login_session.pwd, channel_index, 0)
                                #stream_urls.update(main_hik_url)
                                hik_stream_urls.update(main_hik_url)
                            if dev_info.struDeviceV30.byMultiStreamProto &0x80 ==1:#support sub stream.
                                sub_hik_url = _make_hik_stream_url(device_id, login_session.ip, login_session.port \
                                                                   , login_session.user, login_session.pwd, channel_index, 1)
                                hik_stream_urls.update(sub_hik_url)
                                #stream_urls.update(sub_hik_url)
            logger.debug('get_stream_url success dvr dev_id:{0} ip:{1} urls:{2}'.format(device_id, login_session.ip,
                                                                                        str(hik_stream_urls)))
        else:  # ipc
            channel_index = 1
            url_main = "rtsp://{0}:{1}@{2}:{3}/h264/ch{4}/main/av_stream".format(str(login_session.user),
                                                                                 str(login_session.pwd),
                                                                                 str(login_session.ip),
                                                                                 str(hik_rtsp.wPort),
                                                                                 str(channel_index))
            url_main_id = "{0}:{1}:{2}".format(device_id, channel_index, "0")
            if url_main_id not in stream_urls:
                stream_urls[url_main_id] = url_main
            url_sub = "rtsp://{0}:{1}@{2}:{3}/h264/ch{4}/sub/av_stream".format(str(login_session.user),
                                                                               str(login_session.pwd),
                                                                               str(login_session.ip),
                                                                               str(hik_rtsp.wPort),
                                                                               str(channel_index))
            url_sub_id = "{0}:{1}:{2}".format(device_id, channel_index, "1")
            if url_sub_id not in stream_urls:
                stream_urls[url_sub_id] = url_sub
            logger.debug('get_stream_url success ipc dev_id:{0} ip:{1} urls:{2}'.format(device_id, login_session.ip, str(stream_urls)))
    if 1 > len(stream_urls) and 1 > len(hik_stream_urls):
        return ("", 0)
    urls = ET.Element('stream_url_lists')
    urls.set("counts", str(len(stream_urls)))
    dest_stream_urls = {}
    for url_id, item in stream_urls.items():
        url = ET.SubElement(urls, 'stream_url')
        url.text = item
        url.set("id", str(url_id))
        url.set("user_name", str(login_session.user))
        url.set("password", str(login_session.pwd))
        url.set("third_party", str(False))
        stream_url = hikvision_global_value.StreamUrl(id=url_id, dev_id=device_id, user_name=login_session.user,\
                                                      pwd=login_session.pwd, third_party=False, stream_url=item)
        dest_stream_urls.update({stream_url._url_id:stream_url})
    for url_id, item in hik_stream_urls.items():
        url = ET.SubElement(urls, 'stream_url')
        url.text = item
        url.set("id", str(url_id))
        url.set("user_name", str(login_session.user))
        url.set("password", str(login_session.pwd))
        url.set("third_party", str(True))
        stream_url = hikvision_global_value.StreamUrl(id=url_id, dev_id=device_id, user_name=login_session.user, \
                                                      pwd=login_session.pwd, third_party=False, stream_url=item)
        dest_stream_urls.update({stream_url._url_id:stream_url})
    if device_id not in hikvision_global_value.device_urls:
        hikvision_global_value.device_urls.update({device_id: dest_stream_urls})

    hik_stream_urls.clear()
    stream_urls.clear()
    urls_xml = ET.tostring(urls, encoding='UTF-8', method='xml')
    return (urls_xml, len(urls_xml))

def start_play(device_id, channel, stream_type, url_obj):
    dev_lists = hikvision_global_value.device_lists
    dll_handle = hikvision_global_value.DllHandle
    call_back_obj = hikvision_global_value.data_callback_obj
    login_session = dev_lists.get(device_id)
    prew_info = NET_DVR_PREVIEWINFO()
    memset(addressof(prew_info), 0, sizeof(NET_DVR_PREVIEWINFO))
    prew_info.lChannel = channel
    prew_info.dwStreamType = stream_type
    prew_info.byPreviewMode = 0
    prew_info.bBlocked = 0
    user_obj = cast(addressof(url_obj), c_void_p)
    if login_session is not None:
        ret = dll_handle.NET_DVR_RealPlay_V40(login_session.session_id, pointer(prew_info), call_back_obj, user_obj)
        if ret == -1:
            logger.error("start play failed, channel:{0} stream_type:{1}".format(channel, stream_type))
            return ret
        else:
            logger.info("start play success, channel:{0} stream_type:{1}".format(channel, stream_type))
            return ret

def stop_play(play_id):
    dev_lists = hikvision_global_value.device_lists
    dll_handle = hikvision_global_value.DllHandle
    dll_handle.NET_DVR_StopRealPlay()
    pass

def get_device_status_ext(device_id, channel=None):
    """ get device status"""
    device_lists = hikvision_global_value.get_device_lists()
    DllHandle = hikvision_global_value.DllHandle
    dev_info_list =  hikvision_global_value.get_device_info_list()
    session_id = None
    if DllHandle is None or device_id not in device_lists:
        return None
    else:
        session_id = device_lists.get(device_id).session_id
    remote_login_info = device_lists.get(device_id)
    if channel is None:
        channel = c_ulong(0xffffffff)
    if dev_info is None:
        return None
    try:
        dev_status_list_node = ET.Element("device_status_list")
        if dev_info is not None and 1 < dev_info.struDeviceV30.byIPChanNum:#nvr.
            bright_value = contrast_value = saturation_value = hue_value = c_ushort()
            dev_status_list_node.set("dev_count", str(dev_info.struDeviceV30.byIPChanNum))
            for item in xrange(0, dev_info.struDeviceV30.byIPChanNum):
                dest_channel = dev_info.struDeviceV30.byStartDChan+item
                tmp_ret = DllHandle.NET_DVR_GetVideoEffect(session_id, dest_channel, pointer(bright_value), pointer(contrast_value),
                                                           pointer(saturation_value), pointer(hue_value))
                err_code = ""
                device_status_node = ET.SubElement(dev_status_list_node, "device_status")
                if tmp_ret:
                    device_status_node.text = 'true'
                else:
                    device_status_node.text = 'false'
                    err_code = DllHandle.NET_DVR_GetLastError()
                device_status_node.set('ip', str(remote_login_info.ip))
                device_status_node.set('port', str(remote_login_info.port))
                device_status_node.set('device_id', str(device_id))
                # device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(dest_channel)))
                # device_status_node.set('channel', str(dest_channel))
                device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(item)))
                device_status_node.set('channel', str(item))
                device_status_node.set('error_node', str(err_code))
            status_xml = ET.tostring(dev_status_list_node, encoding='UTF-8', method='xml')
            return (status_xml, len(status_xml))
        else:#ipc
            cur_time = NET_DVR_TIME()
            memset(addressof(cur_time), 0, sizeof(NET_DVR_TIME))
            dev_info = dev_info_list.get(device_id)
            ret = c_ulong()
            tmp_ret = DllHandle.NET_DVR_GetDVRConfig(session_id, 118, channel, pointer(cur_time), sizeof(NET_DVR_TIME),
                                                     pointer(ret))
            out_str = "dll:{0} handle:{1} ret:{2}".format(str(DllHandle), str(session_id), str(tmp_ret))
            dest_channel = 0
            for item in xrange(0, dev_info.struDeviceV30.byChanNum):#nvr or dvr.
                device_status_node = ET.SubElement(dev_status_list_node, 'device_status')
                err_code = ""
                if tmp_ret:
                    device_status_node.text = 'true'
                    #dest_channel = dev_info.struDeviceV30.byStartChan
                else:
                    device_status_node.text = 'false'
                    err_code = DllHandle.NET_DVR_GetLastError()
                device_status_node.set('ip', str(remote_login_info.ip))
                device_status_node.set('port', str(remote_login_info.port))
                device_status_node.set('device_id', str(device_id))
                device_status_node.set('channel', str(dest_channel))
                device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(dest_channel)))
                device_status_node.set('error_node', str(err_code))
                dest_channel += 1
            status_xml = ET.tostring(dev_status_list_node, encoding='UTF-8', method='xml')
            logger.info("get status id:{0} ip:{1} ret:{2} value:{3}, handle:{4} threadid:{5}.".format(str(device_id), str(remote_login_info.ip),
                                                                                                      str(tmp_ret), str(status_xml),
                                                                                                      str(session_id), threading.currentThread().ident))
            return (status_xml, len(status_xml))
    except:
        traceback.print_exc()
        return ('', 0)
#@profile
def get_device_status(device_id, channel=None):
    """ get device status"""
    device_lists = hikvision_global_value.get_device_lists()
    offline_device_lists = hikvision_global_value.get_offline_device_lists()
    DllHandle = hikvision_global_value.DllHandle
    dev_info_list =  hikvision_global_value.get_device_info_list()
    if not device_lists.has_key(device_id):
        logger.warn("id{0} not in device lists.".format(device_id))
        return ("", 0)
    remote_login_info = device_lists.get(device_id)
    session_id = None
    if DllHandle is None or device_id not in device_lists:
        return ("", 0)
    else:
        session_id = device_lists.get(device_id).session_id
    if channel is None:
        channel = c_ulong(0xffffffff)
    cur_time = NET_DVR_TIME()
    memset(addressof(cur_time), 0, sizeof(NET_DVR_TIME))
    dev_info = None
    if device_id in dev_info_list:
        dev_info = dev_info_list.get(device_id)
    else:
        return ("", 0)
    try:
        dev_status_list_node = ET.Element("device_status_list")
        if dev_info is not None and 1 < dev_info.struDeviceV30.byIPChanNum:#nvr.
            bright_value = contrast_value = saturation_value = hue_value = c_ushort()
            dev_status_list_node.set("dev_count", str(dev_info.struDeviceV30.byIPChanNum))
            for item in xrange(0, dev_info.struDeviceV30.byIPChanNum):
                dest_channel = dev_info.struDeviceV30.byStartDChan+item
                tmp_ret = DllHandle.NET_DVR_GetVideoEffect(session_id, dest_channel, pointer(bright_value), pointer(contrast_value),
                                       pointer(saturation_value), pointer(hue_value))
                err_code = ""
                device_status_node = ET.SubElement(dev_status_list_node, "device_status")
                if tmp_ret:
                    device_status_node.text = 'true'
                    if device_id in offline_device_lists:
                        offline_device_lists.remove(device_id)
                else:
                    device_status_node.text = 'false'
                    err_code = DllHandle.NET_DVR_GetLastError()
#                    if err_code==7:
                    offline_device_lists.add(device_id)
                device_status_node.set('ip', str(remote_login_info.ip))
                device_status_node.set('port', str(remote_login_info.port))
                device_status_node.set('device_id', str(device_id))
                # device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(dest_channel)))
                # device_status_node.set('channel', str(dest_channel))
                device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(item)))
                device_status_node.set('channel', str(item))
                device_status_node.set('error_node', str(err_code))
            status_xml = ET.tostring(dev_status_list_node, encoding='UTF-8', method='xml')
            return (status_xml, len(status_xml))
        else:#ipc
            ret = c_ulong()
            tmp_ret = DllHandle.NET_DVR_GetDVRConfig(session_id, 118, channel, pointer(cur_time), sizeof(NET_DVR_TIME),
                                                     pointer(ret))
            out_str = "dll:{0} handle:{1} ret:{2}".format(str(DllHandle), str(session_id), str(tmp_ret))
            logger.info("put str:{0}".format(out_str))
            dest_channel = 0
            for item in xrange(0, dev_info.struDeviceV30.byChanNum):#nvr or dvr.
                device_status_node = ET.SubElement(dev_status_list_node, 'device_status')
                err_code = ""
                if tmp_ret:
                    device_status_node.text = 'true'
                    #dest_channel = dev_info.struDeviceV30.byStartChan
                else:
                    device_status_node.text = 'false'
                    err_code = DllHandle.NET_DVR_GetLastError()
                device_status_node.set('ip', str(remote_login_info.ip))
                device_status_node.set('port', str(remote_login_info.port))
                device_status_node.set('device_id', str(device_id))
                device_status_node.set('channel', str(dest_channel))
                device_status_node.set('status_id', "{0}:{1}".format(str(device_id), str(dest_channel)))
                device_status_node.set('error_node', str(err_code))
                dest_channel += 1
            status_xml = ET.tostring(dev_status_list_node, encoding='UTF-8', method='xml')
            logger.info("get status id:{0} ip:{1} ret:{2} value:{3}, handle:{4} threadid:{5}.".format(str(device_id), str(remote_login_info.ip),
                                                                                 str(tmp_ret), str(status_xml),
                                                                                 str(session_id), threading.currentThread().ident))
            return (status_xml, len(status_xml))
    except:
        traceback.print_exc()
        return ('', 0)


#@profile
def unregister_device(device_id):
    """ unregister a hikvision device"""
    DllHandle = hikvision_global_value.DllHandle
    cur_device_lists = hikvision_global_value.get_device_lists()
    cur_status_device_lists = hikvision_global_value.get_device_status_lists()
    if device_id in cur_device_lists:
        if DllHandle.NET_DVR_Logout(cur_device_lists.get(device_id).session_id):
            logger.debug("deviceID:{0} logout success".format(device_id, cur_device_lists.get(device_id).session_id))
        else:
            logger.error("deviceID:{0} logout failed".format(device_id, cur_device_lists.get(device_id).session_id))
        cur_device_lists.pop(device_id)
        for key in cur_status_device_lists.keys():
            if device_id in key:
                cur_status_device_lists.pop(key)


##------ PTZ Begin -------


def ptz(device_id, cmd, *args, **kwargs):
    dev_lists = hikvision_global_value.get_device_lists()
    if device_id in dev_lists:
        session_info = dev_lists.get(device_id)
        handle = session_info.session_id
        cmd_map = get_ptz_cmd_map()
        if cmd in cmd_map:
            func = cmd_map.get(cmd)
            return func(handle, *args, **kwargs)
    return False
        #session_info.session_id


def move_left(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.PAN_LEFT, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move left\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move left success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_right(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.PAN_RIGHT, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move right\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move right success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_up(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.TILT_UP, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move up\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move up success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_down(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.TILT_DOWN, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move down\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move down success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_left_up(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.LEFT_UP, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move left up\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move left up success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_left_down(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.LEFT_DOWN, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move left down\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move left down success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_right_up(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.RIGHT_UP, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move right up\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move right up success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def move_right_down(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.RIGHT_DOWN, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, move right down\
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("move right down success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def zoom_in(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.ZOOM_IN, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, zoom in \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("zoom in success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def zoom_out(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.ZOOM_OUT, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, zoom out \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("zoom out success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def focus_far(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.FOCUS_FAR, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, focus far \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("focus far success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def focus_near(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.FOCUS_NEAR, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, focus near \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("focus near success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def iris_open(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.IRIS_OPEN, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, iris open \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("iris open success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def iris_close(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.IRIS_CLOSE, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, iris close \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("iris close success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def heater(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    """
    """
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.HEATER_PWRON, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, heater \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("heater success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def light(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.LIGHT_PWRON, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, light \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("light success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def wiper(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.WIPER_PWRON, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, wiper \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("wiper success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def fan(handle, speed, b_stop, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    dest_speed = int(7*speed)
    if handle is not None and 1 <= dest_speed and 7 >= dest_speed and channel is not None:
        ret = DllHandle.NET_DVR_PTZControlWithSpeed_Other(handle, int(channel), V_PTZ_CMD_TYPE.FAN_PWRON, b_stop, dest_speed)
        if not ret:
            err_code = c_long()
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.warning("NET_DVR_PTZControlWithSpeed_Other failed, fan \
handle:{0} channel:{1} speed:{2} b_stop:{3} errNo:{4}".format(handle, channel, dest_speed, b_stop, err_code))
        else:
            logger.info("fan success handle:{0} channel:{1} speed:{2} b_stop:{3}".format(handle, channel, dest_speed, b_stop))
            return True
    return False

def preset_add(handle, index, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    if handle is not None and channel is not None and 0 < index and 300 > index:
        ret = DllHandle.NET_DVR_PTZPreset_Other(handle, int(channel), V_PTZ_CMD_TYPE.SET_PRESET, index)
        if not ret:
            logger.warning("NET_DVR_PTZPreset_Other failed, errNo:{0}".format(DllHandle.NET_DVR_GetLastError()))
        else:
            return True
    return False

def preset_del(handle, index, channel=None, **kwargs):
    DllHandle = hikvision_global_value.DllHandle
    if handle is not None and channel is not None and 0 < index and 300 > index:
        ret = DllHandle.NET_DVR_PTZPreset_Other(handle, int(channel), V_PTZ_CMD_TYPE.DEL_PRESET, index)
        if not ret:
            logger.warning("NET_DVR_PTZPreset_Other failed, errNo:{0}".format(DllHandle.NET_DVR_GetLastError()))
        else:
            return True
    return False

def preset_goto():
    DllHandle = hikvision_global_value.DllHandle
    if handle is not None and channel is not None and 0 < index and 300 > index:
        ret = DllHandle.NET_DVR_PTZPreset_Other(handle, int(channel), V_PTZ_CMD_TYPE.GOTO_PRESET, index)
        if not ret:
            logger.warning("NET_DVR_PTZPreset_Other failed, errNo:{0}".format(DllHandle.NET_DVR_GetLastError()))
        else:
            return True
    return False

ptz_cmd_map = {V_PTZ_CMD_TYPE.PAN_LEFT: move_left, V_PTZ_CMD_TYPE.PAN_RIGHT:move_right, V_PTZ_CMD_TYPE.TILT_UP:move_up,
               V_PTZ_CMD_TYPE.TILT_DOWN:move_down, V_PTZ_CMD_TYPE.LEFT_UP:move_left_up,
               V_PTZ_CMD_TYPE.LEFT_DOWN: move_left_down, V_PTZ_CMD_TYPE.RIGHT_UP:move_right_up,
               V_PTZ_CMD_TYPE.RIGHT_DOWN:move_right_down, V_PTZ_CMD_TYPE.ZOOM_IN:zoom_in,
               V_PTZ_CMD_TYPE.ZOOM_OUT:zoom_out, V_PTZ_CMD_TYPE.FOCUS_FAR:focus_far,
               V_PTZ_CMD_TYPE.FOCUS_NEAR:focus_near, V_PTZ_CMD_TYPE.IRIS_OPEN:iris_open,
               V_PTZ_CMD_TYPE.IRIS_CLOSE:iris_close, V_PTZ_CMD_TYPE.HEATER_PWRON:heater,
               V_PTZ_CMD_TYPE.LIGHT_PWRON:light, V_PTZ_CMD_TYPE.WIPER_PWRON:wiper,
               V_PTZ_CMD_TYPE.FAN_PWRON:fan, V_PTZ_CMD_TYPE.SET_PRESET:preset_add,
               V_PTZ_CMD_TYPE.CLE_PRESET:preset_del, V_PTZ_CMD_TYPE.GOTO_PRESET:preset_goto}

##------ PTZ End   -------


##----- try check device is can process -----
def add_device_category(IPChanNum,ChanNum,wDevType,Device):
    if Device.DeviceCategory is None:
        Device.DeviceCategory=v_data.DmDeviceCategory()
    if (IPChanNum>0 and ChanNum>0) or (IPChanNum==0 and ChanNum>1):
        Device.DeviceCategory.CategoryID = DEVICE_CATEGORY["DVR"].CategoryID
        Device.DeviceCategory.CategoryCode = DEVICE_CATEGORY["DVR"].CategoryCode
        Device.DeviceCategory.CategoryName = DEVICE_CATEGORY["DVR"].CategoryName
        Device.DeviceCategory.BasicFlag = DEVICE_CATEGORY["DVR"].BasicFlag
    elif IPChanNum>0 and ChanNum==0:
        Device.DeviceCategory.CategoryID = DEVICE_CATEGORY["Network Video Recorder"].CategoryID
        Device.DeviceCategory.CategoryCode = DEVICE_CATEGORY["Network Video Recorder"].CategoryCode
        Device.DeviceCategory.CategoryName = DEVICE_CATEGORY["Network Video Recorder"].CategoryName
        Device.DeviceCategory.BasicFlag = DEVICE_CATEGORY["Network Video Recorder"].BasicFlag
    elif wDevType in (NET_DVR_DEV_TYPE.ITCCAM,NET_DVR_DEV_TYPE.IVS_IPCAM):
        Device.DeviceCategory.CategoryID = DEVICE_CATEGORY["IP CAPTURE CAMERA"].CategoryID
        Device.DeviceCategory.CategoryCode = DEVICE_CATEGORY["IP CAPTURE CAMERA"].CategoryCode
        Device.DeviceCategory.CategoryName = DEVICE_CATEGORY["IP CAPTURE CAMERA"].CategoryName
        Device.DeviceCategory.BasicFlag = DEVICE_CATEGORY["IP CAPTURE CAMERA"].BasicFlag
    else:
        Device.DeviceCategory.CategoryID = DEVICE_CATEGORY["IP CAMERA"].CategoryID
        Device.DeviceCategory.CategoryCode = DEVICE_CATEGORY["IP CAMERA"].CategoryCode
        Device.DeviceCategory.CategoryName = DEVICE_CATEGORY["IP CAMERA"].CategoryName
        Device.DeviceCategory.BasicFlag = DEVICE_CATEGORY["IP CAMERA"].BasicFlag





#@profile
def try_process_device(device):
    logger.info("try start id:{0} ip:{1}".format(device.DeviceID, device.IP))
    device_id = device.DeviceID
    ip = device.IP
    port = device.Port
    user = device.Username
    pwd = device.Password
    # global DllHandle
    if sys.platform == 'win32':
        dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'HCNetSDK'))
        DllHandle = load_dll(dll_path)
        hik_login_info = NET_DVR_USER_LOGIN_INFO()
        hik_device_info = NET_DVR_DEVICEINFO_V40()
        memset(addressof(hik_device_info), 0, sizeof(NET_DVR_DEVICEINFO_V40))
        memset(addressof(hik_login_info), 0, sizeof(NET_DVR_USER_LOGIN_INFO))
        hik_login_info.s_DeviceAddress = ip
        hik_login_info.wPort = port
        hik_login_info.sUserName = user
        hik_login_info.sPassword = pwd
        logger.info("try login hikevison")
        login_id = DllHandle.NET_DVR_Login_V40(pointer(hik_login_info), pointer(hik_device_info))
        logger.info("try type:{0}".format(str(login_id)))
        if login_id == -1:
            err_code = DllHandle.NET_DVR_GetLastError()
            logger.error("device_id:{0} ip{1} user:{2} pwd:{3} err:{4} pid:{5} threadid:{6} try process failed.".format(\
                device_id, ip, user, pwd, err_code, os.getpid(), threading.currentThread().ident))
            return (device_id, False, 0, "hikvision")
        else:
            device.Manufacture = "hikvision"
            channel_list = list()
            if not device.ChannelList:
                device.ChannelList = channel_list
            if device:
                device.ProtocolFlag = 1
            if 0 < hik_device_info.struDeviceV30.byIPChanNum:
                ip_access_cfg = NET_DVR_IPPARACFG_V40()
                memset(addressof(ip_access_cfg), 0, sizeof(NET_DVR_IPPARACFG_V40))
                dw_ret = c_ulong()
                ret = DllHandle.NET_DVR_GetDVRConfig(login_id, 1062, 0, pointer(ip_access_cfg), sizeof(NET_DVR_IPPARACFG_V40), pointer(dw_ret))
                start_index = 0
                for item in xrange(0, hik_device_info.struDeviceV30.byIPChanNum):#nvr or 混合型DVR
                    #if ip_access_cfg.struStreamMode[item].uGetStream.struChanInfo.byEnable:
                        # print("ip:{0}channel:{1}user:{2}pwd:{3}port:{4}".format(ip_access_cfg.struIPDevInfo[item].struIP.sIpV4,
                        #                                                  ip_access_cfg.struStreamMode[item].uGetStream.struChanInfo.byChannel,
                        #                                                  str(ip_access_cfg.struIPDevInfo[item].sUserName.value),
                        #                                                  str(ip_access_cfg.struIPDevInfo[item].sPassword.value),
                        #                                                  ip_access_cfg.struIPDevInfo[item].wDVRPort))
                    ip = str(ip_access_cfg.struIPDevInfo[item].struIP.sIpV4)
                    channel = v_data.DmDeviceVideoChannel()
                    #channel.ChannelIndex = hik_device_info.struDeviceV30.byStartDChan + item
                    channel.ChannelIndex = start_index + item
                    channel.Name = "{0}-{1}".format(ip, channel.ChannelIndex)
                    if device.DeviceID:
                        channel.DeviceID = device.DeviceID
                    if device is not None:
                        channel_list.append(channel)
            else:
                channel_num = hik_device_info.struDeviceV30.byChanNum
                #channel_index = hik_device_info.struDeviceV30.byStartChan
                channel_index = 0
                while channel_num > 0:
                    channel = v_data.DmDeviceVideoChannel()
                    channel.ChannelIndex = channel_index
                    channel.Name = "{0}-{1}".format(ip, channel.ChannelIndex)
                    if device.DeviceID:
                        channel.DeviceID = device.DeviceID
                    if device:
                        channel_list.append(channel)
                    channel_num -= 1
                    channel_index += 1
            add_device_category(hik_device_info.struDeviceV30.byIPChanNum,hik_device_info.struDeviceV30.byChanNum,hik_device_info.struDeviceV30.wDevType,device)
            DllHandle.NET_DVR_Logout(login_id)
            logger.info("device_id:{0} ip{1} user:{2} pwd:{3} pid:{4} threadid:{5} try process success." \
                        .format(device_id, ip, user, pwd, os.getpid(), threading.currentThread().ident))
            # logger.info("device_id:{0} ip{1} user:{2} pwd:{3} try process success, device:{4}."\
            #             .format(device_id, ip, user, pwd, device))
            return (device_id, True, 1, "hikvision")
    else:
        logger.warning("linux process")
        return (device_id, False, 0, "hikvision")

##----- try check device is can process end -----
##--------------------------------------------------------
def start_server():
    logger.debug('start_check status server.')
    device_status_manager = work_template.WorkerManager(16, 2)
    device_status_cache = dict()
    device_status_change_counts = dict()
    while True:
        device_lists = hikvision_global_value.get_device_lists()
        logger.debug("register devices counts:{0}".format(len(device_lists)))
        device_status_lists = hikvision_global_value.get_device_status_lists()
        for device_id, login_info in device_lists.items():
            device_status_manager.add_job(get_device_status, login_info.device_id)
        out_queue = hikvision_global_value.get_status_queue()
        while not device_status_manager.result_queue_empty():
            out_str = device_status_manager.get_result()
            if 1 > len(out_str[0]):
                continue
            #device_status_node = ET.fromstring(out_str[0])
            device_status_list_node = ET.fromstring(out_str[0])
            #dev_node_id = device_status_node.get('device_id')
            #root_node = device_status_list_node.find("device_status_list")
            if device_status_list_node is not None:
                for device_status_node in device_status_list_node.iterfind("device_status"):
                    dev_status_id = device_status_node.get('status_id')
                    cur_status = str(device_status_node.text)
                    if dev_status_id in device_status_lists and str(device_status_node.text) != str(device_status_lists.get(dev_status_id)):
                        if dev_status_id in device_status_cache:
                            if device_status_cache[dev_status_id] > 2:
                                node_str = ET.tostring(device_status_node, encoding="UTF-8", method="xml")
                                out_queue.put(node_str)
                                device_status_lists[dev_status_id] = cur_status
                                device_status_cache[dev_status_id] = 0
                            else:
                                device_status_cache[dev_status_id] += 1
                        else:
                            device_status_cache[dev_status_id] = 1
                    elif dev_status_id in device_status_cache:
                        device_status_cache[dev_status_id] = 0
        time.sleep(5)


class StartServerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, name="get_all_status_thread")
        self.setDaemon(True)

    def run(self):
        # check_device_status()
        get_all_status_by_threadpool(32)
        #start_server()
class OfflineDeviceStatus(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, name="get_offline_status_thread")
        self.setDaemon(True)

    def run(self):
        # check_device_status()
        get_offline_status_by_threadpool(8)
        #start_server()

class StartCheckThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, name="check_all_status_thread")
        self.setDaemon(True)
    def run(self):
        push_device_change()

def push_device_change():
    # task_pool = greenpool.GreenPool()
    while True:
        while not hikvision_global_value.cur_status_queue.empty():
            begin_time = time.time()
            cur_status_xml_result = hikvision_global_value.cur_status_queue.get()
            try:
                map(check_device_change, cur_status_xml_result)
                # for item in cur_status_xml_result:
                    # task_pool.spawn(check_device_change, item)
                    #task_pool.spawn(check_device_change_one, item)
                #task_pool.imap(check_device_change_one, cur_status_xml_result)
                # task_pool.waitall()
            except:
                traceback.print_exc()
            end_time = time.time()
            # logger.info("total check {0} device status time:{1}s.".format(len(cur_status_xml_result), (end_time-begin_time)))
        time.sleep(0.001)

def check_device_change_one(result_xml):
    out_queue = hikvision_global_value.get_status_queue()
    device_status_lists = hikvision_global_value.get_device_status_lists()
    if isinstance(result_xml, tuple) and 0 < len(result_xml[0]):
        device_status_list_node = ET.fromstring(result_xml[0])
        if device_status_list_node is not None:
            for device_status_node in device_status_list_node.iterfind("device_status"):
                dev_status_id = device_status_node.get('status_id')
                cur_status = str(device_status_node.text)
                if dev_status_id in device_status_lists and str(device_status_node.text) != str(device_status_lists.get(dev_status_id)):
                        node_str = ET.tostring(device_status_node, encoding="UTF-8", method="xml")
                        out_queue.put(node_str)
                        #print("come here1")
                        
						#logger.info("status change:{0}".format(node_str))
                        device_status_lists[dev_status_id] = cur_status

def check_device_change(result_xml):
    device_status_cache = hikvision_global_value.get_device_status_cache()
    #device_status_change_counts = dict()
    out_queue = hikvision_global_value.get_status_queue()
    device_status_lists = hikvision_global_value.get_device_status_lists()
    if isinstance(result_xml, tuple) and 0 < len(result_xml[0]):
        device_status_list_node = ET.fromstring(result_xml[0])
        #dev_node_id = device_status_node.get('device_id')
        #root_node = device_status_list_node.find("device_status_list")
        if device_status_list_node is not None:
            for device_status_node in device_status_list_node.iterfind("device_status"):
                dev_status_id = device_status_node.get('status_id')
                cur_status = str(device_status_node.text)
                if dev_status_id in device_status_lists and str(device_status_node.text) != str(device_status_lists.get(dev_status_id)):
                    if dev_status_id in device_status_cache:
                        if device_status_cache[dev_status_id] > 1:
                            node_str = ET.tostring(device_status_node, encoding="UTF-8", method="xml")
                            out_queue.put(node_str)
                            logger.info("status change:{0}".format(node_str))
                            device_status_lists[dev_status_id] = cur_status
                            device_status_cache[dev_status_id] = 0
                        else:
                            device_status_cache[dev_status_id] += 1
                    else:
                        device_status_cache[dev_status_id] = 1
                elif dev_status_id in device_status_cache:
                    device_status_cache[dev_status_id] = 0

def get_all_status_by_threadpool(size=32):
    task_pool = threadpool.ThreadPool(size)
    while 1:
        begin_time = time.time()
        device_lists = hikvision_global_value.get_device_lists()
        offline_device_list=hikvision_global_value.get_offline_device_lists()
        task_requests = []
        for device_id in device_lists.keys():
            if device_id not in offline_device_list:
                task_requests.extend(threadpool.makeRequests(get_device_status, [((device_id, ), {})], get_all_status_callback))
        if 0 < len(task_requests):
            results = [task_pool.putRequest(req) for req in task_requests]
            # results = map(task_pool.putRequest, task_requests)
            task_pool.wait()
            end_time = time.time()
            # print ("get all {0} device status time {1}".format(len(device_lists), (end_time-begin_time)))
            logger.info("total get all {0} device status time {1}".format(len(device_lists), (end_time-begin_time)))
        time.sleep(5)

def get_offline_status_by_threadpool(size=32):
    task_pool = threadpool.ThreadPool(size)
    while 1:
        begin_time = time.time()
        device_lists = hikvision_global_value.get_offline_device_lists()
        task_requests = []
        for device_id in device_lists:
            task_requests.extend(threadpool.makeRequests(get_device_status, [((device_id, ), {})], get_all_status_callback))
        if 0 < len(task_requests):
            results = [task_pool.putRequest(req) for req in task_requests]
            # results = map(task_pool.putRequest, task_requests)
            task_pool.wait()
            end_time = time.time()
            # print ("get all {0} device status time {1}".format(len(device_lists), (end_time-begin_time)))
            logger.info("total get all {0} device status time {1}".format(len(device_lists), (end_time-begin_time)))
        time.sleep(5)
def check_device_status():
    task_pool = greenpool.GreenPool()
    while True:
        begin_time = time.time()
        device_lists = hikvision_global_value.get_device_lists()
        #logger.debug("register devices counts:{0}".format(len(device_lists)))
        # device_status_lists = hikvision_global_value.get_device_status_lists()
        results = task_pool.imap(get_device_status, device_lists.keys())
        task_pool.waitall()
        insert_list = []
        for result in results:
            insert_list.append(result)
        end_time = time.time()
        logger.info("total get {0} device status time:{1}s begin:{2} end:{3}".format(len(device_lists)\
                                                                                        ,(end_time-begin_time)\
                                                                                        , begin_time\
                                                                                        , end_time ))
        hikvision_global_value.get_cur_status_queue().put(insert_list)
        time.sleep(5)

def test_dvr():
    try:
        # device = v_data.DmDevice()
        # device.DeviceID = "218.76.175.206"
        # device.IP = "218.76.175.206"
        # device.Port = 8000
        # device.Username="admin"
        # device.Password = "tysz12345"
        # register_device(device.DeviceID, device.IP, device.Port, device.Username, device.Password)
        # get_stream_url(device.DeviceID)
        device = v_data.DmDevice()
        device.DeviceID = "172.16.1.198"
        device.IP = "172.16.1.198"
        device.Port = 8000
        device.Username="admin"
        device.Password = "ADMIN123"
        register_device(device.DeviceID, device.IP, device.Port, device.Username, device.Password)
        get_stream_url(device.DeviceID)
        #try_process_device(device)
        #register_device('218.76.175.206', '218.76.175.206', 8000, 'admin', 'tysz12345')
        #get_stream_url('218.76.175.206')
        #get_device_status('218.76.175.206')
        raw_input()
    except:
        print(traceback.print_exc())

def test_ipc():
    try:
        device = v_data.DmDevice()
        device.DeviceID = "xxxx"
        device.IP = "172.16.1.198"
        #device.IP = "221.2.91.54"
        device.Port = 8000
        #device.Username="admin"
        device.Username="admin"
        device.Password = "admin123"
        try_process_device(device)
        #device.Password = "admin12345"
        #register_device(device.DeviceID, device.IP, device.Port, device.Username, device.Password)

        # stream_url_ext = hikvision_global_value.StreamUrlC()
        # memset(addressof(stream_url_ext), 0, sizeof(hikvision_global_value.StreamUrlC))
        # stream_url_ext.url_id = "test"
        # stream_url_ext.dev_id = device.DeviceID
        # stream_url_ext.user_name = device.Username
        # stream_url_ext.password = device.Password
        # stream_url_ext.third_party = False
        # stream_url_ext.stream_url_value = "ddd"
        # start_play(device.DeviceID, 0, 0, stream_url_ext)
        # import timeit
        # timeit.timeit("", number=1000)
        #while 1:
           # get_stream_url(device.DeviceID)
            #time.sleep(1)
        #try_process_device(device)
    except:
        print(traceback.print_exc())
##----------------------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        #test_dvr()
        #raw_input()
        test_ipc()
        if sys.platform == 'win32':
            register_device('172.16.1.195', '172.16.1.195', 8000, 'admin', 'vistek123456')
            get_stream_url('172.16.1.195', 0)
            #register_device('218.76.175.206', '218.76.175.206', 8000, 'admin', 'tysz12345')
            #get_stream_url('218.76.175.206')
            ptz("172.16.1.192", V_PTZ_CMD_TYPE.PAN_LEFT, speed=1, channel=1, b_stop=0)
            time.sleep(10)
            ptz("172.16.1.192", V_PTZ_CMD_TYPE.PAN_LEFT, speed=1, channel=1, b_stop=1)
            raw_input()
    except:
        print(traceback.print_exc())
