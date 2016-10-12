#!/usr/bin/env python
# -*- coding: utf-8 -*-

import inspect, time, re
import hikvision_global_value
import vistek_util.PTZParser as PTZParser

from collections import defaultdict
from urlobject import URLObject

try:
    import hikvision_wrap
except:
    from . import hikvision_wrap

class uri_parser():
    """uri parser"""

    def __init__(self, uri):
        """init function"""
        self.uri = URLObject(uri)
        self.params = self.uri.query.dict

    def user_name(self):
        return self.uri.username

    def password(self):
        return self.uri.password

    def ip(self):
        return self.uri.hostname

    def port(self):
        return self.uri.port

    def add_func_param(self, param):
        self.params.update(param)

    def func_name(self, name):
        query = self.uri.query.dict

        if query.has_key(name):
            return query[name]
        else:
            return ''

    def func_params(self, name):
        query = self.uri.query.dict
        if query[name] == 'register_device':
            self.add_func_param({'ip': self.uri.hostname})
            self.add_func_param({'port': self.uri.port})
            self.add_func_param({'user_name': self.uri.username})
            self.add_func_param({'user_pwd': self.uri.password})
        if self.params.has_key(name):
            self.params.pop(name)
        return self.params


def getStatusQueue():
    return hikvision_global_value.get_status_queue()

def getCurrentDeviceInfo():
    return hikvision_global_value.getCurrentDeviceInfo()

def try_process_device(device):
    func = getattr(hikvision_wrap, "try_process_device")
    if func:
        return func(device)
    else:
        return None

PTZ_CMD_Map = defaultdict(tuple)  # device_id ptz_cmd

PTZ_CMD_Map_Relation = {PTZParser.V_PTZ_CMD.V_PTZ_UP: hikvision_wrap.V_PTZ_CMD_TYPE.TILT_UP,
                        PTZParser.V_PTZ_CMD.V_PTZ_DOWN: hikvision_wrap.V_PTZ_CMD_TYPE.TILT_DOWN,
                        PTZParser.V_PTZ_CMD.V_PTZ_LEFT: hikvision_wrap.V_PTZ_CMD_TYPE.PAN_LEFT,
                        PTZParser.V_PTZ_CMD.V_PTZ_RIGHT: hikvision_wrap.V_PTZ_CMD_TYPE.PAN_RIGHT,
                        PTZParser.V_PTZ_CMD.V_PTZ_LEFT_UP: hikvision_wrap.V_PTZ_CMD_TYPE.LEFT_UP,
                        PTZParser.V_PTZ_CMD.V_PTZ_LEFT_DOWN: hikvision_wrap.V_PTZ_CMD_TYPE.LEFT_DOWN,
                        PTZParser.V_PTZ_CMD.V_PTZ_RIGHT_UP: hikvision_wrap.V_PTZ_CMD_TYPE.RIGHT_UP,
                        PTZParser.V_PTZ_CMD.V_PTZ_RIGHT_DOWN: hikvision_wrap.V_PTZ_CMD_TYPE.RIGHT_DOWN,
                        PTZParser.V_PTZ_CMD.V_PTZ_ZOOM_IN: hikvision_wrap.V_PTZ_CMD_TYPE.ZOOM_IN,
                        PTZParser.V_PTZ_CMD.V_PTZ_ZOOM_OUT: hikvision_wrap.V_PTZ_CMD_TYPE.ZOOM_OUT,
                        PTZParser.V_PTZ_CMD.V_PTZ_FOCUS_FAR: hikvision_wrap.V_PTZ_CMD_TYPE.FOCUS_FAR,
                        PTZParser.V_PTZ_CMD.V_PTZ_FOCUS_NEAR: hikvision_wrap.V_PTZ_CMD_TYPE.FOCUS_NEAR,
                        PTZParser.V_PTZ_CMD.V_PTZ_PRESET_ADD: hikvision_wrap.V_PTZ_CMD_TYPE.SET_PRESET,
                        PTZParser.V_PTZ_CMD.V_PTZ_PRESET_DEL: hikvision_wrap.V_PTZ_CMD_TYPE.CLE_PRESET,
                        PTZParser.V_PTZ_CMD.V_PTZ_PRESET_GOTO: hikvision_wrap.V_PTZ_CMD_TYPE.GOTO_PRESET,
                        PTZParser.V_PTZ_CMD.V_PTZ_LIGHT: hikvision_wrap.V_PTZ_CMD_TYPE.LIGHT_PWRON,
                        PTZParser.V_PTZ_CMD.V_PTZ_SWIPER: hikvision_wrap.V_PTZ_CMD_TYPE.WIPER_PWRON,
                        PTZParser.V_PTZ_CMD.V_PTZ_HEATER: hikvision_wrap.V_PTZ_CMD_TYPE.HEATER_PWRON,
                        PTZParser.V_PTZ_CMD.V_PTZ_IRIS_OPEN: hikvision_wrap.V_PTZ_CMD_TYPE.IRIS_OPEN,
                        PTZParser.V_PTZ_CMD.V_PTZ_IRIS_CLOSE: hikvision_wrap.V_PTZ_CMD_TYPE.IRIS_CLOSE
                        }

"""
ptz xml example.
<?xml version='1.0'?>
<ptz deviceid="", channelindex=1, userid="", userlevel="">
	 <move p="1" t="1" z="1">
	 <stop>
	 <PTZIrisOpen value="0.5"/>
	 <PTZIrisClose value="0.5"/>
	 <PTZFocusForward value="0.5"/>
	 <PTZFocusBackward value="0.5"/>
	 <PTZZoomIn value="0.5"/>
	 <PTZZoomOut value="0.5"/>

	 <PTZPresetAdd value="0"/>
	 <PTZPresetRemove value="0"/>
	 <PTZPresetGoto value="0"/>
	 <LIGHT value="0"/>
	 <SWIPER value="1"/>
	 <HEATER value="0"/>
</ptz>
"""

def ptz_cmd(xml_content):
    global PTZ_CMD_Map
    global PTZ_CMD_Map_Relation
    ptz_parser = PTZParser.ptzParser(xml_content)
    cmd = ptz_parser.ptz_cmd  # device_id channel cmd param
    dest_param = ()
    if cmd is not None:
        if cmd[2] == PTZParser.V_PTZ_CMD.V_PTZ_STOP:
            cmd = PTZ_CMD_Map[cmd[0]]
            if len(cmd) == 0:
                return None
            dest_param = (cmd[0], PTZ_CMD_Map_Relation[cmd[2]]) + cmd[3:] + (
            1, cmd[1])  # device_id cmd cmd_param start|stop channel
        elif cmd[2] == PTZParser.V_PTZ_CMD.V_PTZ_NONE:
            return None
        else:
            dest_param = (cmd[0], PTZ_CMD_Map_Relation[cmd[2]]) + cmd[3:] + (
            0, cmd[1])  # device_id cmd cmd_param start|stop channel
            PTZ_CMD_Map[str(cmd[0])] = cmd
        if dest_param is not None:
            func = getattr(hikvision_wrap, "ptz")
            return func(*dest_param)


def request_cmd(device_id, uri, params):
    """device cmd"""
    res_data = list()
    func_lists = dir(hikvision_wrap)
    parser = uri_parser(uri)
    parser.add_func_param({'device_id': device_id})
    func_name = parser.func_name('func')
    if func_name in func_lists:
        cmd_func = getattr(hikvision_wrap, func_name)
        cmd_params = parser.func_params('func')
        params_lists = []
        need_args = inspect.getargspec(cmd_func).args
        for call_args in need_args:
            if cmd_params.has_key(call_args):
                params_lists.append(cmd_params.get(call_args))
        # logger.debug("cmd=%s args:%s args_value:%s", func_name, inspect.getargspec(cmd_func).args, params_lists)
        if func_name=='register_device':
            out_data = cmd_func(device_channel_list=params,**cmd_params)
        else:
            out_data=cmd_func(**cmd_params)
        return out_data
    else:
        return ('', 0)


def test_zoom():
    stop_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><stop></stop></ptz>"
    zoom_in_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.0\" t=\"0.0\" z=\"0.5\"></move></ptz>"
    zoom_out_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.0\" t=\"0.0\" z=\"-0.5\"></move></ptz>"
    ptz_cmd(zoom_in_xml)
    time.sleep(1)
    ptz_cmd(stop_xml)
    ptz_cmd(zoom_out_xml)
    time.sleep(1)
    ptz_cmd(stop_xml)


def test_iris():
    stop_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><stop></stop></ptz>"
    iris_open_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><PTZIrisOpen value=\"0.5\"/></ptz>"
    iris_close_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><PTZIrisClose value=\"0.5\"/></ptz>"
    ptz_cmd(iris_open_xml)
    time.sleep(1)
    ptz_cmd(stop_xml)
    ptz_cmd(iris_close_xml)
    time.sleep(1)
    ptz_cmd(stop_xml)


def test_focus():
    stop_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><stop></stop></ptz>"
    focus_far_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><PTZFocusForward value=\"0.5\"/></ptz>"
    focus_near_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"172.16.1.191\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><PTZFocusBackward value=\"0.5\"/></ptz>"
    ptz_cmd(focus_far_xml)
    time.sleep(1)
    ptz_cmd(stop_xml)
    ptz_cmd(focus_near_xml)
    time.sleep(1)
    ptz_cmd(stop_xml)

def test_move(ip):
    stop_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><stop></stop></ptz>".format(
        ip)
    move_left_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"-0.5\" t=\"0.0\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_right_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.5\" t=\"0.0\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_up_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.0\" t=\"0.5\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_down_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.0\" t=\"-0.5\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_left_up_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"-0.5\" t=\"0.5\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_left_down_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"-0.5\" t=\"-0.5\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_right_up_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.5\" t=\"0.5\" z=\"0.0\"></move></ptz>".format(
        ip)
    move_right_down_xml = "<?xml version=\'1.0\'?><ptz deviceid=\"{0}\" channelindex=\"1\" userid=\"xxx\" userlevel=\"2\"><move p=\"0.5\" t=\"-0.5\" z=\"0.0\"></move></ptz>".format(
        ip)
    ptz_cmd(move_left_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    return 0
    ptz_cmd(move_right_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    ptz_cmd(move_up_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    ptz_cmd(move_down_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    ptz_cmd(move_left_up_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    ptz_cmd(move_left_down_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    ptz_cmd(move_right_down_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)
    ptz_cmd(move_right_up_xml)
    # time.sleep(5)
    ptz_cmd(stop_xml)


if __name__ == '__main__':
    camera_ip = "172.16.1.192"
    user = "admin"
    pwd = "vistek123456"
    port = 8000
    uri = "http://{0}:{1}@{2}:{3}/device/meida?func=register_device".format(user, pwd, camera_ip, port)
    out_data = request_cmd(camera_ip, uri, '')
    device_info = getCurrentDeviceInfo()
    while True:
        time.sleep(5)
    out_data = request_cmd('172.16.1.191', "http://admin:12345@172.16.1.191:8000/device/meida?func=register_device", '')
    # test_move(camera_ip)
    # raw_input()
    # test_zoom()
    # test_focus()
    # test_iris()
    out_data = request_cmd('172.16.1.191', "http://172.16.1.191:8000/device/meida?func=get_stream_url", '')
    print('receive:', out_data)
    while 1:
        out_data = request_cmd('172.16.1.191', "http://172.16.1.191:8000/device/meida?func=get_device_status", '')
        print('receive:', out_data)
        time.sleep(5)
