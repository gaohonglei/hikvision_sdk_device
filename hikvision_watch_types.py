#!/usr/bin/env python
# -*- coding=utf-8 -*-

"""
@version: 0.0.1
@author: lee
@license: Apache Licence
@contact: shida23577@hotmail.com
@software: PyCharm Community Edition
@file: hikvision_watch_types.py
@time: 2016/5/17 11:10
"""
__title__ = ''
__version = ''
__build__ = 0x000
__author__ = 'lee'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 li shi da'

import time, os, collections, sys
import psutil

try:
    import xml.etree.cElementTree as ET
except:
    import xml.etree.ElementTree as ET

CPU_TIME_LABEL = "cpu_time"
CPU_PERCENT_LABEL = "percent"

MEM_USAGE_LABEL = "use"
MEM_RATE_LABEL = "rate"

RUN_NUM_THREAD = "thread_num"
RUN_NUM_FDS = "fds_num"
RUN_NUM_CONNECTIONS = "connection_num"

SERVICE_INFO_NODE_NAME = "service_info"
class BaseServiceInfo(object):
    def __init__(self, service_id):
        self._time = time.asctime(time.localtime(time.time()))
        self._service_id = service_id
        self._xml_node = ET.Element(SERVICE_INFO_NODE_NAME)
        self._base_info_node = ET.SubElement(self._xml_node, "base_service_info")
        self._base_info_node.set("time_stamp", self._time)
        self._base_info_node.set("service_id", self._service_id)

    def out_xml(self):
        return ET.tostring(self._xml_node, encoding="UTF-8", method="xml")

class WatchDeviceInfo(BaseServiceInfo):
    def __init__(self,service_id, device_count, register_success_count, unregister_count\
                 , unregister_device_list, register_device_list):
        super(WatchDeviceInfo, self).__init__(service_id)
        self._device_count = device_count
        self._register_count = register_success_count
        self._unregister_count = unregister_count
        self._unregister_list = unregister_device_list
        self._register_list = register_device_list

        self._watch_device_node = ET.SubElement(self._xml_node, "watch_device_info")
        self._watch_device_node.set("device_count", str(self._device_count))
        self._watch_device_node.set("register_count", str(self._register_count))
        self._watch_device_node.set("unregister_count", str(self._unregister_count))
        self._watch_device_node.set("register_list", str(":").join(self._register_list).strip(":"))
        self._watch_device_node.set("unregister_list", str(":").join(self._unregister_list).strip(":"))

class ServiceLoadInfo(BaseServiceInfo):
    def __init__(self, service_id):
        super(ServiceLoadInfo, self).__init__(service_id)
        service_name, service_proc_id = self._service_id.split(":")
        service_proc = psutil.Process(int(service_proc_id))

        self._service_load_node = ET.SubElement(self._xml_node, "service_load_info")

        self._cpu_info_node = ET.SubElement(self._service_load_node, "cpu_info")
        self._cpu_info = self._cpu_info(service_proc)
        self._cpu_info_node.set(CPU_TIME_LABEL, str(self._cpu_info.get(CPU_TIME_LABEL)))
        self._cpu_info_node.set(CPU_PERCENT_LABEL, str(self._cpu_info.get(CPU_PERCENT_LABEL)))

        self._mem_info_node = ET.SubElement(self._service_load_node, "mem_info")
        self._mem_info = self._mem_info(service_proc)
        self._mem_info_node.set(MEM_USAGE_LABEL, str(self._mem_info.get(MEM_USAGE_LABEL)))
        self._mem_info_node.set(MEM_RATE_LABEL, str(self._mem_info.get(MEM_RATE_LABEL)))

        self._run_info_node = ET.SubElement(self._service_load_node, "run_info")
        self._run_info = self._run_info(service_proc)
        self._run_info_node.set(RUN_NUM_THREAD, str(self._run_info.get(RUN_NUM_THREAD)))
        #self._run_info_node.set(RUN_NUM_FDS, str(self._run_info.get(RUN_NUM_FDS)))
        self._run_info_node.set(RUN_NUM_CONNECTIONS, str(self._run_info.get(RUN_NUM_CONNECTIONS)))

    def _cpu_info(self, service_proc):
        cpu_info = {}
        cpu_time = service_proc.cpu_times()
        percent = service_proc.cpu_percent(interval=1)
        cpu_info[CPU_TIME_LABEL] = cpu_time.user
        cpu_info[CPU_PERCENT_LABEL] = percent
        return cpu_info

    def _mem_info(self, service_proc):
        out_mem_info = {}
        mem_info = service_proc.memory_info()
        percent = service_proc.memory_percent()
        out_mem_info[MEM_USAGE_LABEL] = float(mem_info.rss/1024/1024)# 单位:M
        out_mem_info[MEM_RATE_LABEL] = float(percent)
        return out_mem_info

    def _run_info(self, service_proc):
        run_info = {}
        num_threads = service_proc.num_threads()
        #num_fds = service_proc.num_fds()
        connect_count = len(service_proc.connections())
        run_info[RUN_NUM_THREAD] = num_threads
        run_info[RUN_NUM_CONNECTIONS] = connect_count
        #run_info[RUN_NUM_FDS] = num_fds
        return run_info

class CurSeviceStatusInfo(BaseServiceInfo):
    def __init__(self, service_id, status, error_msg=None):
        super(CurSeviceStatusInfo, self).__init__(service_id)
        self._status = status
        if error_msg is None:
            self._error_msg = ""
        else:
            self._error_msg = error_msg
        self._cur_service_node = ET.SubElement(self._xml_node, "cur_service")
        self._cur_service_node.set("status", str(self._status))
        self._cur_service_node.set("error_msg", str(self._error_msg))

class PhysicsDeviceInfo():
    def __init__(self):
        self._cpu_count = psutil.cpu_count()
        self._phy_cpu_count = psutil.cpu_count(logical=False)
        self._cpu_rate = psutil.cpu_percent(1)
        self._total_mem = psutil.virtual_memory().total/1024/1024
        self._free_mem = psutil.virtual_memory().free/1024/1024
        self._mem_rate = float(self._free_mem)/float(self._free_mem)

        self._net_info = collections.defaultdict(dict)
        net_info = psutil.net_io_counters(pernic=True)
        for name, item in net_info.items():
            name = name.decode('gbk').encode('UTF-8')
            self._net_info[name]["send"] = item.bytes_sent/1024/1024#单位 M
            self._net_info[name]["recv"] = item.bytes_recv/1024/1024#单位 M

        self._xml_node = ET.Element(SERVICE_INFO_NODE_NAME)
        self._phy_info_node = ET.SubElement(self._xml_node, "physisc_device")

        self._cpu_node = ET.SubElement(self._phy_info_node, "cpu")
        self._cpu_node.set("phy_cpu_count", str(self._phy_cpu_count))
        self._cpu_node.set("cpu_count", str(self._cpu_count))

        self._mem_node = ET.SubElement(self._phy_info_node, "mem")
        self._mem_node.set("total_mem", str(self._total_mem))
        self._mem_node.set("free_mem", str(self._free_mem))
        self._mem_node.set("mem_rate", str(self._mem_rate))

        self._net_node = ET.SubElement(self._phy_info_node, "net")
        self._net_node.set("count", str(len(self._net_info)))
        for name, item in self._net_info.items():
            self._sub_net_node = ET.SubElement(self._net_node, "subnet")
            self._sub_net_node.set("name", name.decode('UTF-8'))
            self._sub_net_node.set("send", str(item.get("send")))
            self._sub_net_node.set("recv", str(item.get("recv")))
    def out_xml(self):
        return ET.tostring(self._xml_node, encoding="UTF-8", method="xml")

if __name__ == "__main__":
    print(dir(psutil))
    mem_info = psutil.virtual_memory()
    print("total:{0} free:{1} percent:{2}".format(mem_info.total/1024/1024\
                                                  , mem_info.free/1024/1024\
                                                  , mem_info.percent))
    cpu_count = psutil.cpu_count()
    cpu_status = psutil.cpu_stats()
    psutil.cpu_times_percent()
    cur_pid = os.getpid()
    service_id = "test:{0}".format(cur_pid)
    base_info = BaseServiceInfo(service_id=service_id)
    register_list = ["dfsdfls", "dfdlfjsdlf"]
    un_register_list = ["fjdlsfjsdl", "dfjldfjs"]
    watch_dev_info = WatchDeviceInfo(service_id, 12, 10, 2, register_list, un_register_list)
    service_load_info = ServiceLoadInfo(service_id=service_id)
    cur_service_info = CurSeviceStatusInfo(service_id=service_id, status=False, error_msg="register failed")
    print("base:{0}\n watch_dev:{1}\n service_load:{2}\n cur_service:{3}\n".format(base_info.out_xml()\
                                                                                   , watch_dev_info.out_xml()\
                                                                                   , service_load_info.out_xml()\
                                                                                   , cur_service_info.out_xml()))

    phy = PhysicsDeviceInfo()
    print("phy:{0}".format(phy.out_xml()))
    raw_input()

