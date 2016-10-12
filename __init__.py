#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
if sys.version_info < (3, 5):
    import hikvision, hikvision_wrap
    from hikvision import request_cmd,try_process_device, getStatusQueue, ptz_cmd, getCurrentDeviceInfo

    __all__ =["hikvision", "hikvision_wrap"]
else:
    from . import hikvision_wrap, hikvision
    from .hikvision import request_cmd,try_process_device, getStatusQueue, ptz_cmd, getCurrentDeviceInfo
