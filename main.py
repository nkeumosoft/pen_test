#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2017-2022 Nicolas SURRIBAS
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import os
import sys

from business.wapitiapi import wapiti_web_asyncio_wrapper

if sys.version_info.major < 3:
    print("Wapiti needs Python 3, you are using {}.{}".format(sys.version_info.major, sys.version_info.minor))
    exit()

parent_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
if os.path.exists(os.path.join(parent_dir, "wapitiCore")):
    sys.path.append(parent_dir)


if __name__ == "__main__":
    wapiti_web_asyncio_wrapper()
