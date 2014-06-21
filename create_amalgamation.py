#!/usr/bin/env python

#
# Copyright 2014 Lieven Govaerts
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

source_files = [ "MockHTTP_private.h", "MockHTTP_server.c", "MockHTTP.c" ]

data = []
for source_file in source_files:
    with open(source_file,'r') as fi:
        data += fi.readlines()

with open("MockHTTP_amalgamation.c", "w") as fo:
    for line in data:
        if not line.startswith("#include \"MockHTTP_private.h\""):
            fo.write(line)
