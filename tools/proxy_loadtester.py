# Copyright (C) 2014-2020 Savoir-faire Linux Inc.
# Author: Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Manually run with Web UI:
#   locust -f tester.py --host http://127.0.0.1:8080
#
# Run in Terminal:
#   locust -f tester.py --host http://127.0.0.1:8080 \
#       --clients 100 --hatch-rate 1 --run-time 10s --no-web --only-summary

from locust import HttpLocust, TaskSet
from random import randint
import urllib.request
import base64
import json

words_url = "http://svnweb.freebsd.org/csrg/share/dict/words?view=co&content-type=text/plain"
words_resp = urllib.request.urlopen(words_url)
words = words_resp.read().decode().splitlines()

headers = {'content-type': 'application/json'}

def rand_list_value(mylist):
    return mylist[randint(0, len(mylist) - 1)]

def put_key(l):
    key = rand_list_value(words)
    val = rand_list_value(words)
    print("Put/get: key={} value={}".format(key, val)) 
    data = base64.b64encode(val.encode()).decode()
    print("Base64 encoding: value={} encoded={}".format(val, data))
    l.client.post("/" + key, data=json.dumps({"data": data}),
                  headers=headers, catch_response=True)

def get_key(l):
    key = rand_list_value(words)
    print("Get: key={}".format(key)) 
    l.client.get("/" + key)

def get_stats(l):
    l.client.get("/stats")

def subscribe(l):
    key = rand_list_value(words)
    print("Subscribe: key={}".format(key))
    l.client.get("/" + key + "/subscribe")

def listen(l):
    key = rand_list_value(words)
    print("Listen: key={}".format(key))
    l.client.get("/" + key + "/listen")

class UserBehavior(TaskSet):
    tasks = {get_key: 5, put_key: 5, get_stats: 1, subscribe: 1, listen: 1}

    def on_start(self):
        put_key(self)
        get_key(self)
        subscribe(self)
        listen(self)

    def on_stop(self):
        get_stats(self)

class WebsiteUser(HttpLocust):
    task_set = UserBehavior
    min_wait = 5000
    max_wait = 9000
    print("Initiate the benchmark at http://127.0.0.1:8089/")
