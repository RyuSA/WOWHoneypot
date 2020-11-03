#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Welcome to Omotenashi Web Honeypot(WOWHoneypot)
# author @morihi_soc
# (c) 2017 @morihi_soc

import base64
import logging
import logging.handlers
import os
import random
import json
import re
import select
import socket
import ssl
import sys
from sys import version
import traceback
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from environmentvalues import EnvironmentValues
from mrr_checker import parse_mrr

WOWHONEYPOT_VERSION = "1.3"

JST = timezone(timedelta(hours=+9), 'JST')
logging.basicConfig(format='%(message)s', level=logging.INFO)
default_content = []
mrrdata = {}
mrrids = []
environmentValues = EnvironmentValues.get_instance()


class Request:
    def __init__(self, time, clientip, hostname, requestline, header: str, payload) -> None:
        method, path, version = requestline.split(" ")
        self.time = time
        self.clientip = clientip
        self.hostname = hostname
        self.path = path
        self.version = version
        self.method = method
        self.header = header
        self.payload = base64.b64encode(
            payload.encode('utf-8')).decode('utf-8')

    def to_json(self):
        return json.dumps(self.__dict__, ensure_ascii=False)


class WOWHoneypotHTTPServer(HTTPServer):
    def server_bind(self):
        HTTPServer.server_bind(self)
        self.socket.settimeout(environmentValues.timeout)

    def finish_request(self, request, client_address):
        request.settimeout(environmentValues.timeout)
        HTTPServer.finish_request(self, request, client_address)


class WOWHoneypotRequestHandler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())
        self.error_message_format = "error"
        self.error_content_type = "text/plain"

    def handle_one_request(self):
        if environmentValues.ipmasking == True:
            clientip = "0.0.0.0"
        else:
            clientip = self.client_address[0]

        try:
            (r, w, e) = select.select([self.rfile],
                                      [], [], environmentValues.timeout)
            if len(r) == 0:
                errmsg = "Client({0}) data sending was too late.".format(
                    clientip)
                raise socket.timeout(errmsg)
            else:
                self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = True
                return

            rrl = str(self.raw_requestline, 'iso-8859-1')
            rrl = rrl.rstrip('\r\n')

            parse_request_flag = True
            if re.match("^[A-Z]", rrl) and (rrl.endswith("HTTP/1.0") or rrl.endswith("HTTP/1.1")):
                rrlmethod = rrl[:rrl.index(" ")]
                rrluri = rrl[rrl.index(" ")+1:rrl.rindex(" ")
                             ].replace(" ", "%20")
                rrluri = rrluri.replace("\"", "%22")
                rrlversion = rrl[rrl.rindex(" ")+1:]
                rrl2 = rrlmethod + " " + rrluri + " " + rrlversion
                self.raw_requestline = rrl2.encode()
            else:
                parse_request_flag = False

            if not self.parse_request() or not parse_request_flag:
                errmsg = "Client({0}) data cannot parse. {1}".format(
                    clientip, str(self.raw_requestline))
                raise ValueError(errmsg)

            body = ""
            if 'content-length' in self.headers:
                content_len = int(self.headers['content-length'])
                if content_len > 0:
                    post_body = self.rfile.read(content_len)
                    body = post_body.decode()

            match = False
            for id in mrrids:
                if match:
                    break

                if "method" in mrrdata[id]["trigger"]:
                    if not self.command == mrrdata[id]["trigger"]["method"]:
                        continue

                uricontinue = False
                if "uri" in mrrdata[id]["trigger"]:
                    for u in mrrdata[id]["trigger"]["uri"]:
                        if re.search(u, self.path) is None:
                            uricontinue = True
                if uricontinue:
                    continue

                headercontinue = False
                if "header" in mrrdata[id]["trigger"]:
                    for h in mrrdata[id]["trigger"]["header"]:
                        if re.search(h, str(self.headers)) is None:
                            headercontinue = True
                if headercontinue:
                    continue

                bodycontinue = False
                if "body" in mrrdata[id]["trigger"]:
                    if len(body) == 0:
                        continue
                    for b in mrrdata[id]["trigger"]["body"]:
                        if re.search(b, body) is None:
                            bodycontinue = True
                if bodycontinue:
                    continue
                match = id

            status = 200
            tmp = self.requestline.split()
            if len(tmp) == 3:
                self.protocol_version = "{0}".format(tmp[2].strip())
            else:
                self.protocol_version = "HTTP/1.1"

            if not match:
                self.send_response(200)
                if environmentValues.server_header:
                    self.send_header("Server", environmentValues.server_header)
                self.send_header('Content-Type', 'text/html')
                r = default_content[random.randint(0, len(default_content)-1)]
                self.send_header('Content-Length', len(r))
                self.end_headers()
                self.wfile.write(bytes(r, "utf-8"))
            else:
                status = mrrdata[match]["response"]["status"]
                self.send_response(status)
                header_server_flag = False
                header_content_type_flag = False
                for name, value in mrrdata[match]["response"]["header"].items():
                    self.send_header(name, value)
                    if name == "Server":
                        header_server_flag = True
                    elif name == "Content-Type":
                        header_content_type_flag = True

                if not header_server_flag:
                    self.send_header('Server', environmentValues.server_header)
                if not header_content_type_flag:
                    self.send_header('Content-Type', 'text/html')
                r = mrrdata[match]["response"]["body"]
                self.send_header('Content-Length', len(r))
                self.end_headers()
                self.wfile.write(bytes(r, "utf-8"))

            self.wfile.flush()

            # logging
            hostname = None
            if "host" in self.headers:
                if self.headers["host"].find(" ") == -1:
                    hostname = self.headers["host"]
                else:
                    hostname = self.headers["host"].split(" ")[0]
                if hostname.find(":") == -1:
                    hostname = "{0}:{1}".format(
                        hostname, environmentValues.host_port)
            else:
                hostname = "blank:{0}".format(environmentValues.host_port)

            request = Request(time=get_time(), clientip=clientip, hostname=hostname,
                              requestline=self.requestline, header=str(self.headers), payload=body)
            logging.info("{message}".format(message=request.to_json()))

        except socket.timeout as e:
            emsg = "{0}".format(e)
            if emsg == "timed out":
                errmsg = "Session timed out. Client IP: {0}".format(clientip)
            else:
                errmsg = "Request timed out: {0}".format(emsg)
            self.log_error(errmsg)
            self.close_connection = True
            logging_system(errmsg, True, False)
            return
        except Exception as e:
            errmsg = "Request handling Failed: {0} - {1}".format(type(e), e)
            self.close_connection = True
            logging_system(errmsg, True, False)
            return


def logging_system(message, is_error, is_exit):
    if is_exit:
        sys.exit(1)


def get_time():
    return "{0:%Y-%m-%dT%H:%M:%S%z}".format(datetime.now(JST))


def config_load():
    # art directory Load
    if not os.path.exists(environmentValues.art_path) or not os.path.isdir(environmentValues.art_path):
        logging_system("{0} directory load error.".format(
            environmentValues.art_path), True, True)

    defaultfile = os.path.join(environmentValues.art_path, "mrrules.xml")
    if not os.path.exists(defaultfile) or not os.path.isfile(defaultfile):
        logging_system("{0} file load error.".format(defaultfile), True, True)

    logging_system("mrrules.xml reading start.", False, False)

    global mrrdata
    mrrdata = parse_mrr(defaultfile, os.path.split(defaultfile)[0])

    global mrrids
    mrrids = sorted(list(mrrdata.keys()), reverse=True)

    if mrrdata:
        logging_system("mrrules.xml reading complete.", False, False)
    else:
        logging_system("mrrules.xml reading error.", True, True)

    defaultlocal_file = os.path.join(
        environmentValues.art_path, "mrrules_local.xml")
    if os.path.exists(defaultlocal_file) and os.path.isfile(defaultlocal_file):
        logging_system("mrrules_local.xml reading start.", False, False)
        mrrdata2 = parse_mrr(defaultlocal_file, os.path.split(defaultfile)[0])

        if mrrdata2:
            logging_system("mrrules_local.xml reading complete.", False, False)
        else:
            logging_system("mrrules_local.xml reading error.", True, True)

        mrrdata.update(mrrdata2)
        mrrids = sorted(list(mrrdata.keys()), reverse=True)

    artdefaultpath = os.path.join(environmentValues.art_path, "default")
    if not os.path.exists(artdefaultpath) or not os.path.isdir(artdefaultpath):
        logging_system("{0} directory load error.".format(
            artdefaultpath), True, True)

    global default_content
    for root, dirs, files in os.walk(artdefaultpath):
        for file in files:
            if not file.startswith(".") and file.endswith(".html"):
                tmp = open(os.path.join(artdefaultpath, file), 'r')
                default_content.append(tmp.read().strip())
                tmp.close()

    if len(default_content) == 0:
        logging_system("default html content not exist.", True, True)


if __name__ == '__main__':
    random.seed(datetime.now().timestamp())

    try:
        config_load()
    except Exception:
        print(traceback.format_exc())
        sys.exit(1)
    logging_system("WOWHoneypot(version {0}) start. {1}:{2} at {3}".format(
        WOWHONEYPOT_VERSION, environmentValues.ip, environmentValues.port, get_time()), False, False)
    logging_system("IP Masking: {0}".format(
        environmentValues.ipmasking), False, False)
    logging_system("TLS Enabled: {0}".format(
        environmentValues.tls_enable), False, False)
    myServer = WOWHoneypotHTTPServer(
        (environmentValues.ip, environmentValues.port), WOWHoneypotRequestHandler)
    myServer.timeout = environmentValues.timeout
    if environmentValues.tls_enable:
        myServer.socket = ssl.wrap_socket(
            myServer.socket, certfile=environmentValues.certfile_path, server_side=True)
    try:
        myServer.serve_forever()
    except KeyboardInterrupt:
        pass

    myServer.server_close()
