import os


class EnvironmentValues:

    def __init__(self) -> None:

        # IPアドレス
        self.ip = "0.0.0.0"

        # サーバーのタイムアウト値
        self.timeout = 3.0

        # TLSの有効化(cert_file_pathを設定する必要がある)
        self.tlsenable = False

        # default port: 8080
        self.port = 44333

        # default server header: Apache
        self.server_header = "Apache"

        # art directory path
        self.art_path = "./art/"

        # WOWHoneypot logfile path
        self.log_path = "./log/"

        # Access log separator
        self.separator = " "

        # WOWHoneypot logfile name
        self.wowhoneypot_log = self.log_path + "wowhoneypot.log"

        # Syslog (Output facility: local0(16), priority: info, only tcp protocol)
        self.syslog_enable = False
        self.syslog_server = "127.0.0.1"
        self.syslog_port = "514"

        # Hunting
        self.hunt_enable = False
        self.hunt_log = self.log_path + "hunting.log"

        # for GDPR(True: replace source ip address with 0.0.0.0)
        self.ipmasking = False

        # SSL certfile path
        self.certfile_path = "./server.pem"

        # default host header port: 80
        self.host_port = 443

    def loadEnv():
        instance = EnvironmentValues()
        for field in instance.__dict__.keys():
            value = os.environ.get(field.upper())
            if value:
                exec("instance.{0} = {1}".format(field, value))
        return instance
