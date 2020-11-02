import os


class EnvironmentValues:

    def __init__(self) -> None:

        # server ipaddress
        self.ip = "0.0.0.0"

        # default port: 8080
        # Wowhoneypot will listen `port`
        self.port = 8080

        # server timeout(sec)
        self.timeout = 3.0

        # enable TLS
        # you may want to set cert_file_path
        self.tlsenable = False

        # TLS certfile path
        # this propatiy will be ignored if tlsenable = false
        self.certfile_path = "./server.pem"

        # default server header: None;
        # server_header = None introduce that the response header doesn't contain "Server: SOMETHING"
        self.server_header = None

        # for GDPR(True: replace source ip address with 0.0.0.0)
        self.ipmasking = False

        # default host header port: the same as `port`
        self.host_port = self.port

        # art directory path
        self.art_path = "./art/"

        # WOWHoneypot logfile path
        self.log_path = "./log/"

        # WOWHoneypot logfile name
        self.wowhoneypot_log = self.log_path + "wowhoneypot.log"

    @classmethod
    def get_instance(cls):
        instance = EnvironmentValues()
        for field in instance.__dict__.keys():
            value = os.environ.get(field.upper())
            if value:
                exec("instance.{0} = {1}".format(field, value))
        return instance
