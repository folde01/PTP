class Packet_Dissection(object):
    def __init__(self, **kwargs):
        self.is_ssl_client_hello = kwargs('is_ssl_client_hello', None)

        self.is_ssl_server_hello = kwargs('is_ssl_server_hello', None)
