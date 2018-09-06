class Is_Encrypted_Enum(object):
    NO = 'No' 
    YES = 'Yes'
    UNKNOWN = 'Unknown'
    UNASSESSED = 'Unassessed'

class Constants(object):

    def __init__(self):
        self.DEFAULT_PCAP_FILENAME = 'sniffed.pcap'
        self.DEFAULT_TS_FIRST_PKT = '2011-11-11 11:11:11'
        self.DEFAULT_TS_LAST_PKT = '2011-11-11 11:11:11'
        self.KILL_PKT_IP = '10.11.12.13'
        self.TEST_PCAP_DIR = 'test-pcap-files'

        self.ssl_version_by_code = { 
	    '0300': 'SSL 3.0',
	    '0301': 'TLS 1.0',
	    '0302': 'TLS 1.1',
	    '0303': 'TLS 1.2',
	}


        self.ssl = {}

        self.ssl['versions'] = {}

        self.ssl['versions']['SSL_3_0'] =                       '0300'
        self.ssl['versions']['SSL_1_0'] =                       '0301'
        self.ssl['versions']['SSL_1_1'] =                       '0302'
        self.ssl['versions']['SSL_1_2'] =                       '0303'


        self.ssl['protocols'] = {}
        self.ssl['protocols']['CHANGE_CIPHER_SPEC'] =        '14'
        self.ssl['protocols']['ALERT'] =                     '15'
        self.ssl['protocols']['HANDSHAKE'] =                 '16'
        self.ssl['protocols']['APPLICATION_DATA'] =          '17'
        
        self.ssl['handshake_messages'] = {}
        self.ssl['handshake_messages']['HELLO_REQUEST'] =          '00'
        self.ssl['handshake_messages']['CLIENT_HELLO'] =           '01'
        self.ssl['handshake_messages']['SERVER_HELLO'] =           '02'
        self.ssl['handshake_messages']['CERTIFICATE'] =            '0b'
        self.ssl['handshake_messages']['SERVER_KEY_EXCHANGE'] =    '0c'
        self.ssl['handshake_messages']['CERTIFICATE_REQUEST'] =    '0d'
        self.ssl['handshake_messages']['SERVER_DONE'] =            '0e'
        self.ssl['handshake_messages']['CERTIFICATE_VERIFY'] =     '0f'
        self.ssl['handshake_messages']['CLIENT_KEY_EXCHANGE'] =    '10'
        self.ssl['handshake_messages']['FINISHED'] =               '14'

        self.ssl['ccs_messages'] = {}
        self.ssl['ccs_messages']['CHANGE_CIPHER_SPEC'] =           '01'

        self.ssl['start_bytes'] = {}
        self.ssl['start_bytes']['PROTOCOL'] =                  0
        self.ssl['start_bytes']['VERSION'] =                          1
        self.ssl['start_bytes']['RECORD_DATA_LENGTH'] =               3
        self.ssl['start_bytes']['HANDSHAKE'] =                       5
        self.ssl['start_bytes']['CHANGE_CIPHER_SPEC'] =         5
        self.ssl['start_bytes']['HANDSHAKE_DATA_LENGTH'] =      6
        
        self.ssl['lengths'] = {}
        self.ssl['lengths']['PROTOCOL'] =                         1
        self.ssl['lengths']['VERSION'] =                        2 
        self.ssl['lengths']['RECORD_DATA_LENGTH'] =             2 
        self.ssl['lengths']['HANDSHAKE'] =                      1 
        self.ssl['lengths']['HANDSHAKE_DATA_LENGTH'] =          3 
        self.ssl['lengths']['CHANGE_CIPHER_SPEC'] =             1 
