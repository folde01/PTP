from flask_table import Table, Col, LinkCol

class Stream_Table(Table):
    """Table's constructor takes a list of objects (here, stream status objects). 
    The Table subclass contains "attr_name = Col('table-heading')" pairs.
    The attr_names refer to the names of the attributes of the stream status objects.

    Credit to https://readthedocs.org/projects/flask-table/
    """
    cli_ip = Col('Client IP address')
    cli_pt = Col('Client TCP port')
    svr_ip = Col('Server IP address')
    svr_pt = Col('Server TCP port')
    bytes_to_svr = Col('Bytes sent to server')
    bytes_to_cli = Col('Bytes sent to client')
    ts_first_pkt = Col('Timestamp of first packet')
    ts_last_pkt = Col('Timestamp of last packet')
    ssl_cli_hello = Col('SSL Client Hello seen')
    ssl_cli_ccs = Col('SSL client Change Cipher Suite seen')
    ssl_svr_hello = Col('SSL Server Hello seen')
    ssl_svr_ccs = Col('SSL server Change Cipher Suite seen')
    ssl_version = Col('SSL version')
    ssl_cipher = Col('Code for SSL cipher suite')

class Stream_Table_Test(Table):
    cli_ip = Col('Client IP address')
    #cli_pt = Col('Client TCP port')
    #svr_ip = Col('Server IP address')
    svr_ip = LinkCol('Server IP address', 'sub_results', url_kwargs=dict(cli_pt='cli_pt'))
    svr_pt = Col('Server TCP port')
    bytes_to_svr = Col('Bytes sent to server')
    bytes_to_cli = Col('Bytes sent to client')
    ts_first_pkt = Col('Timestamp of first packet')
    ts_last_pkt = Col('Timestamp of last packet')
    ssl_cli_hello = Col('SSL Client Hello seen')
    ssl_cli_ccs = Col('SSL client Change Cipher Suite seen')
    ssl_svr_hello = Col('SSL Server Hello seen')
    ssl_svr_ccs = Col('SSL server Change Cipher Suite seen')
    ssl_version = Col('SSL version')
    ssl_cipher = Col('Code for SSL cipher suite')

class Stream_Table_Small(Table):
    svr_ip = Col('Server IP address')
    cli_pt = Col('Client TCP port')

    '''
    TODO Phase 3:
       
    ssl_handshake = Col('SSL handshake')
    ssl_version = Col('SSL version')
    ssl_cipher = Col('SSL cipher used') 
    ssl_records = Col('SSL records')
    encrypted = Col('Encrypted') 
    TODO Phase 4:
    app_name = Col('App name')
    '''


