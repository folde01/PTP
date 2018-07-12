from flask_table import Table, Col

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
