from flask_table import Table, Col

class Stream_Table(Table):
    cli_ip = Col('cli_ip')
    cli_pt = Col('cli_pt')
    svr_ip = Col('svr_ip')
    svr_pt = Col('svr_pt')
    bytes_to_svr = Col('bytes_to_svr')
    bytes_to_cli = Col('bytes_to_cli')
