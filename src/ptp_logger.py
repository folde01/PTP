from datetime import datetime

class Logger:
    def __init__(self, logfile):
        self._logfile = logfile

    def log(self, msg):
        msg += "\n"
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = date + " " + msg
        with open(self._logfile, "a") as f:
            f.write(msg)
