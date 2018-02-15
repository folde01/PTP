from flask import Flask, render_template, url_for
from ptp_sniffer import Sniffer
from ptp_analyser import Analyser

app = Flask(__name__)

@app.route('/index')
def index():  
    '''Web page accessible via http://localhost/index. Has 'start capture' button.'''
    return render_template('index.html')


@app.route('/capture')
def capture():
    '''Web page accessible via http://localhost/capture. Has 'stop capture and see results' button.'''
    start_capture()
    return render_template('capturing.html')


@app.route('/results')
def results():
    '''Web page accessible via http://localhost/capture. Has results of capture, and a button to return to index page.'''
    stop_capture()
    results = generate_analysis()
    return render_template('results.html', results=results)


def start_capture():
    '''Starts capturing traffic involving the target device.'''
    sniffer = Sniffer()
    sniffer.start()
    log("start_capture(): traffic capture started")
    return sniffer


def stop_capture(sniffer):
    '''Stops capturing traffic involving the target device.'''
    sniffer.stop()
    log("stop_capture(): traffic capture stopped")


def generate_analysis(sniffer):
    '''Analyses captured traffic involving the target device'''
    analyser = Analyser(sniffer)
    log("generate_analysis(): analysed")
    return analyser.results() 


def log(msg): 
    '''Writes to a log file, for debugging purposes'''
    log_file = "ptp.log"
    msg += "\n"
    with open(log_file, "a") as f:
        f.write(msg)


if __name__ == "__main__":
    app.run()
