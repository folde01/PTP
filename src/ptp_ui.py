from flask import Flask, render_template, url_for
from ptp_sniffer import Sniffer
from ptp_analyser import Analyser
from ptp_stream_model import Stream_Model
from ptp_stream_reassembler import Stream_Reassembler
from ptp_stream_db import Stream_DB

app = Flask(__name__)
sniffer = Sniffer() 
stream_reassembler = Stream_Reassembler(sniffer.pcap_filename())
stream_db = Stream_DB()
stream_model = Stream_Model(sniffer, stream_reassembler, stream_db)
analyser = Analyser(stream_model)

@app.route('/index')
@app.route('/')
def index():  
    '''Web page accessible via http://localhost/index. Has 'start capture' button.'''
    return render_template('index.html')

@app.route('/capture')
def capture():
    '''Web page accessible via http://localhost/capture. Has 'stop capture and see results' button.'''
    global sniffer
    sniffer.start()
    log("start_capture(): traffic capture started")
    return render_template('capturing.html')

@app.route('/results')
def results():
    '''Web page accessible via http://localhost/capture. Has results of capture, and a button to return to index page.'''
    global sniffer
    sniffer.stop()
    log("stop_capture(): traffic capture stopped")
    results = analyser.results()
    log("generate_analysis(): analysed")
    return render_template('results.html', results=results)

def log(msg): 
    '''Writes to a log file, for debugging purposes'''
    log_file = "ptp.log"
    msg += "\n"
    with open(log_file, "a") as f:
        f.write(msg)

if __name__ == "__main__":
    app.run(host= '0.0.0.0')
