from flask import Flask, render_template, url_for
from ptp_analyser import Analyser

app = Flask(__name__)
analyser = Analyser()
sniffer = analyser.get_sniffer() 

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
    results_table = analyser.results()
    results_table.border = True
    #print "UI results:", repr(results)
    log("generate_analysis(): analysed")
    return render_template('results.html', results=results_table)

def log(msg): 
    '''Writes to a log file, for debugging purposes'''
    log_file = "ptp.log"
    msg += "\n"
    with open(log_file, "a") as f:
        f.write(msg)

if __name__ == "__main__":
    app.run(host= '0.0.0.0')
