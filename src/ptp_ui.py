from flask import Flask, render_template, url_for
from ptp_analyser import Analyser
from ptp_stream_table import Stream_Table, Stream_Table_Test, Stream_Table_Small

app = Flask(__name__)
analyser = Analyser()
#sniffer = analyser.get_sniffer() 
_results = None

@app.route('/index')
@app.route('/')
def index():  
    '''Web page accessible via http://localhost/index. Has 'start capture' button.'''
    return render_template('index.html')

@app.route('/capture-started')
def capture_started():
    '''Web page accessible via http://localhost/capture-started. Has 'stop capture and see results' button.'''
    #global sniffer
    #sniffer.start()
    analyser.start_sniffing()
    log("start_capture(): traffic capture started")
    return render_template('capturing.html')

@app.route('/results')
def results():
    '''Web page accessible via http://localhost/capture. Has results of capture, and a button to return to index page.'''
    #global sniffer
    #sniffer.stop()
    analyser.stop_sniffing()
    log("stop_capture(): traffic capture stopped")
    #results_table = analyser.results()
    results = analyser.get_analysis_results()
    results_table = Stream_Table(results)
    results_table.border = True
    #print "UI results:", repr(results)
    log("generate_analysis(): analysed")
    return render_template('results.html', results=results_table)

@app.route('/results-for-existing-pcapfile')
def results_test():
    '''Web page accessible via http://localhost/capture. Has results of capture, and a button to return to index page.'''
    pcap_filename = "test.pcap" 
    analyser = Analyser(pcap_filename) 
    global _results
    _results = analyser.results()
    results = _results
    results_table = Stream_Table_Test(results)
    results_table.border = True
    #print "UI results:", repr(results)
    log("generate_analysis(): analysed")
    return render_template('results.html', results=results_table)

@app.route('/subresults/<int:cli_pt>')
def sub_results(cli_pt):
    global _results
    results = _results 
    subresults = None
    for result in results

    results_table = Stream_Table_Small(results)
    results_table.border = True
    return render_template('sub-results.html', results=results_table)

def log(msg): 
    '''Writes to a log file, for debugging purposes'''
    log_file = "ptp.log"
    msg += "\n"
    with open(log_file, "a") as f:
        f.write(msg)

if __name__ == "__main__":
    app.run(host= '0.0.0.0')
