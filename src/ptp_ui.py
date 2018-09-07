from flask import Flask, render_template, url_for, request
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

@app.route('/capture')
def capture():
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

@app.route('/results2')
def results2():
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
    #global _results
    #_results = analyser.get_analysis_results()
    results = analyser.get_analysis_results()
    #results = _results
    #results_table = Stream_Table_Test(results)
    results_table = Stream_Table(results)
    results_table.border = True
    #print "UI results:", repr(results)
    log("generate_analysis(): analysed")
    return render_template('results.html', results=results_table)

@app.route('/results-for-existing-pcapfile2')
def results_test2():
    '''Web page accessible via http://localhost/capture. Has results of capture, and a button to return to index page.'''
    pcap_filename = "test.pcap" 
    analyser = Analyser(pcap_filename) 
    results = analyser.get_analysis_results2()
    #print "UI results:", repr(results)
    log("generate_analysis(): analysed")
    return render_template('results2.html', results=results)

@app.route('/encryption_details')
def encryption_details():
    conn_id = request.args.get('conn_id')
    results = analyser.get_encryption_details_row(conn_id)
    return render_template('encryption_details.html', results=results)

@app.route('/connection_details')
def connection_details():
    conn_id = request.args.get('conn_id')
    results = analyser.get_connection_details_row(conn_id)
    return render_template('connection_details.html', results=results)

def log(msg): 
    '''Writes to a log file, for debugging purposes'''
    log_file = "ptp.log"
    msg += "\n"
    with open(log_file, "a") as f:
        f.write(msg)

if __name__ == "__main__":
    app.run(host= '0.0.0.0')
