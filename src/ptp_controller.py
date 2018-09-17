from flask import Flask, render_template, url_for, request
from ptp_analyser import Analyser

app = Flask(__name__)
analyser = Analyser()
_results = None


@app.route('/index')
@app.route('/')
def index():  
    """UI page where user can start capture."""
    return render_template('index.html')

@app.route('/capture')
def capture():
    """UI page where user can stop capture and go to main results page.
    
    Note: 
        start_sniffing() is located here because the user is taken here 
        immediately upon clicking the start button in the /index page.
        start_sniffing() starts up a background thread so that the /capture 
        page can finish loading (otherwise it won't ever load and the user
        will never see the stop button.)
    """
    
    analyser.start_sniffing()
    log("start_capture(): traffic capture started")
    return render_template('capturing.html')


@app.route('/results')
def results():
    """Main results page - also has a start again button taking user back to /index.

    Note:
        The results.html template sends back links that allow the user to drill
        down for TCP/IP and SSL related information about each connection.
    """
    analyser.stop_sniffing()
    #log("stop_capture(): traffic capture stopped")
    results = analyser.get_analysis_results()

    if results:
        return render_template('results.html', results=results)
    else:
        return render_template('no_results.html')


@app.route('/encryption_details')
def encryption_details():
    """Page for encryption details about the connection the user is
    interested in. Reached via a link on /results page.
    """
    conn_id = request.args.get('conn_id')
    results = analyser.get_encryption_details_row(conn_id)
    return render_template('encryption_details.html', results=results)


@app.route('/connection_details')
def connection_details():
    """Page for TCP/IP details about the connection the user is
    interested in. Reached via a link on /results page.
    """
    conn_id = request.args.get('conn_id')
    results = analyser.get_connection_details_row(conn_id)
    return render_template('connection_details.html', results=results)


@app.route('/results-for-existing-pcapfile')
def results_test():
    """For testing"""
    pcap_filename = "test-pcap-files/controller-test.pcap" 
    analyser = Analyser(pcap_filename) 
    results = analyser.get_analysis_results()
    #print "UI results:", repr(results)
    log("generate_analysis(): analysed")
    return render_template('results.html', results=results)


def log(msg): 
    """Writes to a log file, for debugging purposes"""
    log_file = "ptp.log"
    msg += "\n"
    with open(log_file, "a") as f:
        f.write(msg)

if __name__ == "__main__":
    app.run(host='localhost')
