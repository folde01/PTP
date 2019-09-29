# MSc Computer Science Final Project

Plain Text Police (or [PTP](https://github.com/folde01/PTP)) is an application which detects when mobile apps encrypt, or fail to encrypt their web traffic.

It is written in Python and runs on a Linux laptop. The user starts out by connecting a mobile device to the Internet via a dedicated VPN running locally on the laptop. PTP then intercepts the mobile device's web traffic, analyses it, and finally reports back to the user whether each connection used HTTP or HTTPS (or possibly that it couldn't decide either way). 

It decides this based on whether it saw a valid SSL handshake take place in the packets exchanged between the mobile device and the web server it contacted. Its traffic analyser extracts the packet payloads as strings and uses regular expressions to look for specific protocol codes at certain points in the flow of traffic. Writing the analyser required in-depth learning of parts of the TCP and SSL protocols, so a lot of experimentation with Wireshark and tcpdump.

The user interface runs in the browser, which in turn connects to a web server running on the laptop. The backend, built using Flask, controls PTP's interception, analysis and reporting functions. The analyser stores its results using MySQL.

I submitted PTP in 2018 and it was awarded a distinction (71). It was supervised by [Dr David Weston](http://www.dcs.bbk.ac.uk/~dweston/) at Birkbeck.

I'm happy to share the accompanying dissertation report with potential employers - please just get in touch. 

As discussed in that report's conclusion, PTP needs a lot of work. Not least is that its dependencies make it hard to install and get running, so I would be happy to demonstrate it in person or over Skype if need be.
