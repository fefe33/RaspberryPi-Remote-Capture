## remote capture application
<h1>what it does</h1>
<p>allows to perform packet capture and download of pcap over the network from a remote device using TCPdump as well as perform some general Nmap scans</p>
<h1>requirements</h1>
<ul>
  <li>TCPdump and Nmap (serverside)</li>
  <li>Tcl/tk support (clientside)</li>
</ul>
<h1>setup/use:</h1>
<ol>
  <li>clone this repo to the IOT device of your choosing (that supports python and has tcpdump installed) *note this was originally designed and tested on a raspberry pi 4.</li>
  <li>cd into the "server" directory and add your client computer's IP address to the allow list (allow.txt)</li>
  <li>run <code>python3 server.py --addr host:port --interface [scan_interface]</code> to make the server start listening and initiate its scan interface -- use '' or \* to run the server on all interfaces</li>
  <li>go over to your client host and clone the repo there too (if you havent already).</li>
  <li>from there, cd into the client directory and run <code>python3 client.py --addr [host]:[port] --cmd [CMD] [options...] </code> where <em>[host]</em> and <em>[port]</em> are that of the server, and <em>[CMD]</em> is the command you wish to run, and [options...] are the required (or optional) flags whose requirement vary depending on what is provided as [CMD]. see -h for usage.</li>
</ol>
