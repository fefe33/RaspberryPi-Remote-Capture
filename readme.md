## remote capture application
<h1>what it does</h1>
<p>allows for remote capture of a network on a remote device using TCPdump, then for download of the resulting pcap for further analysis on the client computer</p>
<h1>requirements</h1>
<ul>
  <li>TCPdump (serverside)</li>
  <li>Tcl/tk support (clientside)</li>
</ul>
<h1>setup/use:</h1>
<ol>
  <li>clone this repo to the IOT device of your choosing (that supports python and has tcpdump installed) *note this was originally designed and tested on a raspberry pi 4.</li>
  <li>cd into the "server" directory and add your client computer's IP address to the allow list (allow.txt)</li>
  <li>run <code>python3 server.py [host] [port]</code> to make the server start listening -- use '' or \* to run on all interfaces</li>
  <li>go over to your client PC and clone the repo there too (if you havent already).</li>
  <li>from there, cd into the server directory and run <code>python3 client.py [host] [port] [limit] </code> where [host] and [port] are that of the server, and [limit] is the number of packets you wish to capture </li>
</ol>
