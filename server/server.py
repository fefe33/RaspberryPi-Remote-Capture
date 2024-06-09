import socket, os, json, subprocess, sys, struct, argparse
'''
    the point of this program is to take commands and do specific actions based on those commands
    the client will send commands to the server, 
    the server will complete the action, 
    the server will then send the output and the newly created packet capture file back to the client via the same socket connection
    the server will then wait for more commands
'''
'''
    this is the json request object schema
    {
        'cmd':<program specific command>[str]
        (if cmd==capture)
        'limit':<num of packets>[int]
        'dir':<packet direction>[str]
    }
    these are the response signals:
        !O for output data which is to be printed to the screen on the clientside
        !F for file data which is to be downloaded, reassembled, and written to storage on the clientside in python 

    responses are separated by byte 0xFF for ease of separation by client (since all the data is sent as as stream)
    

'''




#this is the TCP socket server




class TCPserver:
    def __init__(self, HOST:str, PORT:int, debug:bool, interface: str):
        self.port = PORT
        self.host = HOST
        self.interface = interface
        self.debug = debug
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #bind to the socket
        self.sock.bind((self.host, self.port))
        self.running = False
        #get the file and append the IP addresses to self.valid_ips array
        self.valid_ips = []
        with open('{}/allow.txt'.format(os.path.dirname(os.path.realpath(__file__)))) as allowed:
            for i in allowed:
                self.valid_ips.append(i.rstrip('\n'))
    
   #this is called once the data has been decoded and no kill signal has been detected
    #it is also where the handler logic is applied
    def requestHandler(self, request, client_sock, addr):
        #request is of type obj
        if request['cmd'] == 'capture':
            #get the packet limit from the object
            command = ['sudo', 'tcpdump', '-c', str(request['limit'][0]), '-w', 'remote.pcap']
            try:
                if request['verbose'] == 'NONE':
            	    pass
                elif request['verbose']=='TEXT':
             	    command.append('--print')
                elif request['verbose']=='HEX':
                    command = command+['--print', '-XX']
            except:
                pass
            #start the process
            print('running command: ', repr(' '.join(command)))
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #wait for it to complete and communicate
            proc.wait()
            out = dict()
            #construct the first response object and start the file transfer
            out['put'], out['err'] = proc.communicate()
            if self.debug==True:
                print('output: ', out['put'], 'error: ', out['err'])
            #decode each value in the object
            out['put'] = out['put'].decode('utf-8')
            out['err'] = out['err'].decode('utf-8')
            r = bytes(json.dumps(out), 'utf-8')
            
            with open('remote.pcap', 'rb') as pcap:
                z = pcap.read()
            #use long long (8 bytes) for header length
            #get the length (in bytes) of the file (len() function isnt working) 
            if self.debug==True:
                print('output length', len(r))
            r = struct.pack('>Q',len(r))+r+z
            if self.debug==True:
                print('payload: ', repr(r))
            #close the current connection and open a new socket not related to self.sock
            print('creating new socket')
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print('attempting to connect to {}:{}'.format(addr[0], self.port+1))
            temp_sock.connect((addr[0], self.port+1))
            temp_sock.sendall(r)
            temp_sock.close()
        elif request['cmd'] == 'scan':
            #this is the nmap scan.
            #these are the scan mappings. values are 2 arrs (for quick injection of other flags)
            scan_mappings = {
                    'OS':[['sudo', 'nmap'], ['-O']],
                    'service':[['nmap'], ['-sV']],
                    'discover':[['nmap'],['-sn']],
                    'IP':[['sudo', 'nmap'], ['-sO']],
                    'TCP':[['nmap'], ['-sT']],
                    'UDP':[['sudo', 'nmap'], ['-sU']],
                    'stealth':[['sudo', 'nmap'], ['-sS']]
            }
            
            #lambda function to validate values
            validate = lambda t: (' ' not in t) and (';' not in t)
            #get the values from the required keys
            target = request['target']  
            method = request['method']
            #try to validate each value that needs validateion, closing connection on exception
            try:
                #next try to get the value for the ports [if its present] and add to list of values to validate, if not, carry on
                to_validate = [target]
                try:
                    ports = request['ports']
                    to_validate.append(ports)
                except:
                    pass
                #now validate
                for i in to_validate:
                    assert validate(i)
                assert method in list(scan_mappings.keys())
            except:
                print('bad request. closing connection.')
                client_sock.close()
                return False
            
            #assemble the command
            cmd = scan_mappings[method]
            #if the scan method is discover. dont bother adding the port specs
            if method == 'discover':
                cmd = cmd[0] + [target] + cmd[1]
            else:
                cmd = cmd[0]+[target, '-p', ports]+cmd[1]

            #check for spoof
            if 'spf' in list(request.keys()):
                if request['spf'] == 'mac':
                    cmd = cmd + ['--spoof-mac', '0']
                elif request['spf'] == 'IP':
                    cmd = cmd + ['-S', '0', '-e', self.interface]
                elif request['spf'] == 'all':
                    cmd = cmd + ['-S', 0, '-e', self.inteface, '-S', '0']
            #run the command
            print('running command: ', cmd)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #wait for the process to complete
            proc.wait()
            #get the data
            out, err = proc.communicate()
            #create the temporary socket
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            addr = (addr[0], self.port+1)
            print('returning data')
            if self.debug==True:
                print('establishing connection to client @ {}'.format(addr))
            temp_sock.connect(addr)
            raw_output = json.dumps({'put': out.decode('utf-8'),'err':err.decode('utf-8')}).encode('utf-8')
            if self.debug==True:
                print('connection successful. response payload: ', raw_output)
            temp_sock.sendall(raw_output)
            temp_sock.close()

    
        return True
                
    


    #when .service() method is called
    def service(self):
        #set self.running to True, bind to the socket and start listening
        self.running = True
        print('serving on {}:{}'.format(self.host, self.port))
        self.sock.listen()
        #while serving...
        while self.running:
            csock, addr = self.sock.accept()
            print('connection attempt from {}'.format(addr))
            #check the connection against the "allow list' table in 
            try: 
                assert addr[0] in self.valid_ips
                print('success. connection accepted.')
            except:
                print('host not on allow list. closing connection')
                csock.close()
                continue
        
            #recieve, and process the data 1024 bytes at a time 
            while True:
                data = csock.recv(1024)
                if not data:
                    break
                
                data = data.decode('utf-8')
                
                print('raw data recieved: ', data)
                #if its the kill signal
                if data == '!KILL':
                    csock.close()
                    self.sock.close()
                    self.running = False
                    break
                else:
                    #deserialize
                    data = json.loads(data)
                    #call request handler function and print the output
                    
                    print('handler success: ', self.requestHandler(data, csock, addr))
        
        #break the connection and exit the program
        print('\n\t -- WHY DID YOU KILL ME?! --\n\nprocess terminated.')
        exit(0)


#get and validate the args with the module
#only takes 2 -- host and port.
p = argparse.ArgumentParser()
p.add_argument('--addr', type=str, nargs=1, help='specifies the host and port the server should listen on [host:port]', required=True)
p.add_argument('-d','--debug', type=str, help='prints payload length and payload for use in debugging (use \'on\'/\'off\'')
p.add_argument('-si', '--interface', type=str, nargs=1, help='define the scan interface (default=wlan0 [may be different on your device])')
#parse them
args = p.parse_args()

#try to get port
try:
    address = args.addr[0].split(':')
    address[1] = int(address[1])
except:
    print('use <host>:<port> where <port> is an integer. see -h for help.')
    exit(-1)

#get the debug value as a boolean
try:
    if args.debug == 'on':
        debug = True
    elif args.debug == 'off':
        debug = False
    else:
        print('invalid arg set for debug (use on/off), setting to default=off')
        debug=False
except:
    print('no --debug arg set. default=off')
    debug=False
#if the first arg is *, make hostname empty string
if address[0] in ['*', '', ' ']:
	address[0] = ''

#try to get the interface. default to wlan0
try:
    iface = args.interface
    print('scan interface: ', args.interface)
except:
    print('defaulting to scan interface \'wlan0\' for interface (none specified)')
    iface = 'wlan0'

app = TCPserver(address[0], address[1], debug, iface)
app.service()



	
