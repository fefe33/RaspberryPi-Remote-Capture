import socket, os, json, subprocess, sys
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
    def __init__(self, HOST:str, PORT:int):
        self.port = PORT
        self.host = HOST
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        #get the file and append the IP addresses to self.valid_ips array
        self.valid_ips = []
        with open('{}/allow.txt'.format(os.path.dirname(os.path.realpath(__file__)))) as allowed:
            for i in allowed:
                self.valid_ips.append(i)
    
   #this is called once the data has been decoded and no kill signal has been detected
    #it is also where the handler logic is applied
    def requestHandler(request, client_sock):
        #request is of type obj
        if request['cmd'] == 'capture':
            #get the packet limit from the object
            command = ['sudo', 'tcpdump', '-c', request['limit'], '-w', 'remote.pcap']
              
            #start the process
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #wait for it to complete and communicate
            proc.wait()
            out = dict()
             #construct the first response object and start the file transfer
            out['put'], out['err'] = proc.communicate()
        
            r = [bytes('!O ','utf-8')+json.dumps(output)+bytes('\xff')]
            with open('remote.pcap', 'rb') as pcap:
                r.append(pcap.read())
            r = r[0]+r[1]
            client_sock.sendall(r)
            return True
                
    


    #when .service() method is called
    def service(self):
        #set self.running to True, bind to the socket and start listening
        self.running = True
        self.sock.bind((self.host, self.port))
        print('serving on {}:{}'.format(self.host, self.port))
        self.sock.listen()
        #while serving...
        while self.running:
            csock, addr = self.sock.accept()
            #check the connection against the "allow list' table in 
            try: 
                  assert addr[0] in self.valid_ips
            except:
                  csock.close()
                  continue

            #recieve, and process the data 1024 bytes at a time 
            while True:
                data = csock.recv(1024)
                if not data:
                    break
                
                data = data.decode('utf-8')
                print(data)
                #if its the kill signal
                if data == '!KILL':
                    sock.close()
                    self.running = False
                    break
                else:
                    #call request handler function and print the output
                    print(self.requestHandler(data, csock))
        
        #break the connection and exit the program
        print('why did you kill me.\nprocess completed. exiting')
        sock.close()
        exit(0)


#get and validate the args
args = sys.argv[1:]
if len(args)!=2:
	print('incorrect number of arguments. use <host> <port>')
	exit(-1)
try:
	#convert the port to integer. 
	args[1] = int(args[1])
except:
	print('port must be of type integer.')
	exit(-1)
	
#if the first arg is *, make hostname empty string
if args[0] == '*':
	args[0] = ''
app = TCPserver(args[0], args[1])
app.service()




