import socket, tkinter, json, os, sys, struct, argparse
from tkinter import scrolledtext
#this is the client for the IOT application
'''
    the goal of this program is to
    initiate the connection to the server
    send the appropriate JSON request to the server
    wait for the server to return some data
    split the data at ['0x20', '0xFF']
    write the data in the first spot of the array to the screen
    write the rest of the data to a PCAP file
    
        
'''
# create the application

class TCPclient:
    #subclass the tkinter frame class (for window management functions)

    def __init__(self, HOST, PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = (HOST, PORT)
        self.window = tkinter.Tk()
        self.downloads_path = os.path.dirname(os.path.realpath(__name__))+'/captures'
        self.cmds = ['capture', 'scan']

    def prompt(self, out, err, path):
        # create main window
        self.window.title('remote capture manager')
        self.window.geometry('980x450')
        # write the scrollbox titles
        TB_labelA = tkinter.Label(self.window, text='output:')
        TB_labelB = tkinter.Label(self.window, text='errors:')
        TB_labelA.grid(column=0, row=0, sticky='nsew')
        TB_labelB.grid(column=1, row=0, sticky='nsew')
        # create the scroll boxes, and make them sticky in all directions. make each in its own column on the same row
        text_area1 = scrolledtext.ScrolledText(self.window, wrap=tkinter.WORD)
        text_area1.grid(column=0, row=1, sticky='nsew')
        text_area2 = scrolledtext.ScrolledText(self.window, wrap=tkinter.WORD)
        text_area2.grid(column=1, row=1, sticky="nsew")
        #add the footer label with the path to the download
        footer = tkinter.Label(self.window, text='success. pcap downloaded to {}'.format(path.replace('/', '\\')))
        footer.grid(column=0, columnspan=2, row=2, sticky="ew")
        # configure the rows and columns for all 3 indexes
        for i in range(3):
            self.window.grid_rowconfigure(i, weight=1)
            self.window.grid_columnconfigure(i, weight=1)

        text_area1.insert(tkinter.INSERT, out)
        text_area2.insert(tkinter.INSERT, err)
        self.window.mainloop()

    '''
        'cmd' values:
            'capture' -- for remote capture
            'scan' -- to initiate remote scan
    '''

    def run(self, cmd, options):
        print('attempting to connect on {}'.format(self.address))
        self.sock.connect(self.address)
        #create the request and validate that the comand is valid and  is a valid one
        action = {
            'cmd': cmd
        }


        #this is the request for a capture
        if cmd == 'capture':
            #all options are required (for simplicities sake)
            req = ['limit', 'verbose']
            #check for required options
            #construct the request:
            action['limit'] = options['limit']
            action['verbose'] = options['verbose']









        self.sock.sendall(json.dumps(action).encode('utf-8'))
        #close the connection
        self.sock.close()
        #wait for the incoming data and append it to buffer b
        b = b''
        self.sock.close()
        #reopen the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #listen on the provided port plus one (presuming it isnt already in use) while waiting for the capture to complete and the download to start
        new_port = self.address[1]+1
        self.sock.bind((socket.gethostbyname(socket.gethostname()), new_port))
        print('waiting for capture to complete')
        self.sock.listen(1)
        b = b''
        csock, addr = self.sock.accept()
        # print('connection attempt from {}'.format(addr))
        #ensure the connection is from the same IP the connection was initiated to
        try:
            assert self.address[0] == addr[0]
            # print('connection attempt successful.')
        except:
            print('connection attempt failed -- unauthorized host. closing connection.')
            csock.close()
            exit(-1)
        print('downloading file (this may take a while)')

        while True:
            d = csock.recv(1024)
            if not d or d == b'':
                break
            b += d

        print('file recieved. parsing output')
        #parse the output
        output_length = struct.unpack('>Q', b[0:8])[0]
        #remove the length header
        b = b[8:]
        print('length: ',output_length)
        #add 1 to output length for index
        file_content = b[output_length:]
        output =  b[:output_length].decode('utf-8')

        print('file_content: ', file_content)

        filepath = self.downloads_path+'/remote{}.pcap'.format(str(len(os.listdir(self.downloads_path))))
        with open(filepath, 'wb') as capture_file:
            for i in file_content:
                capture_file.write(i.to_bytes())
        #call the prompt button to display stdout/stderr and alert the user to the process having been completed
        print('pre-deserialized output: ', output)
        output = json.loads(output) #this will determine whether the buffer is being read/calculated correctly

        self.prompt(output['put'], output['err'], filepath)

#parse the args
p = argparse.ArgumentParser(
    prog='client.py',
    description='use this program to connect to the IOT capture server'
)
p.add_argument('--addr', type=str, nargs=1, help='specifies the host and port you wish to connect to [host:port]', required=True)
p.add_argument('-c', '--cmd', type=str, nargs=1, help='the command you wish to run [\'capture\' or \'scan\'])')
p.add_argument('-l', '--limit', type=int, nargs=1, help='this specefies how many packets you wish to capture [if performing a capture]')
p.add_argument('-v', '--verbose', type=int, nargs=1, help='specifies verbosity level.\n\t0=none\n\t1=verbose (text only)\n\t2=verbose (hex/ascii) --> [may run into buffer errors] if size is too large for transport')

args = p.parse_args()

try:
    address = args.addr[0].split(':')
    address[1] = int(address[1])
except:
    print('port must be of type int. see -h for help')
    exit(-1)
client_app = TCPclient(address[0], address[1])

#handle the other arguments
#first the command
cmd = args.cmd[0]
valid_commands = ['capture', 'scan']
try:
    assert cmd in valid_commands
except:
    print('{} is not a valid command'.format(cmd))
    exit(-1)


#next handle the conditionals:
if cmd == valid_commands[0]: # if its a capture ----------
    #check for invalid arguments [of which there are currently none]
    #check the request mode and convert to string

    #try to construct the object:
    try:
        verbose = args.verbose[0]
        print(verbose)
        if verbose == 0:
            v = 'NONE'
        elif verbose == 1:
            v = 'TEXT'
        elif verbose == 2:
            v = 'HEX'
        o = {
            'limit':args.limit,
            'verbose':v
        }
    except:
        print('missing required argument.\nrequired args for captures are --limit (or -l) and --verbose (or -v). see -h for help')
        exit(-1)

client_app.run(cmd, o) #takes 2 options, str(command) and dict(options)





