import socket, tkinter, json, os, sys
from tkinter import ttk
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
    class App(tkinter.Frame):
        def __init__(self, master=None):
            super().__init__(master)
            self.pack()

    def __init__(self, HOST, PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = (HOST, PORT)
        self.root = self.App()
        self.downloads_path = os.path.dirname(os.path.realpath(__name__))+'/captures'

    def prompt(self, t):
        #this is for the final popup
        # here are method calls to the window manager class
        #
        self.root.master.title("remote capture client")
        self.root.master.maxsize(1000, 400)
        self.root.master.minsize(500, 140)
        frm = ttk.Frame(self.root, padding=10)
        frm.grid()
        ttk.Label(frm, text=t).grid(column=0, row=0)
        ttk.Label(frm, text='process complete.', padding=40).grid(column=0, row=1)
        self.root.mainloop()

    def run(self, limit):
        print('attempting to connect on {}'.format(self.address))
        self.sock.connect(self.address)
        #send the request body:
        #this is the request for a capture
        capture = {
            'cmd':'capture',
            'limit': limit
        }
        self.sock.sendall(json.dumps(capture).encode('utf-8'))
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
        header_length = int(b[0].to_bytes())
        file_content = b[header_length+1:]
        output =  b[1:header_length+1].decode('utf-8')

        print('file_content: ', file_content)

        filepath = self.downloads_path+'/remote{}.pcap'.format(str(len(os.listdir(self.downloads_path))))
        with open(filepath, 'wb') as capture_file:
            for i in file_content:
                capture_file.write(i.to_bytes())
        #call the prompt button to display stdout/stderr and alert the user to the process having been completed

        self.prompt(output.decode('utf-8'))


# get and validate the args
args = sys.argv[1:]
if len(args) != 3:
    print('incorrect number of arguments. use <server> <port> <limit (for number of packets)>')
    exit(-1)
try:
    # convert the port to integer.
    args[1] = int(args[1])
except:
    print('port must be of type integer.')
    exit(-1)

#validate the


# if the first arg is *, make hostname empty string
if args[0] == '*':
    args[0] = ''
app = TCPserver(args[0], args[1])
app.service()



client_app = TCPclient(sys.argv[1], int())
client_app.run()
