import socket


target_host = "0.0.0.0"
target_port = 9998

#create a socket object and establish connect
client = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
client.connect((target_host, target_port))

#sent some b(bytes) data
#client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
client.send(b"ABCDE\n")

#receive data
response = client.recv(4096)
print(response.decode())
client.close()