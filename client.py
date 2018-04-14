from socket import socket, SOCK_DGRAM, AF_INET

for i in range(10):
    print(i)
    client_socket = socket(AF_INET, SOCK_DGRAM)
    client_socket.settimeout(1.0)
    message = b'test'
    client_socket.sendto(message, ('127.0.0.1', 9000))
    data, server = client_socket.recvfrom(1024)
    print(data)
