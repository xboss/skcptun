import socket
remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
remote.bind(('192.168.2.2', 0))
remote.connect(('110.242.68.3', 80))
#remote.connect(('192.168.2.2', 80))
remote.send("12345")
