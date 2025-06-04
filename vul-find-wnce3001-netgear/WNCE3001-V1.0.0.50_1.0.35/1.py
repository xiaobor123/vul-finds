import socket

# 定义目标服务器和端口
host = "172.17.0.173"
port = 80
file = "../crashes/payload.txt"
f = open(file, "rb")
# 创建socket对象
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到服务器
s.connect((host, port))

# 构建HTTP请求
request = f.read()

# 发送请求
s.send(request)

# 接收服务器的响应
response = s.recv(4096)

# 打印响应内容
print(response.decode())

# 关闭连接
s.close()