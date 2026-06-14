lines = []
ips = ['192.168.1.1','10.0.0.1','172.16.0.1']
endpoints = ['/api/users','/api/login','/api/data']
codes = [200,404,500,401]
for i in range(50):
    ip = ips[i%3]
    ep = endpoints[i%3]
    code = codes[i%4]
    lines.append(f'{ip} - - [13/Jun/2026:1{i%4}:00:00 +0000] "GET {ep} HTTP/1.1" {code} 512 "Mozilla/5.0" response_time={i*10}')
with open(r'C:\Users\aiman\Downloads\test.log','w') as f:
    f.write('\n'.join(lines))
print('Done! File saved to Downloads!')




