# smart_nmap

需要安装nmap、python和python-nmap库

```bash
python -m pip install python-nmap
```

扫描原理：

1. 首先PING，能PING通的主机加入存活列表；

2. PING不通的主机，扫描常见端口（可自定义）；
只要有任何一个端口开着，则加入存活列表。

3. 对存活列表中的所有主机，进行全端口扫描。

目前只是个demo，nmap扫描参数等请在代码中直接修改。