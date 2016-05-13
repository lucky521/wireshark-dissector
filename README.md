# wireshark-dissector
There are multiple method to parse wirshark pcap, in real time or offtime.

## Dissect your private network protocol using Lua
- 怎么让wireshark调用lua脚本？
  - 首先保证lua调用开启，打开Wireshark安装目录的init.lua文件，搜索disable_lua(找到disable_lua = true; do return end;)，在这一行的开头添加--注释。
  - 将自己的Lua脚本复制到Wireshark安装目录内。
  - 在init.lua调用你的Lua插件：dofile('文件名.lua')。
  - 开始使用wireshark。
  
- 你需要对私有协议定义有充分的理解。

- 创建 Proto 对象，然后将其加入到 DissectorTable 中。


## Parse your pcap file using Python
Dpkt pylib is a fast and simple packet creation / parsing, with definitions for the basic TCP/IP protocols.
我可以在其基础上再自定义解析应用层数据包。


## Reference

- [Official Tutorial](https://wiki.wireshark.org/Lua/Examples)

- [Lua API in Wireshark](https://wiki.wireshark.org/LuaAPI)
