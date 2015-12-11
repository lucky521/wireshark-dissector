# wireshark-lua
wireshark dissector by Lua


## Dissect your private network protocol 
- 怎么让wireshark调用lua脚本？
  - 首先保证lua调用开启，打开Wireshark安装目录的init.lua文件，搜索disable_lua(找到disable_lua = true; do return end;)，在这一行的开头添加--注释。
  - 将自己的Lua脚本复制到Wireshark安装目录内。
  - 在init.lua调用你的Lua插件：dofile('文件名.lua')。
  - 开始使用wireshark。
  
- 你需要对私有协议定义有充分的理解。

- 创建 Proto 对象，然后将其加入到 DissectorTable 中。


## Reference

- [Official Tutorial](https://wiki.wireshark.org/Lua/Examples)

- [Lua API in Wireshark](https://wiki.wireshark.org/LuaAPI)
