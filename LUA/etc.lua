----------------------------------------
-- script-name: etc.lua
--
-- Author: Arjan van Vught <arjan.van.vught@gmail.com>
-- GitHub: https://github.com/vanvught/wireshark
-- Reference: https://www.etcconnect.com/WorkArea/DownloadAsset.aspx?id=10737494995
----------------------------------------

local etc_proto = Proto("etc","ETC Connect")

local message_ascii = ProtoField.string("etconnect.ascii", "ASCII", base.ASCII)

etc_proto.fields = { 
  message_ascii
}

function etc_proto.dissector(buffer, pinfo, tree)
  length = buffer:len()
 
  if length == 0 then return end

  pinfo.cols.protocol = "ETC"
  
  local subtree = tree:add(etc_proto,buffer(),"ETC Connect")
  subtree:add(message_ascii, buffer(0,length))
  
  pinfo.cols.info = buffer(0, length):string()
  
 end

udp_table = DissectorTable.get("udp.port")
udp_table:add(1234,etc_proto)