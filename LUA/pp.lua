----------------------------------------
-- script-name: pp.lua
--
-- Author: Arjan van Vught <arjan.van.vught@gmail.com>
-- GitHub: https://github.com/vanvught/wireshark
----------------------------------------

local pp_proto = Proto("pp","PixelPusher")

local device_types = {
	[0] = "Etherdream",
	[1] = "Lumiabridge",
	[2] = "PixelPusher"
}

local set_not_set = {
	[0] = "Not set",
	[1] = "Set"
}

-- Header

local device_type = ProtoField.uint8("pp.discovery.header.devicetype", "Device type", base.DEC, device_types)
local vender_id = ProtoField.uint16("pp.discovery.header.venderid", "Vender Id", base.HEX)
local product_id = ProtoField.uint16("pp.discovery.header.productid", "Product Id", base.HEX)
local hw_revision = ProtoField.uint16("pp.discovery.header.hwrevision", "Hardware revision", base.DEC)
local sw_revision = ProtoField.uint16("pp.discovery.header.swrevision", "Software revision", base.DEC)
local link_speed = ProtoField.uint32("pp.discovery.header.linkspeed", "Link speed", base.DEC)

-- Pixel Pusher Base
local strips_attached = ProtoField.uint8("pp.discovery.pixelpusherbase.stripsattached", "Strips attached", base.DEC)
local max_strips_per_packet = ProtoField.uint8("pp.discovery.pixelpusherbase.maxstripsperpacket", "Max strips per packet", base.DEC)
local pixels_per_strip = ProtoField.uint16("pp.discovery.pixelpusherbase.pixelsperstrip", "Pixels per strip", base.DEC)
local update_period = ProtoField.uint32("pp.discovery.pixelpusherbase.updateperiod", "Update period", base.DEC)
local power_total = ProtoField.uint32("pp.discovery.pixelpusherbase.powertotal", "Power total", base.DEC)
local delta_sequence = ProtoField.uint32("pp.discovery.pixelpusherbase.deltasequence", "Delta sequence", base.DEC)
local controller_ordinal = ProtoField.int32("pp.discovery.pixelpusherbase.controllerordinal", "Controller ordinal", base.DEC)
local group_ordinal = ProtoField.int32("pp.discovery.pixelpusherbase.groupordinal", "Group ordinal", base.DEC)
local artnet_universe = ProtoField.uint16("pp.discovery.pixelpusherbase.artnetuniverse", "Art-Net universe", base.DEC)
local artnet_channel = ProtoField.uint16("pp.discovery.pixelpusherbase.artnetchannel", "Art-Net channel", base.DEC)
local my_port = ProtoField.uint16("pp.discovery.pixelpusherbase.myport", "My port", base.DEC)
local padding = ProtoField.uint16("pp.discovery.pixelpusherbase.padding", "Padding", base.HEX)

local strip_flag_rgbow = ProtoField.uint8("pp.discovery.pixelpusherbase.stripflag.rgbow", "RGBOW", base.DEC, set_not_set , 0x01)
local strip_flag_widepixels = ProtoField.uint8("pp.discovery.pixelpusherbase.stripflag.widepixels", "WIDEPIXELS", base.DEC, set_not_set , 0x02)
local strip_flag_logarithmic = ProtoField.uint8("pp.discovery.pixelpusherbase.stripflag.logarithmic", "LOGARITHMIC", base.DEC, set_not_set , 0x04)
local strip_flag_motion = ProtoField.uint8("pp.discovery.pixelpusherbase.stripflag.motion", "MOTION", base.DEC, set_not_set , 0x08)
local strip_flag_notidepotent = ProtoField.uint8("pp.discovery.pixelpusherbase.stripflag.motion", "NOTIDEMPOTENT", base.DEC, set_not_set , 0x10)
local strip_flag_brightness = ProtoField.uint8("pp.discovery.pixelpusherbase.stripflag.brightness", "BRIGHTNESS", base.DEC , set_not_set , 0x20)

-- Pixel Pusher Ext
local padding = ProtoField.uint16("pp.discovery.pixelpusherext.padding", "Padding", base.HEX)
local strip_count_16 = ProtoField.uint16("pp.discovery.pixelpusherext.stripcount16", "Strip count", base.DEC)

local pusher_flag_global_protected = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.protected", "PROTECTED", base.DEC , set_not_set , 0x0001)
local pusher_flag_fixed_size = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.fixedsize", "FIXEDSIZE", base.DEC , set_not_set , 0x0002)
local pusher_flag_global_brightness = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.globalbrightness", "GLOBALBRIGHTNESS", base.DEC , set_not_set , 0x0004)
local pusher_flag_strip_brightness = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.stripbrightness", "STRIPBRIGHTNESS", base.DEC , set_not_set , 0x0008)
local pusher_flag_dynamics = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.dynamics", "DYNAMICS", base.DEC , set_not_set , 0x0010)
local pusher_flag_can_buffer = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.canbuffer", "CANBUFFER", base.DEC , set_not_set , 0x0020)
local pusher_flag_16bit_stuf = ProtoField.uint32("pp.discovery.pixelpusherext.pusherflag.16bitstuff", "16BITSTUFF", base.DEC , set_not_set , 0x0040)


local segments = ProtoField.uint32("pp.discovery.pixelpusherext.segments", "Segments", base.DEC)
local power_domain = ProtoField.uint32("pp.discovery.pixelpusherext.powerdomain", "Power domain", base.DEC)
local last_driven_ip = ProtoField.uint32("pp.discovery.pixelpusherext.lastdrivenip", "Last driven ip")
local last_driven_port = ProtoField.uint16("pp.discovery.pixelpusherext.lastdrivenport", "Last driven port", base.DEC)

-- Data
local sequence_number = ProtoField.uint32("pp.discovery.data.sequencenummer", "Sequence number", base.DEC)
local strip_number = ProtoField.uint8("pp.discovery.data.stripnumber", "Strip number", base.DEC)

local number_of_pusher_commands = ProtoField.uint16("pp.discovery.data.numberofpushercommands", "Pusher commands", base.DEC)

pp_proto.fields = { 
	device_type, vender_id, product_id, hw_revision, sw_revision, link_speed,
	strips_attached, max_strips_per_packet, pixels_per_strip, update_period, power_total, delta_sequence, controller_ordinal, group_ordinal, artnet_universe, artnet_channel, my_port, 
	strip_flag_rgbow, strip_flag_widepixels, strip_flag_logarithmic, strip_flag_motion, strip_flag_notidepotent, strip_flag_brightness,
	padding, strip_count_16,
	pusher_flag_global_protected, pusher_flag_fixed_size, pusher_flag_global_brightness, pusher_flag_strip_brightness, pusher_flag_dynamics, pusher_flag_can_buffer, pusher_flag_16bit_stuf,
	segments, power_domain, last_driven_ip, last_driven_port,
	sequence_number, strip_number, number_of_pusher_commands
}

function parse_strip_flags(buffer, tree) 
	tree:add(strip_flag_rgbow, buffer)
	tree:add(strip_flag_widepixels, buffer)
	tree:add(strip_flag_logarithmic, buffer)
	tree:add(strip_flag_motion, buffer)
	tree:add(strip_flag_notidepotent, buffer)
	tree:add(strip_flag_brightness, buffer)
end

local flag_16bit_stuff = 0

-- sizeof(struct DiscoveryPacket)=84
-- sizeof(struct DiscoveryPacketHeader)=24
-- sizeof(struct PixelPusher)=60
-- sizeof(struct PixelPusherBase)=40
-- sizeof(struct PixelPusherExt)=20

function pp_proto.dissector(buffer, pinfo, tree)
  length = buffer:len()
 
 	if length == 0 then return end

 	pinfo.cols.protocol = "PP"

 	local subtree = tree:add(pp_proto,buffer(),"Pixel Pusher")

 	if pinfo.dst_port == 7331 then
 			if length < 84 then
   	 		subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "The Discovery packet is malformed")
			end

 			flag_16bit_stuff = bit.band(buffer(66,4):le_uint(), 0x0040)
			
			if flag_16bit_stuff == 0 then
				pinfo.cols.info = "Discovery"
			else
				pinfo.cols.info = "Discovery [16BITSTUFF]"
			end
	 		
	 		local discoverytree = subtree:add(pp_proto,buffer(),"Discovery")
	 		
	 		local discoveryheadertree = discoverytree:add(pp_proto,buffer(0,24),"Header")
	 		discoveryheadertree:add(buffer(0,6),"MAC:", buffer(0,1):bytes():tohex() .. ":" .. buffer(1,1):bytes():tohex() .. ":" .. buffer(2,1):bytes():tohex() .. ":" .. buffer(3,1):bytes():tohex().. ":" .. buffer(4,1):bytes():tohex().. ":" .. buffer(5,1):bytes():tohex())
	 		discoveryheadertree:add(buffer(6,4),"IP:", buffer(6,1):uint() .. "." .. buffer(7,1):uint() .. "." .. buffer(8,1):uint() .. "." .. buffer(9,1):uint())
			discoveryheadertree:add(device_type, buffer(10,1))
			discoveryheadertree:add(buffer(11,1), "Protocol version:", buffer(11,1):uint())
			discoveryheadertree:add_le(vender_id, buffer(12,2))
			discoveryheadertree:add_le(product_id, buffer(14,2))
			discoveryheadertree:add_le(hw_revision, buffer(16,2))
			discoveryheadertree:add_le(sw_revision, buffer(18,2))
			discoveryheadertree:add_le(link_speed, buffer(20,4))

			local pixelpusherbasetree = discoverytree:add(pp_proto,buffer(24, 40),"Pixel Pusher Base")
			pixelpusherbasetree:add(strips_attached, buffer(24,1))

			if flag_16bit_stuff ~= 0 then
				if buffer(24,1):uint() ~= 1 then
					pixelpusherbasetree:add_expert_info(PI_MALFORMED, PI_ERROR, "if PFLAG_16BITSTUFF, this must be set to 1")
				end
			end

			pixelpusherbasetree:add(max_strips_per_packet, buffer(25,1))
			pixelpusherbasetree:add_le(pixels_per_strip, buffer(26,2))
			pixelpusherbasetree:add_le(update_period, buffer(28,4))
			pixelpusherbasetree:add_le(power_total, buffer(32,4))
			pixelpusherbasetree:add_le(delta_sequence, buffer(36,4))
			pixelpusherbasetree:add_le(controller_ordinal, buffer(40,4))
			pixelpusherbasetree:add_le(group_ordinal, buffer(44,4))
			pixelpusherbasetree:add_le(artnet_universe, buffer(48,2))
			pixelpusherbasetree:add_le(artnet_channel, buffer(50,2))
			pixelpusherbasetree:add_le(my_port, buffer(52,2))
			pixelpusherbasetree:add_le(padding, buffer(54,2))

			local stripflagstree = pixelpusherbasetree:add(pp_proto,buffer(56,8),"Strip flags")
			stripflagstree:add(buffer(54,1), "1:", "0x" .. buffer(56,1):bytes():tohex())
			parse_strip_flags(buffer(54,1), stripflagstree)
			stripflagstree:add(buffer(55,1), "2:", "0x" .. buffer(57,1):bytes():tohex())
			parse_strip_flags(buffer(55,1), stripflagstree)
			stripflagstree:add(buffer(56,1), "3:", "0x" .. buffer(58,1):bytes():tohex())
			parse_strip_flags(buffer(56,1), stripflagstree)
			stripflagstree:add(buffer(57,1), "4:", "0x" .. buffer(59,1):bytes():tohex())
			parse_strip_flags(buffer(57,1), stripflagstree)
			stripflagstree:add(buffer(58,1), "5:", "0x" .. buffer(60,1):bytes():tohex())
			parse_strip_flags(buffer(58,1), stripflagstree)
			stripflagstree:add(buffer(59,1), "6:", "0x" .. buffer(61,1):bytes():tohex())
			parse_strip_flags(buffer(59,1), stripflagstree)
			stripflagstree:add(buffer(60,1), "7:", "0x" .. buffer(61,1):bytes():tohex())
			parse_strip_flags(buffer(60,1), stripflagstree)
			stripflagstree:add(buffer(61,1), "8:", "0x" .. buffer(62,1):bytes():tohex())
			parse_strip_flags(buffer(61,1), stripflagstree)

			local pixelpusherexttree = discoverytree:add(pp_proto,buffer(64, 20),"Pixel Pusher Ext")

			if flag_16bit_stuff == 0 then
				pixelpusherexttree:add(padding, buffer(64,2))
			else
				pixelpusherexttree:add_le(strip_count_16, buffer(64,2))
			end

			local pusherflagstree = pixelpusherexttree:add(pp_proto,buffer(66,4),"Pusher Flags")
			pusherflagstree:add_le(pusher_flag_global_protected, buffer(66,4))
			pusherflagstree:add_le(pusher_flag_fixed_size, buffer(66,4))
			pusherflagstree:add_le(pusher_flag_global_brightness, buffer(66,4))
			pusherflagstree:add_le(pusher_flag_strip_brightness, buffer(66,4))
			pusherflagstree:add_le(pusher_flag_dynamics, buffer(66,4))
			pusherflagstree:add_le(pusher_flag_can_buffer, buffer(66,4))
			pusherflagstree:add_le(pusher_flag_16bit_stuf, buffer(66,4))

			pixelpusherexttree:add_le(segments, buffer(70,4))
			pixelpusherexttree:add(power_domain, buffer(74,4))
			pixelpusherexttree:add(buffer(78,4), "Last driven IP:", buffer(78,1):uint() .. "." .. buffer(79,1):uint() .. "." .. buffer(81,1):uint() .. "." .. buffer(82,1):uint())
			pixelpusherexttree:add_le(last_driven_port, buffer(82,2))

			local device_type =  buffer(10,1):uint()
			local device_type_text = device_types[device_type]
 	end

 	if pinfo.dst_port == 5078 then
 		local datatree = subtree:add(pp_proto,buffer(),"Data")
 		datatree:add_le(sequence_number, buffer(0,4))
 		
 		if flag_16bit_stuff == 0 then
 			datatree:add(strip_number, buffer(4,1))

 			local data_size = length - 5
 			datatree:add(buffer(5,data_size),"Data: " .. buffer(5,data_size))
 
 			pinfo.cols.info = "Data Sequence=" .. buffer(0,4):le_uint() .. " Strip number=" .. buffer(4,1):uint() .. " Size=" .. data_size
 		else
 			datatree:add_le(number_of_pusher_commands, buffer(4,2))
 			local data_size = length - 8
			
			if buffer(4,2):le_uint() == 0 then
				datatree:add(strip_number, buffer(6,2):le_uint())
 				datatree:add(buffer(8,data_size),"Data: " .. buffer(8,data_size))

 				pinfo.cols.info = "Data Sequence=" .. buffer(0,4):le_uint() .. " Strip number=" .. buffer(6,2):le_uint() .. " Size=" .. data_size
			else
				datatree:add(buffer(7,data_size),"Pusher command: " .. buffer(7,data_size))
			end
 		end
 	end

end

udp_table = DissectorTable.get("udp.port")
udp_table:add(7331,pp_proto)
udp_table:add(5078,pp_proto)