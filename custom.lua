local myproto = Proto("custom", "Custom Protocol")

local f_flag = ProtoField.uint8("myproto.flag", "Flag", base.DEC)
local f_seq = ProtoField.uint32("myproto.seq", "Sequence Number", base.DEC)
local f_checksum = ProtoField.uint16("myproto.checksum", "Checksum", base.HEX)
local f_payload = ProtoField.bytes("myproto.payload", "Payload Data")

myproto.fields = { f_flag, f_seq, f_checksum, f_payload }

local flag_values = {
    [0] = "SYN",
    [1] = "SYN_ACK",
    [2] = "MESS",
    [3] = "ACK",
    [4] = "END",
    [5] = "KEEP_ALIVE",
    [6] = "NACK",
    [7] = "FILE_START",
    [8] = "CHUNK",
    [9] = "FILE_END",
    [10] = "MESS_END"
}

local function parse_payload(flag, buffer, offset, subtree)
    local payload_length = buffer:len() - offset
    if payload_length <= 0 then return end

    if flag == 2 then -- MESS (text message)
        subtree:add(buffer(offset, payload_length), "Text Message: "):append_text(buffer(offset, payload_length):string())
    elseif flag == 7 or flag == 8 then -- FILE_START or CHUNK
        subtree:add(buffer(offset, payload_length), "File Data (" .. payload_length .. " bytes)")
    elseif flag == 5 or flag == 6 then -- KEEP_ALIVE or NACK
        subtree:add(buffer(offset, payload_length), "Keep-Alive or NACK Data")
    else
        subtree:add(f_payload, buffer(offset, payload_length)):append_text(" (" .. payload_length .. " bytes)")
    end
end

function myproto.dissector(buffer, pinfo, tree)
    if buffer:len() < 7 then return end
    pinfo.cols.protocol = "MYPROTO"
    local subtree = tree:add(myproto, buffer(), "My Protocol Data")
    local flag = buffer(0, 1):uint()
    subtree:add(f_flag, buffer(0, 1)):append_text(" (" .. (flag_values[flag] or "Unknown") .. ")")
    local seq = buffer(1, 4):uint()
    subtree:add(f_seq, buffer(1, 4))
    local checksum = buffer(5, 2):uint()
    subtree:add(f_checksum, buffer(5, 2))
    parse_payload(flag, buffer, 7, subtree)
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(50601, myproto)
