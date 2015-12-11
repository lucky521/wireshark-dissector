lu_proto = Proto("lucky","lucky protocol")


-- Declare a few fields that we are in
f_first = ProtoField.uint32("lucky.first", "firstfield", base.HEX)
f_second = ProtoField.uint32("lucky.second", "secondfield", base.HEX)
f_third = ProtoField.uint32("lucky.third", "thirdfield", base.DEC)
lu_proto.fields = {f_first, f_second, f_third}


-- add expert information
local test_info = ProtoExpert.new("lu_proto.test_info.expert", "testinfo",
                                     expert.group.REQUEST_CODE, expert.severity.CHAT)
lu_proto.experts = {test_info}


-- create a function to dissect it
function lu_proto.dissector(buffer, pinfo, tree)
    -- protocol title
    pinfo.cols.protocol = "LUCKY"
    local direction
    if (pinfo.src_port == 50002) then
        direction = "out  "
    else
        direction = "in"
    end

    -- create parent tree
    local subtree = tree:add(lu_proto, buffer(), "Lucky Protocol Data")

    offset = 0
    local first_value = buffer(offset,4):int()
    subtree:add(f_first, buffer(offset,4), first_value)
    -- tree:add(filed,, tvbrange, value)

    offset = offset + 4
    local second_value = buffer(offset,4):int()
    subtree:add(f_second,buffer(offset,4), second_value)

    offset = offset + 4
    local third_value = buffer(offset,4):int()
    subtree:add(f_third, buffer(offset,4), third_value)

    offset = offset + 4
    local all_len = buffer:len()
    subtree:add(buffer(offset,(all_len-12)), "Following Data")


    -- protocol info display
    pinfo.cols.info:append(". " .. direction .. " first=" .. tostring(first_value) .. ",second=" .. tostring(second_value) .. ",third=" .. tostring(third_value) )
end


DissectorTable.get("udp.port"):add(50002, lu_proto)