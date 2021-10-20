
'''
    Extracts the UUID/GUID from the code to have a strong 
    Host based indicator that can be used reference to malware
    in the future.
'''


def guid_capture(ea):
    
    segment_1 = idc.GetManyBytes(ea,4)
    segment_1 = struct.unpack("<I",segment_1)[0]
    
    ea += 4
    segment_2 = idc.GetManyBytes(ea,2)
    segment_2 = struct.unpack("<H",segment_2)[0]
    

    ea += 2
    segment_3 = idc.GetManyBytes(ea,2)
    segment_3 = struct.unpack("<H",segment_3)[0]
    

    ea += 2
    segment_4 = idc.GetManyBytes(ea,2)
    segment_4 = struct.unpack(">H",segment_4)[0]
  

    ea += 2
    segment_5 = idc.GetManyBytes(ea,6)
    collection = ""
    for b in segment_5:
        collection += "%02x" % ord(b)
    #print data5Str
    return "%08x-%04x-%04x-%04x-%s" % (segment_1,segment_2,segment_3,segment_4,collection)
