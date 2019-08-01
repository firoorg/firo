def parse_tmp_dumpwallet_code_from_warning(msg):
    istart = msg.index(':')
    ifinish = msg.index('\n')
    return msg[istart+2:ifinish]