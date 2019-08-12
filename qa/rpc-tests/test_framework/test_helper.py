def get_dumpwallet_otp(msg):
    istart = msg.index(':')
    ifinish = msg.index('\n')
    return msg[istart+2:ifinish]