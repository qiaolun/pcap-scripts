#!/usr/bin/env python

from pcappy import open_offline

import sys
import pcap
import string
import time
import socket
import struct
import json


stats = {'continous_request':0, 'continous_request_skip':0, 'continous_response':0, 'continous_response_skip':0, 'not_fin':0, 'skip_ack':0, 'skip_no_syn':0, 'skip_fin':0, 'skip_other':0}
tmp_stream_index = 0
tmp_streams = {}


if not sys.argv[1:]:
    print 'usage: %s <dump.pcap>' % sys.argv[0]
    exit(-1)

# Open the file
p = open_offline(sys.argv[1])

# or this instead: p = PcapPyOffline(argv[1])


# Parse only HTTP traffic
#p.filter = 'tcp and port 80'

def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s)) 
    for i in xrange(0,len(bytes)/16):
        print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
    print '        %s' % string.join(bytes[(i+1)*16:],' ')

def hex_string(s):
    return ''.join( [ "%02X" % ord( x ) for x in s ] )

def ip_string(s):
    return '.'.join( [ "%d" % ord( x ) for x in s ] )

def port_string(s):
    return struct.unpack('>H', s)[0]

def print_packet(data, ts, size):
    global tmp_streams, tmp_stream_index, stats

    if not data:
        return

    ip_src = ip_string(data[0x1c:0x20])
    ip_dst = ip_string(data[0x20:0x24])

    port_src = port_string(data[0x24:0x26])
    port_dst = port_string(data[0x26:0x28])

    # print "%s(%s) -> %s(%s)" % ( ip_src, port_src, ip_dst, port_dst )


    tcp_seq = data[0x28:0x2c]
    # print hex_string(tcp_seq)
    # dumphex(tcp_seq)
 
    tcp_header_len = ord(data[0x30]) >> 2
    psh_offset = 0x24 + tcp_header_len
    tcp_header_flag = ord(data[0x31])

    tcp_flags = {'ACK':0, 'PSH':0, 'SYN':0, 'FIN':0}
    tcp_flags['ACK'] = ( tcp_header_flag & 0b00010000 ) >> 4
    tcp_flags['PSH'] = ( tcp_header_flag & 0b00001000 ) >> 3
    tcp_flags['SYN'] = ( tcp_header_flag & 0b00000010 ) >> 1
    tcp_flags['FIN'] = ( tcp_header_flag & 0b00000001 )

    # print tcp_flags

    mc_cmd = data[psh_offset:]
    mc_cmd_len = size - psh_offset
    # print mc_cmd

    stream_key = ''
    if ip_src > ip_dst:
        stream_key = '%s:%s_%s:%s' % (ip_src, port_src, ip_dst, port_dst)
    else:
        stream_key = '%s:%s_%s:%s' % (ip_dst, port_dst, ip_src, port_src)

    
 
    if tcp_flags['SYN'] and not tcp_flags['ACK']:
        # connect

        if stream_key in tmp_streams:
            stats['not_fin'] += 1
            

        tmp_streams[stream_key] = {
            'stream'        : 0,
            'ts_begin'      : ts,
            'ts_end'        : 0,
            'mmc_cmds'      : [],
            'mmc_cmd_last'  : None,
            'mmc_cmd_last_t': 0,
        }

    elif tcp_flags['FIN'] and tcp_flags['ACK'] and port_dst == 11211:
        # disconnect

        if not stream_key in tmp_streams:
            # print 'skip fin'
            stats['skip_fin'] += 1
            return

        tmp_streams[stream_key]['ts_end'] = ts

        tmp_stream_index += 1
        tmp_streams[stream_key]['stream'] = tmp_stream_index

        print json.dumps(tmp_streams[stream_key])

        del tmp_streams[stream_key]


    elif port_dst != 11211:
        # response

        if not stream_key in tmp_streams:
            # print 'no syn'
            stats['skip_no_syn'] += 1
            return

        x_len = mc_cmd_len
        x_res = (mc_cmd.split(' ')[0]).strip()

        if tmp_streams[stream_key]['mmc_cmd_last'] and x_res in ['VALUE', 'STORED', 'END']:
            if x_res == 'VALUE':
                x_len = int( ((mc_cmd.split(' ')[3]).split('\n')[0]).strip() )

            cmd = {
                'req' : tmp_streams[stream_key]['mmc_cmd_last'], 
                'res' : x_res,
                'tc'  : int(1000000 * (ts - tmp_streams[stream_key]['mmc_cmd_last_t'])),
                'req_len' : tmp_streams[stream_key]['mmc_cmd_last_l'],
                'res_len' : x_len,
                'svr' : (ip_src, port_src),
            }
            tmp_streams[stream_key]['mmc_cmds'].append(cmd)

            tmp_streams[stream_key]['mmc_cmd_last'] = None
            tmp_streams[stream_key]['mmc_cmd_last_l'] = 0
            tmp_streams[stream_key]['mmc_cmd_last_t'] = 0
        else:
            stats['continous_response_skip'] += 1

            """
            print >> sys.stderr, ""
            print >> sys.stderr, "skip response"
            print >> sys.stderr, "%s(%s) -> %s(%s)" % ( ip_src, port_src, ip_dst, port_dst )
            print >> sys.stderr, tmp_streams[stream_key]
            print >> sys.stderr, repr(mc_cmd)
            """

    elif port_dst == 11211:

        if not stream_key in tmp_streams:
            # print 'no syn'
            stats['skip_no_syn'] += 1
            return

        # request
        
        x_len = mc_cmd_len
        x_cmd = (mc_cmd.split(' ')[0]).strip()
        if x_cmd in ['set','add']:
            x_len = int( (((mc_cmd.split(' ')[4]).split('\n'))[0]).strip() ) + len(' '.join(mc_cmd.split('\r')[0]))

        if x_cmd not in ['get', 'set', 'delete', 'add']:
            stats['continous_request_skip'] += 1

            """
            print >> sys.stderr, ""
            print >> sys.stderr, "skip request"
            print >> sys.stderr, "%s(%s) -> %s(%s)" % ( ip_src, port_src, ip_dst, port_dst )
            print >> sys.stderr, tmp_streams[stream_key]
            print >> sys.stderr, repr(mc_cmd)
            """
        
        else :
            
            # cmd start
            tmp_streams[stream_key]['mmc_cmd_last'] = (' '.join(mc_cmd.split(' ')[:2])).strip()
            tmp_streams[stream_key]['mmc_cmd_last_l'] = x_len
            tmp_streams[stream_key]['mmc_cmd_last_t'] = ts

        
    elif tcp_flags['ACK'] and not tcp_flags['PSH'] and not tcp_flags['FIN'] and not tcp_flags['SYN']:
        # print "skip ack %s(%s) -> %s(%s) %s" % ( ip_src, port_src, ip_dst, port_dst, repr(tcp_flags))
        stats['skip_ack'] += 1
        
    else:
        # skip tcp packet
        #print "skip packet %s(%s) -> %s(%s) %s" % ( ip_src, port_src, ip_dst, port_dst, repr(tcp_flags))
        stats['skip_other'] += 1


def gotpacket(d, hdr, data):
    ts = ( hdr['ts']['tv_sec'] + hdr['ts']['tv_usec'] / 1000000.0 )
    # print '%f, %d' % ( ts, hdr['len'] )
    # print repr(data)
    print_packet(data, ts, hdr['len'])

# pass in some random parameters to loop()'s callback. Can be any python object you want!
d = {'count': 0}

# Parameters are count, callback, user params
p.loop(-1, gotpacket, d)

print >> sys.stderr, repr(stats)

