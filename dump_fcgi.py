#!/usr/bin/env python

from pcappy import open_offline

import pyamf.remoting

import sys
import pcap
import string
import time
import socket
import struct
import json


# flup_fcgi_client {{{
# Copyright (c) 2006 Allan Saddi <allan@saddi.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id$
#
# Copyright (c) 2011 Vladimir Rusinov <vladimir@greenmice.info>
#
# __author__ = 'Allan Saddi <allan@saddi.com>'
# __version__ = '$Revision$'

import select
import struct
import socket
import errno
import types


# Constants from the spec.
FCGI_LISTENSOCK_FILENO = 0

FCGI_HEADER_LEN = 8

FCGI_VERSION_1 = 1

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_DATA = 8
FCGI_GET_VALUES = 9
FCGI_GET_VALUES_RESULT = 10
FCGI_UNKNOWN_TYPE = 11
FCGI_MAXTYPE = FCGI_UNKNOWN_TYPE

FCGI_NULL_REQUEST_ID = 0

FCGI_KEEP_CONN = 1

FCGI_RESPONDER = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER = 3

FCGI_REQUEST_COMPLETE = 0
FCGI_CANT_MPX_CONN = 1
FCGI_OVERLOADED = 2
FCGI_UNKNOWN_ROLE = 3

FCGI_MAX_CONNS = 'FCGI_MAX_CONNS'
FCGI_MAX_REQS = 'FCGI_MAX_REQS'
FCGI_MPXS_CONNS = 'FCGI_MPXS_CONNS'

FCGI_Header = '!BBHHBx'
FCGI_BeginRequestBody = '!HB5x'
FCGI_EndRequestBody = '!LB3x'
FCGI_UnknownTypeBody = '!B7x'

FCGI_BeginRequestBody_LEN = struct.calcsize(FCGI_BeginRequestBody)
FCGI_EndRequestBody_LEN = struct.calcsize(FCGI_EndRequestBody)
FCGI_UnknownTypeBody_LEN = struct.calcsize(FCGI_UnknownTypeBody)

if __debug__:
    import time

    # Set non-zero to write debug output to a file.
    DEBUG = 1
    DEBUGLOG = '/tmp/fcgi_app.log'

    def _debug(level, msg):
        if DEBUG < level:
            return

        try:
            f = open(DEBUGLOG, 'a')
            f.write('%sfcgi: %s\n' % (time.ctime()[4:-4], msg))
            f.close()
        except:
            pass

def decode_pair(s, pos=0):
    """
    Decodes a name/value pair.

    The number of bytes decoded as well as the name/value pair
    are returned.
    """
    nameLength = ord(s[pos])
    if nameLength & 128:
        nameLength = struct.unpack('!L', s[pos:pos+4])[0] & 0x7fffffff
        pos += 4
    else:
        pos += 1

    valueLength = ord(s[pos])
    if valueLength & 128:
        valueLength = struct.unpack('!L', s[pos:pos+4])[0] & 0x7fffffff
        pos += 4
    else:
        pos += 1

    name = s[pos:pos+nameLength]
    pos += nameLength
    value = s[pos:pos+valueLength]
    pos += valueLength

    return (pos, (name, value))

def encode_pair(name, value):
    """
    Encodes a name/value pair.

    The encoded string is returned.
    """
    nameLength = len(name)
    if nameLength < 128:
        s = chr(nameLength)
    else:
        s = struct.pack('!L', nameLength | 0x80000000L)

    valueLength = len(value)
    if valueLength < 128:
        s += chr(valueLength)
    else:
        s += struct.pack('!L', valueLength | 0x80000000L)

    return s + name + value

class Record(object):
    """
    A FastCGI Record.

    Used for encoding/decoding records.
    """
    def __init__(self, type=FCGI_UNKNOWN_TYPE, requestId=FCGI_NULL_REQUEST_ID):
        self.version = FCGI_VERSION_1
        self.type = type
        self.requestId = requestId
        self.contentLength = 0
        self.paddingLength = 0
        self.contentData = ''

    def read(self, data):
        """Read and decode a Record from a socket."""
        
        header = data[:FCGI_HEADER_LEN]
        data = data[FCGI_HEADER_LEN:]
        
        self.version, self.type, self.requestId, self.contentLength, \
                      self.paddingLength = struct.unpack(FCGI_Header, header)

        if __debug__: _debug(9, 'read: type = %d, requestId = %d, '
                             'contentLength = %d' %
                             (self.type, self.requestId,
                              self.contentLength))
        
        if self.contentLength:
            self.contentData = data[:self.contentLength]
            data = data[self.contentLength:]

        if self.paddingLength:
            data = data[self.paddingLength:]

        return data


# }}} 


stats = {'continous_request':0, 'continous_request_skip':0, 'continous_response':0, 'continous_response_skip':0, 'not_fin':0, 'skip_ack':0, 'skip_no_syn':0, 'skip_fin':0, 'skip_other':0, 'no_response_body':0, 'bad_request_amf':0}
tmp_stream_index = 0
tmp_streams = {}


if not sys.argv[1:]:
    print 'usage: %s <dump.pcap>' % sys.argv[0]
    exit(-1)

# Open the file
p = open_offline(sys.argv[1])


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

    payload = data[psh_offset:]
    payload_len = size - psh_offset
    # print payload


    stream_key = ''
    stream_key1 = '%s:%s' % (ip_src, port_src)
    stream_key2 = '%s:%s' % (ip_dst, port_dst)

    if stream_key1 > stream_key2:
        stream_key = '%s-%s' % (stream_key1, stream_key2)
    else:
        stream_key = '%s-%s' % (stream_key2, stream_key1)
    
 
    if tcp_flags['SYN'] and tcp_flags['ACK'] and port_src == 9000:
        # connect

        if stream_key in tmp_streams:
            stats['not_fin'] += 1

        tmp_streams[stream_key] = {
            'stream'        : 0,
            'ts_begin'      : ts,
            'ts_end'        : 0,
            'request'       : [],
            'response'      : [],
        }

    elif tcp_flags['FIN'] and tcp_flags['ACK'] and port_src == 9000:
        # disconnect

        if not stream_key in tmp_streams:
            # print 'skip fin'
            stats['skip_fin'] += 1
            return

        tmp_streams[stream_key]['ts_end'] = ts

        tmp_stream_index += 1
        tmp_streams[stream_key]['stream'] = tmp_stream_index


        a = tmp_streams[stream_key]
        del tmp_streams[stream_key]

        # print json.dumps(a)
        request_data = ''.join(a['request'])
        response_data = ''.join(a['response'])

        # print "stream %d, req: %d, resp: %d" % (a['stream'], len(request_data), len(response_data))

        """
        parse fcgi
        """

        request_params ={} 
        request_stdin = []
        response_stdout = []

        while len(request_data) > 0:

            # print 'len: ', len(request_data)

            req_rec = Record()
            request_data = req_rec.read(request_data)

            # print req_rec.type, req_rec.requestId

            
            if req_rec.type == FCGI_BEGIN_REQUEST:
                pass
            elif req_rec.type == FCGI_PARAMS:
                if req_rec.contentLength:
                    pos = 0
                    while pos < req_rec.contentLength:
                        pos, (name, value) = decode_pair(req_rec.contentData, pos)
                        request_params[name] = value

            elif req_rec.type == FCGI_STDIN:
                if req_rec.contentData:
                    request_stdin.append(req_rec.contentData)
            

        while len(response_data) > 0:

            # print 'len: ', len(response_data)

            resp_rec = Record()
            response_data = resp_rec.read(response_data)

            # print resp_rec.type, resp_rec.requestId

            if resp_rec.type == FCGI_STDOUT:
                if resp_rec.contentData:
                    response_stdout.append(resp_rec.contentData)
                else:
                    # TODO: Should probably be pedantic and no longer
                    # accept FCGI_STDOUT records?
                    pass
            elif resp_rec.type == FCGI_STDERR:
                # Simply forward to wsgi.errors
                #environ['wsgi.errors'].write(inrec.contentData)
                pass
            elif resp_rec.type == FCGI_END_REQUEST:
                # TODO: Process appStatus/protocolStatus fields?
                break

        # print request_params
        # print request_stdin
        # print response_stdout

        stdout = ''.join(response_stdout)
        if stdout.find("\r\n\r\n") == -1:
            # bad http response
            stats['no_response_body'] += 1
            return


        request_body = ''.join(request_stdin)
        response_header, response_body = stdout.split("\r\n\r\n", 1)


        if response_header.find('application/x-amf') != -1:
            # amf request  

            a_tc = int(1000000 * (a['ts_end'] - a['ts_begin']))

            request_amf = None
            try:
                request_amf = pyamf.remoting.decode(request_body)
            except:
                stats['bad_request_amf'] += 1
                return

            print request_amf.bodies[0][1].body[0], request_amf.bodies[0][1].body[2], a_tc

            # sys.exit(0)
        else:
            pass


        


    elif port_src == 9000 and payload_len > 0:
        # response

        if not stream_key in tmp_streams:
            # print 'no syn'
            stats['skip_no_syn'] += 1
            return

        tmp_streams[stream_key]['response'].append(payload)
    
    elif port_dst == 9000 and payload_len > 0:
        # request

        if not stream_key in tmp_streams:
            # print 'no syn'
            stats['skip_no_syn'] += 1
            return

        tmp_streams[stream_key]['request'].append(payload)
        
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

