#!/usr/bin/env python

import sys, os, json


dumpfile = sys.argv[1]

total_count = {}

def gen_prefix(key):
    prefix = 'get key error'
    sess_k = key.find(' SESS_')
    if sess_k != -1:
        prefix = key[:sess_k] + ' SESS_'
    else:
        prefix = str(key).translate(None, '0123456789')

    return prefix

def parse_line(line):
    global total_count

    j = json.loads(line, 'latin-1')

    if 'mmc_cmds' in j:

        for x in j['mmc_cmds']:

            prefix = gen_prefix(x['req'])


            if prefix not in total_count:
                total_count[prefix] = {}
                total_count[prefix]['count'] = 0

                total_count[prefix]['req_size_min'] = x['req_len']
                total_count[prefix]['req_size_max'] = x['req_len']
                total_count[prefix]['req_size_total'] = 0

                total_count[prefix]['res_size_min'] = x['res_len']
                total_count[prefix]['res_size_max'] = x['res_len']
                total_count[prefix]['res_size_total'] = 0

                total_count[prefix]['tc_min'] = x['tc']
                total_count[prefix]['tc_max'] = x['tc']
                total_count[prefix]['tc_total'] = 0

                total_count[prefix]['hit'] = 0
                total_count[prefix]['miss'] = 0


            total_count[prefix]['count'] += 1
            total_count[prefix]['req_size_min'] = min(x['req_len'], total_count[prefix]['req_size_min'])
            total_count[prefix]['req_size_max'] = max(x['req_len'], total_count[prefix]['req_size_max'])
            total_count[prefix]['req_size_total'] += x['req_len']

            total_count[prefix]['res_size_min'] = min(x['res_len'], total_count[prefix]['res_size_min'])
            total_count[prefix]['res_size_max'] = max(x['res_len'], total_count[prefix]['res_size_max'])
            total_count[prefix]['res_size_total'] += x['res_len']

            total_count[prefix]['tc_min'] = min(x['tc'], total_count[prefix]['tc_min'])
            total_count[prefix]['tc_max'] = max(x['tc'], total_count[prefix]['tc_max'])
            total_count[prefix]['tc_total'] += x['tc']

            if x['req'][:4] == 'get ':
                if x['res'] == 'VALUE':
                    total_count[prefix]['hit'] += 1
                else:
                    total_count[prefix]['miss'] += 1
    
                

with open(dumpfile, 'r') as f:
    for line in f:
        line = line.strip()
        
        parse_line(line)


for x in total_count:
    v = total_count[x]

    req_size_avg =  v['req_size_total'] / float(v['count'])
    res_size_avg =  v['res_size_total'] / float(v['count'])
    tc_avg =  v['tc_total'] / float(v['count'])

    print ','.join(str(zzz) for zzz in (x, v['count'], v['req_size_min'], v['req_size_max'], req_size_avg,
        v['res_size_min'], v['res_size_max'], res_size_avg,
        v['tc_min'], v['tc_max'], tc_avg,
        v['hit'], v['miss'], ))


