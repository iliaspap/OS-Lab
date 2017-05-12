#!/usr/bin/python

import sys
import math

total = 0
score = 2000
non_elastic = []
elastic = []

lines = sys.stdin.readlines()

for line in lines:
    temp = line.split(":")
    temp[3] = int(temp[3])
    score -= temp[3]
    if temp[3] == 50:
	elastic.append(temp)
    elif (total + temp[3] <= 2000):
        total += temp[3]
        non_elastic.append(temp)

score = float(score)
print "score:" + str(score)

for x in non_elastic:
    print "set_limit:" + x[1] + ":cpu.shares:" + str(x[3])

remaining = 2000 - total

if (len(elastic) != 0) and (remaining != 0): 
    elastic_resources = remaining/len(elastic)
    for x in elastic:
	print "set_limit:" + x[1] + ":cpu.shares:" + str(elastic_resources)
   
