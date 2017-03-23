from walker.walker import Walker
from twisted.internet import reactor
import os
import sys
import time
from twisted.internet import task
f = open(os.devnull, 'w')
#sys.stdout = f
if sys.platform == "darwin":
    # Workaround for annoying MacOS Sierra bug: https://bugs.python.org/issue27126
    # As fix, we are using pysqlite2 so we can supply our own version of sqlite3.
    import pysqlite2.dbapi2 as sqlite3
else:
    import sqlite3

if os.path.isfile('load_balancing.db'):
	os.remove('load_balancing.db')
conn = sqlite3.connect('load_balancing.db')

c = conn.cursor()
c.execute('''CREATE TABLE visit
             (walker text, min1 INTEGER, min2 INTEGER, min3 INTEGER, min4 INTEGER, min5 INTEGER)''')
conn.commit()


def stop():
	reactor.stop()

def loop_counting():
	loop_count=loop_count+1
	print("loop_count is now: "+str(loop_count)+"!!!!!!!!!!!!")
	if(loop_count>1):
		reactor.stop()


NUM_WALKER =1000
i=0
walker_list = []
while(i<NUM_WALKER):
	print "this is walker "+str(i)
	walker = Walker(25000+i)
	walker_list.append(walker)
	entry = [(str(25000+i),0,0,0,0,0)]
	c.executemany("INSERT INTO visit VALUES (?,?,?,?,?,?)",entry)
	conn.commit()
	i=i+1

for walker in walker_list:
	print "now is for walker"+str(walker.lan_port)+"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	#walker.run()

#loop = task.LoopingCall(loop_counting)
#loop.start(10)
reactor.callLater(60, stop)
reactor.run()

#time.sleep(20)
#for walker in walker_list:
	#walker.stop()

