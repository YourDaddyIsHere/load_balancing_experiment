from tracker.walker import Walker
import os
import sys
f = open(os.devnull, 'w')
#sys.stdout = f

tracker = Walker(1235,is_tracker=True)
tracker.run()