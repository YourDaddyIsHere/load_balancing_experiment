import numpy as np
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
from numpy.random import normal
import os
import sys
if sys.platform == "darwin":
    # Workaround for annoying MacOS Sierra bug: https://bugs.python.org/issue27126
    # As fix, we are using pysqlite2 so we can supply our own version of sqlite3.
    import pysqlite2.dbapi2 as sqlite3
else:
    import sqlite3

conn = sqlite3.connect('load_balancing.db')
c = conn.cursor()
c.execute("select visited_count from visit")
list_visit = c.fetchall()

list_min1=[]
for tuple in list_visit:
	list_min1.append(tuple[0])

plt.hist(list_min1)
plt.title("Load Balancing Histogram")
plt.xlabel("Value")
plt.ylabel("Frequency")
plt.show()