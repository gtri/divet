#!/usr/bin/env python
import sys
import os

MATCH = ["$py.class",".pyc"]

for root,dirs,files in os.walk(os.path.dirname(sys.argv[0])):
	for file in files:
		for match in MATCH:
			if file[-len(match):] == match:
				path = os.path.join(root,file)
				os.unlink(path)
				break
