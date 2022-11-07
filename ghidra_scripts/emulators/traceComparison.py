#!/home/dtabor/bin/python2.7/bin/python
import sys

def usage():
	print "%s [-h] left_trace right_trace [-m addressMask] [-d stepMask] [-b] [-i address]" % sys.argv[0]
	print ""
	print "  -h print this message"
	print "  -m specifies a mask (ie 0xFFFF) to be applied to all addresses"
	print "  -s specifies a mask (ie 0xFFFFFFE) to be applied to all step addresses"
	print "  -b specifies endian as Big (default is little)"
	print "  -i specifies instruction addresses to ignore in the comparison"
	print "     (multiple -i arguments can be given)"
	sys.exit(1)

if len(sys.argv) < 3:
	usage()
if "-h" in sys.argv:
	usage()
	
argv = sys.argv
del argv[0]
	
isBigEndian = False
try:
	idx = argv.index("-b")
except ValueError:
	pass
else:
	isBigEndian = True
	del argv[idx]
	
addressMask = None
try:
	idx = argv.index("-m")
except ValueError:
	pass
else:
	addressMask = eval(argv[idx+1])
	del argv[idx]
	del argv[idx]
	
stepMask = None
try:
	idx = argv.index("-s")
except ValueError:
	pass
else:
	stepMask = eval(argv[idx+1])
	del argv[idx]
	del argv[idx]
	
ignoreInstr = []
while True:
	try:
		idx = argv.index("-i")
	except ValueError:
		break
	ignoreInstr.append( eval(argv[idx+1]) )
	del argv[idx]
	del argv[idx]

left_path = argv[0]
left_fp = open(left_path,"rb")
right_path = argv[1]
right_fp = open(right_path,"rb")

def parseStep(fp):
	stepCount = None
	programCounter = None
	af = None
	readSet = {}
	writeSet = {}
	while True:
		line = fp.readline()
		if not len(line):
			break
		items = [item.strip().upper() for item in line.strip().split(",")]
		if items[0] == "STEP":
			stepCount = int(items[1])
			programCounter = int(items[2],16)
			if addressMask != None:
				programCounter = programCounter&addressMask
			if stepMask != None:
				programCounter = programCounter&stepMask
			break
	if stepCount == None:
		return stepCount, programCounter, readSet, writeSet
	while True:
		offset = fp.tell()
		line = fp.readline()
		if not len(line):
			break
		line = line.strip()
		if line[0] == "#":
			continue
		items = [item.strip().upper() for item in line.split(",")]
		if items[0] == "UNSTEP":
			continue
		if items[0] == "UNDO":
			continue
		if items[0] == "STEP":
			fp.seek(offset)
			break
		bankName, accessType, address, value, taint = items
		byteCount = len(value)/2
		value = int(value,16)
		address = int(address,16)
		if addressMask != None:
			address = address&addressMask
		if bankName.lower() == "io":
			address = address&0xFF
		bytes = []
		for i in xrange(byteCount):
			byte = value&0xFF
			value = value >> 8
			if isBigEndian:
				byteAddress = address + (byteCount-1-i)
			else:
				byteAddress = address + i
			if accessType == "R":
				readSet[byteAddress] = byte
			elif accessType == "W":
				writeSet[byteAddress] = byte
	return stepCount, programCounter, readSet, writeSet
		
def stepsEqual( stepInfo1, stepInfo2 ):
	stepCount1, programCounter1, readSet1, writeSet1 = stepInfo1
	stepCount2, programCounter2, readSet2, writeSet2 = stepInfo2
	#if stepCount1 != stepCount2:
	#	return False
	if programCounter1 != programCounter2:
		return False
	
	#To accomodate Pcode traces, allow random reads just after the programCounter
	ignoreAddrs = {programCounter1:None}
	i = 0
	while programCounter1+i in readSet1:
		if programCounter1+i not in readSet2:
			ignoreAddrs[programCounter1+i] = None
		i += 1
	i = 0
	while programCounter2+i in readSet2:
		if programCounter2+i not in readSet1:
			ignoreAddrs[programCounter2+i] = None
		i += 1
		
	for address in readSet1:
		if address not in ignoreAddrs and \
			(address not in readSet2 or readSet2[address] != readSet1[address]):
			return False
	for address in readSet2:
		if address not in ignoreAddrs and \
			(address not in readSet1 or readSet1[address] != readSet2[address]):
			return False
			
	writeKeys1 = writeSet1.keys()
	writeKeys1.sort()
	
	writeKeys2 = writeSet2.keys()
	writeKeys2.sort()
	
	if len(writeKeys1) != len(writeKeys2):
		return False
	for i in xrange(len(writeKeys1)):
		if writeKeys1[i] != writeKeys2[i]:
			return False
		if writeSet1[writeKeys1[i]] != writeSet2[writeKeys2[i]]:
			return False
			
	return True

def printStep(stepInfo):
	def printByteRun(start,bytes):
		if len(bytes) == 1:
			print "    %X: %s" % (start," ".join(["%02X" % b for b in bytes]))
		else:
			print "    %X-%X: %s" % (start,start+len(bytes)-1," ".join(["%02X" % b for b in bytes]))
	
	def printAccessSet(accessSet):
		keys = accessSet.keys()
		keys.sort()
		start = None
		bytes = []
		for address in keys:
			if start == None:
				start = address
			if address == start+len(bytes):
				bytes.append(accessSet[address])
			else:
				printByteRun(start,bytes)
				start = address
				bytes = [accessSet[address]]
		printByteRun(start,bytes)
	
	stepCount, programCounter, readSet, writeSet = stepInfo
	print "STEP %d @ %X" % (stepCount, programCounter)
	if len(readSet):
		print "  READ:"
		printAccessSet(readSet)
	if len(writeSet):
		print "  Write:"
		printAccessSet(writeSet)
	


while True:
	leftInfo = parseStep(left_fp)
	rightInfo = parseStep(right_fp)
		 
	if leftInfo[0] == None or rightInfo[0] == None:
		break
	
	equal = None
	for addr in ignoreInstr:
		if leftInfo[1] == addr and rightInfo[1] == addr:
			equal = True
			break
	if equal == None:
		equal = stepsEqual(leftInfo,rightInfo)
	
	if equal:
		print "-------------------------"
		printStep(leftInfo)
	else:
		print "<<<<<<<<<<<<<<<<<<<<<<<<<"
		printStep(leftInfo)
		print "<<<<<<<<<<<<<<<<<<<<<<<<<"
		print ">>>>>>>>>>>>>>>>>>>>>>>>>"
		printStep(rightInfo)
		print ">>>>>>>>>>>>>>>>>>>>>>>>>"
		
		
