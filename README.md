
```
_______  ______ _____ _           _   ____                    _   
| ____\ \/ / ___| ____| |    _ __ | |_|  _ \  ___  _ __  _   _| |_ 
|  _|  \  / |   |  _| | |   | '_ \| __| | | |/ _ \| '_ \| | | | __|
| |___ /  \ |___| |___| |___| | | | |_| |_| | (_) | | | | |_| | |_ 
|_____/_/\_\____|_____|_____|_| |_|\__|____/ \___/|_| |_|\__,_|\__|
                    by @JoeLeonJr (@FortyNorthSec)                

```

EXCELntDonut is a XLM (Excel 4.0) macro generator. Start with C# source code (DLL or EXE) and end with a XLM (Excel 4.0) macro that will execute your code in memory. XLM (Excel 4.0) macros can be saved in .XLS files.

## Installation

```bash
chmod +x install.sh
./install.sh

```

What is installed?
- pip3
- mono-complete (both mcs and all possible libraries you'd reference in your source files)
- EXCELntDonut as a CLI

If you'd like to run EXCELntDonut as just a python script, you'll need to setup a virtual environment with two packages "pandas" and "donut-shellcode". Additionally, you'll need to apt-get install mono-complete and call the drive.py script using python3. We recommend just using the ./install.sh bash script, but it's up to you.


## Usage

```bash
Usage:
	$ EXCELntDonut -f dll_source.cs -c ClassName -m MethodName -r System.Windows.Forms.dll
	$ EXCELntDonut -f exe_source.cs -r System.Windows.Forms.dll --sandbox --obfuscate

Flags:
	(required)
	-f path to file containing your C# soure code (can be for an exe or dll)

	(required for DLL source code)
	-c ClassName where method that you want to call lives
	*NOTE* The class must be marked as public.

	-m Method containing your executable payload
	*NOTE* The method must be marked as public and static.

	-r References needed to compile your C# code (same ones for when using mcs to compile on Linux)
	(ex: -r 'System.Management')

	(optional)
	-o output filename
	--sandbox 
		Perform basic sandbox checks. This will be updated as new approaches are discovered.
	--obfuscate 
		Perform basic macro obfuscation. 
```

## How it works

You provide a C# file containing your payload (like a DLL with a method that executes a cobalt strike beacon payload). That C# file is compiled using MCS into two .NET assemblies:  x86 and x64. After compilation, the awesome tool Donut converts each assembly into position independent shellcode. Next, all nullbytes are removed, since XLM (Excel 4.0) macros don't play nicely with nullbytes and the payload is chunked into lines with no more than 255 characters (for x86) or 10 characters (for x64).

Once the shellcode is prepared, it's combined with basic process injection functions (VirtualAlloc, WriteProcessMemory and CreateThread) as well as an architecture check function to determine which payload (x86 or x64) to run on the target system. If you elect to execute sandbox checks or basic obfuscation, then those functions will update your macro. Finally, the output is placed in a CSV file (saved as .txt). 

## How to create a XLM (Excel 4.0) Macro

Once you have the output file from EXCELntDonut, open the output file in a *text editor* and copy the entirety of it (Ctrl-A, Ctrl-S). Open up Excel on a Windows VM, right-click on "Sheet 1" and select "Insert". Choose "MS Excel 4.0 Macro". Go to cell A1 and paste the EXCELntDonut output. All the data will likely be pasted in one column. The data is semi-colon separated ";". Go to the "Data" tab and then click "Text-to-columns". Select "Delimited" and on the next screen select "Semicolon" and then click "Finish". The macro will spread across the appropriate columns and rows. 

(Note - if you selected the "--obfuscate" flag, you'll need to scroll horizontally quite a bit to find your actual code, since part of the obuscation logic moves the macro into a random section of the worksheet).  

We recommend two things at this point:
1. Find the starting cell (will be the top-left cell of your macro code, likely A1). Right-click and select "Run". Test out your macro to make sure it works.
2. Once you verify that the macro works, select that same top-left cell again. On the left-side of the screen, there should be a dropdown that says the cell you're in (likely "A1"). Click in the dropdown and change the text value to "Auto_open". That will produce the same automatic execution functionality that you're used to in VBA macros.

Save the file (.xls) and try opening it up. It should automatically execute your payload.

## Sandbox Checks

These checks are based on what actual threat actors are using in their malware.

1. Is there a mouse active?
2. Is the screen size greater than 770 width and 381 height?
3. Can the host play sounds?
4. Is this a Windows machine?


## Obfuscation

1. For the process injection instructions (VirtuaAlloc, WriteProcessMemory, CreateThread) and sandbox checks, all macro functions will turn into the following structure: 
```
=FORMULA(D3&D23&D54&D23&D44,E45)
```
The FORMULA function allows us to place a formula, which can later be executed, into another cell. So in this case, we put the process injection instructions and then use the FORMULA function to place the actual function into another cell to be executed. This avoids defenders conducting static analysis from seeing things like "VirtualAlloc".

2. The entire macro will shift some value to the right, so that when you initially open up the sheet with the macros, it appears blank.

## Things to know

- Less sophisticated payloads just uses the =EXEC() command to execute commands. Some also use URLMON to download files. Other files even includes the word "SHELL". All of that seemed like a bad idea to us. This tool doesn't include any of that. Instead it injects your C# source code into the Excel process (either 32-bit or 64-bit) and then executes. From there, it's up to your payload on what it does next. .

## Tips

- Your C# source code could do anything you want it to. We recommend your source code break the Parent > Child relationship between Excel and whatever you spawn into. 
- There's a lot of good blog posts about "Very Hidden" excel sheets. Consider using that.
- Don't forget to make your Excel file look real.
- Huge source code files might slow the tool down a ton (specifically during nullbyte removal with msfvenom). Also, if you're targeting a x64 version of Excel, consider a staged payload since the injection process is quite slow.

## Troubleshooting

###### "The type or namspace name ... does not exist ... "

```bash
root@excelntdonut-test:/opt# EXCELntDonut -f test.cs
 _______  ______ _____ _           _   ____                    _   
| ____\ \/ / ___| ____| |    _ __ | |_|  _ \  ___  _ __  _   _| |_ 
|  _|  \  / |   |  _| | |   | '_ \| __| | | |/ _ \| '_ \| | | | __|
| |___ /  \ |___| |___| |___| | | | |_| |_| | (_) | | | | |_| | |_ 
|_____/_/\_\____|_____|_____|_| |_|\__|____/ \___/|_| |_|\__,_|\__|
                    by @JoeLeonJr (@FortyNorthSec)                
[i] Generating your x86 .NET assembly.
warning CS8001: SDK path could not be resolved
test.cs(2,14): error CS0234: The type or namespace name `Management' does not exist in the namespace `System'. Are you missing an assembly reference?
```

This error most likely means you're missing a reference assembly during compilation using mono. To fix this, simply pass in the namespace mentioned into the -r flag. In this case, we'd add -r 'System.Management' to the command line. The new command would be:

```bash
root@excelntdonut-test:/opt# EXCELntDonut -f test.cs -r 'System.Management'

```

###### "Metadata file ... could not be found"

```bash
root@excelntdonut-test:/opt# EXCELntDonut -f test.cs -r System.Management
 _______  ______ _____ _           _   ____                    _   
| ____\ \/ / ___| ____| |    _ __ | |_|  _ \  ___  _ __  _   _| |_ 
|  _|  \  / |   |  _| | |   | '_ \| __| | | |/ _ \| '_ \| | | | __|
| |___ /  \ |___| |___| |___| | | | |_| |_| | (_) | | | | |_| | |_ 
|_____/_/\_\____|_____|_____|_| |_|\__|____/ \___/|_| |_|\__,_|\__|
                    by @JoeLeonJr (@FortyNorthSec)                
[i] Generating your x86 .NET assembly.
warning CS8001: SDK path could not be resolved
error CS0006: Metadata file `System.Management' could not be found

[x] Error in generating x86 .NET assembly using MCS. See error message above.
```

This error should not pop up unless you run EXCELntDonut without using the install.sh bash script. In that case, you'll need to manually install mono-complete. This will download the relevant dependencies. You can install it using apt like this:

```bash
apt-get install mono-complete
```

###### "Program ... does not contain a static 'Main' method ..."

```bash
root@kali:~/Desktop# EXCELntDonut -f test.cs
 _______  ______ _____ _           _   ____                    _   
| ____\ \/ / ___| ____| |    _ __ | |_|  _ \  ___  _ __  _   _| |_ 
|  _|  \  / |   |  _| | |   | '_ \| __| | | |/ _ \| '_ \| | | | __|
| |___ /  \ |___| |___| |___| | | | |_| |_| | (_) | | | | |_| | |_ 
|_____/_/\_\____|_____|_____|_| |_|\__|____/ \___/|_| |_|\__,_|\__|
                    by @JoeLeonJr (@FortyNorthSec)                
[i] Generating your x86 .NET assembly.
error CS5001: Program `_excelntdonut_GJAoNuVPMcX.exe' does not contain a static `Main' method suitable for an entry point

[x] Error in generating x86 .NET assembly using MCS. See error message above.

```

This error typically occurs when you supply source code for a DLL, but don't specify a class and method name to be called. When the tool does not see "-c" class and "-m" method arguments, it will assume you're trying to compile an exe and will spit out this error. Either convert your file to an EXE and put the payload in Main() method OR even easier, just add a -c and -m argument.

###### General Troubleshooting Advice

1. First, compile your C# source code using csc on windows and execute to verify that the payload works. Test this out by compiling to x86 and x64 payloads, since it's likely you won't know if your target environment operates 32-bit or 64-bit Excel.
2. You should be able to run your payload multiple times in the same process, but if you're getting weird errors, exit it out of Excel, re-open and retry. 
3. When in doubt, close out of Excel and create a new file to test from. 

## Detection
- Here are some Yara rules to start with by @InQuest:

	Look for a very hidden sheet
	> https://github.com/InQuest/yara-rules/blob/master/Excel_Hidden_Macro_Sheet.rule

	Look for the Auto_Open string
	> https://github.com/Neo23x0/signature-base/blob/master/yara/general_officemacros.yar

There's a lot of posts about using OLEDUMP.py to review XLM files. Consider this one:
> https://clickallthethings.wordpress.com/2020/04/06/covid-19-excel-4-0-macros-and-sandbox-detection/

## Defense
1. Enable GPO blocking macro execution for files downloaded from the internet. See - https://www.microsoft.com/security/blog/2016/03/22/new-feature-in-office-2016-can-block-macros-and-help-prevent-infection/
2. AMSI unfortunately doesn't help here.
3. ASR Rules...we're not sure.
4. Most users send .xlsx files these days. Perhaps block .xls files from being sent to your employees' inboxes. It wouldn't be outrageous to request someone re-send a file saved as .xlsx.
5. The most recent version of Defender ATP caught the unobfuscated version of this file when dropped to disk. 

## Acknowledgments 

This wouldn't even be on our radar without the fantastic work done by the folks at Outflank (@outflanknl). Special thanks to @StanHacked for his insight during this project. Also, equally, this project would not be possible without Donut (by @TheWover and @odzhan) and the related python library (by @byt3bl33d3r). Finally, thanks to Philip Tsukerman with Cybereason for the awesome research on making XLM macros compatible with 64-bit versions of Excel.

## Disclaimer

We are not responsible for misuse of this tool. This tool was generated for educational and authorized-testing purposes to demonstrate how  C# source code can be injected into memory using a XLM (Excel 4.0) macro. The ultimate goal of this project is to (1) provide red teamers another phishing payload option to emulate what actual adversaries are currently using, and (2) provide defenders a frame of reference for building analytics and mitigations. Without a tool to quickly generate this type of payload, we believe defenders will not be adequately prepared for what's actually coming their way. Please act responsibly. 

