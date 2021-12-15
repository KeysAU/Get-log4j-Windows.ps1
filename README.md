# Get-log4j-Windows.ps1
  
 Identifying all log4j components across all windows servers, entire domain, can be multi domain. CVE-2021-44228
 
 Will scale to 1,000+ windows servers, 250+ servers at a time. 1k servers took about 1 1/2 hours.
 
 [Apache log4j](https://logging.apache.org/log4j/2.x/)
 
 [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228)

# Script Running:

![image](https://user-images.githubusercontent.com/38932932/146176040-d29e4c1f-fea1-4a6c-af3e-95cba2de1352.png)

# Export:

![image](https://user-images.githubusercontent.com/38932932/146176682-d8e6ea01-4668-428e-963f-080d9c1c3214.png)

# Description: 
              Made for CVE-2021-44228
              Searches AD for all Computer objects with filter. (Made for windows servers)
              Invokes PowerShell on remote server from central server.
              Sets up working directory C:\Temp\log4j on remote servers and copy's over 7zip.exe
              Recursively scans all drives for .jar containers.
              Extracts all .jar with 7-zip.exe to C:\temp\log4j\Extracted           
              Gets version number of log4j version.
              Dynamically creates central csv of where embedded log4j module was located. 
              Captures failed PS jobs and closes stuck jobs after 25min.
              Will scale to 1,000+ servers, 250 servers at a time. 1k servers
				
# Created for: 
              Identifying all log4j components across all windows servers, entire domain, can be multi domain. CVE-2021-44228


# Dependencies: 
              You must install 7-zip.exe in C:\support\tools\7-zip on the command-and-control server (x32 bit suggested)
              PowerShell 5.0+
              Uses Windows Remote Management (WinRM) to connect.
              Must run as a domain admin or equivalent permissions to scan all drives
              Needs ping port access through firewalls.

# Change Log:
        15-Dec-2021  -Change Notes: Initial version

# Notes: 
        You need to modify --replaceme 
        You need to update info for your domain(s) See line 64.
        You need to uncomment line 36 for first run.
	
# Licence:
	Open-sourced software licensed under the MIT license.

# Author:
         Keith Waterman
# Date : 
        15-Dec-2021
