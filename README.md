# Get-log4j-Windows.ps1
Identifying all log4j components across all windows servers, entire domain, can be multi domain. CVE-2021-44228

#####################################################################################
#
#     Get-log4j-Windows-v1.ps1
#
# Author: Keith Waterman
# Date : 15-Dec-2021
#
#
# Description: Made for CVE-2021-44228
#              Searches AD for all Computer objects with filter. (Made for windows servers)
#              Invokes PowerShell on remote server from central server.
#              Sets up working directory C:\Temp\log4j on remote servers and copy's over 7zip.exe
#              Recursively scans all drives for .jar containers.
#              Extracts all .jar with 7-zip.exe to C:\temp\log4j\Extracted           
#              Gets version number of log4j version.
#              Dynamically creates central csv of where embedded log4j module was located. 
#              Captures failed PS jobs and closes stuck jobs after 25min.
#				
# Created for: Identifying all log4j components across all windows servers, entire domain, can be multi domain. CVE-2021-44228
#
#
# Dependencies: You must install 7-zip.exe in C:\support\tools\7-zip on the command-and-control server (x32 bit suggested)
#              PowerShell 5.0+
#              Uses Windows Remote Management (WinRM) to connect.
#              Must run as a domain admin or equivalent permissions to scan all drives
#              Needs ping port access through firewalls.
#
# Change Log:
#    15-Dec-2021  -Change Notes: Initial version
#
# Notes: you need to modify --replaceme 
#        You need to update info for your domain(s) See line 64.
#        You need to uncomment line 36 for first run.
