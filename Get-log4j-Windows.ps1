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


#$Cred = Get-Credential #Uncomment this when you've entered your DA credentials
$HostServer = (Get-WmiObject Win32_ComputerSystem).name

if (!(Test-Path -Path "c:\Support\Tools\7-zip")) {
    Write-Host -ForegroundColor Yellow "7-zip tools not installed to C:\Support\Tools\7-zip"
    Write-Host -ForegroundColor Red "ERROR: Stopping Script."
    Write-Host -ForegroundColor Yellow "Please Install 7-zip x32 to C:\Support\Tools"
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: 7-zip tools installed. Proceeding.." }

if (!(($PSVersionTable.PSVersion.Major) -ge "5")) {
    Write-Host -ForegroundColor Yellow "Powershell version to low, requires 5.0+"
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: Powershell 5.0+. Proceeding.." }


If ([string]::IsNullOrEmpty($Cred)) {
    Write-Host -ForegroundColor Yellow "No credentials detected, uncomment #`$Cred"
    Write-Host -ForegroundColor Red "ERROR: Stopping Script."
    Write-Host -ForegroundColor Yellow "Please enter in domain admin credentials."
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: Credentials Detected. Proceeding.." }

# Update Domain Here
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
switch ($Domain) {
    
    "my.happy.domain.com" { 
        $AdCompSearchPrefix = "--replaceme*" #Enter in your AD Computer object prefix eg Dev for DEVAPP001
        $DnsDomainSuffix = ".--replaceme" # Enter in your Domain names FQDN with a proceeding . eg: .my.happy.domain.com
        $DnsShortName = "--replaceme" #Enter in your DNS shorname eg DEV for dev.my.happy.domain.com
    }
    "my.happy.domain.com" { 
        $AdCompSearchPrefix = "--replaceme*" #Enter in your AD Computer object prefix eg Dev for DEVAPP001
        $DnsDomainSuffix = ".--replaceme" # Enter in your Domain names FQDN with a proceeding . eg: .my.happy.domain.com
        $DnsShortName = "--replaceme" #Enter in your DNS shorname eg DEV for dev.my.happy.domain.com
    }
}



$Servers = Get-ADComputer -Filter "SamAccountName -like '$($AdCompSearchPrefix)'" -Properties  Name | Select-Object Name

$ReportObj4 = @()

Foreach ($ReportObject4 in $Servers) {


    $ObjProp4 = [ordered]@{    
        DnsHostName = $ReportObject4.Name + "$DnsDomainSuffix"
                    
    }
    $TempObj4 = New-Object -TypeName psobject -Property $ObjProp4 
    $ReportObj4 += $TempObj4
}

$InvokedServers = $null

$Servers = $ReportObj4

$Servers = $Servers | Sort-Object -Property DnsHostName | Where-Object { ($_.DnsHostName -ne "$($HostServer)$DnsDomainSuffix") }#  -or ($_.DnsHostName -eq "prdbkp109$DnsDomainSuffix")} 

Write-Host "0.) Ping AD servers to make sure online.."
$PingObj = @()

$Servers.DnsHostName  | ForEach-Object {
    $pingstatus = ""
    IF (Test-Connection -BufferSize 32 -Count 1 -ComputerName $_ -Quiet) {
        $pingstatus = "Online"
    }
    Else {
        $pingstatus = "Offline"
    }

    $PingObj += New-Object -TypeName PSObject -Property @{
        DnsHostName = $_
        Status      = $pingstatus 
        
    }
}

Write-Host "1.) Complete." 

#####################
#Setup Host Server Working Directories csv
#####################

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j")) {
    mkdir "\\$HostServer\c$\Temp\Log4j" -Force  | Out-Null
}

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j\Extracted")) {
    mkdir "\\$HostServer\c$\Temp\Log4j\Extracted" -Force  | Out-Null
}

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j\Extracted\Split-CSV")) {
    mkdir "\\$HostServer\c$\Temp\Log4j\Extracted\Split-CSV" -Force  | Out-Null
}

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j\log4j-reports")) {
    mkdir "\\$HostServer\c$\Temp\Log4j\log4j-reports" -Force  | Out-Null
}

$Servers = $PingObj | Where-Object { $_.Status -eq "Online" }
$PingObj | Where-Object { $_.Status -eq "Offline" } | Export-csv C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv -NoTypeInformation -Force

#Used to restrict number eg [1..3]
$Servers = $Servers

#####################
# MULTI-THREAD Split Computer Objects in Block CSV's
#####################
    
Write-host "2.) Splitting $($Servers.Count) AD servers into blocks of 1 Servers each.."

#$365Data
$Blocks = [System.Collections.ArrayList]::new()
for ($i = 0; $i -lt $Servers.Count; $i += 1) {
    if (($Servers.Count - $i) -gt 1  ) {
        $Blocks.add($Servers[$i..($i + 0)]) | Out-Null
    }
    else {
        $Blocks.add($Servers[$i..($Servers.Count - 1)]) | Out-Null
    }
}  
    
$count = 1
foreach ($Block in $Blocks) {
    $path = "C:\Temp\Log4j\Extracted\Split-CSV\Server-Block-$count-of-$($Blocks.Count).csv"
    $Block | Export-Csv $path -NoTypeInformation
    $count++
}

$Items = $Null
$Items = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\Split-CSV\*"

Write-host "3.) Complete."

Write-host "4.) Multi-thread Searching blocks of servers.."

#####################
# MULTI-THREAD Convert csv to Json
#####################


$InvokedServers = @()

foreach ($Item in $Items.FullName) {
    
    $MaxConcurrentJobs1 = '250' 
    $Counter1++
    $CSVJobNumber++   
    
    $ScriptBlock = {
            
        $ImportCsv = Import-csv $Using:Item

        $InvokedServers = @()

        Foreach ($ServerBlock in $ImportCsv) {


            Foreach ($Server in $ServerBlock.DnsHostName) {
    
                #Setup Desitnation Folders 
                write-Host "*** $Server ***"
                write-Host "0.) Creating Folder Structure in $Server C:\Temp\Log4j\Extracted"
                                                                          

                if (!(Test-Path -Path "\\$Server\c$\Temp")) {
                    mkdir "\\$Server\c$\Temp" -Force | Out-Null
                }

                if (!(Test-Path -Path "\\$Server\c$\Temp\Log4j")) {
                    mkdir "\\$Server\c$\Temp\Log4j" -Force | Out-Null
                }

                if (!(Test-Path -Path "\\$Server\c$\Temp\Log4j\Extracted")) {
                    mkdir "\\$Server\c$\Temp\Log4j\Extracted" -Force  | Out-Null
                }


                if (!(Test-Path -Path "\\$Server\c$\Support\Tools\7-Zip")) {
    
            
                    Try { Robocopy /e "\\$Using:HostServer\C$\Support\Tools\7-Zip" "\\$Server\c$\Support\Tools\7-Zip" | Out-Null } Catch { "Error" }
 
                }             
                                
                  
            }
                        
            Try {
                $InvokedServers += Invoke-Command -ComputerName $ServerBlock.DnsHostName -Credential $using:cred -ScriptBlock { 

                    #$ReportObj = @()

                    #if ($True -eq $True) {
                    #     throw "$ServerBlock.DnsHostName"
                    #    }
                    

                    Function Get-log4j {

                        $ReportObj = @()
                        write-Host "1.) Getting Local Drives.."
                        #Get Local Drives
                        $Local_Drives = Get-PSDrive | Select-Object Root | Where-Object { $_.Root -like "*:*" }
                        write-Host "2.) Completed."
                        write-Host "3.) Searching Local Drives.." $Local_Drives.Root
                        $Jar_Files = @()

                        Foreach ($DriveLetter in $Local_Drives) {

                            $Items = Get-ChildItem -Path $DriveLetter.Root -Recurse | Where-Object { $_.Name -like "*.jar" } |  Select-Object Name, FullName | Where-Object { $_.FullName -like "*log4j*" }
                            $Jar_Files += $Items
                        }
                                               

                        write-Host "4.) Completed."

                        If (-NOT [string]::IsNullOrEmpty($Jar_Files)) { Write-host "5.) Found .jar files.." } Else {
                            write-Host "5.) No .jar Files Found. Exiting." ; 
                            $ObjProp0 = @{    
                                ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                                FullPath                  = "No .js files found"    
                                Log4JVersion              = [string]"N/A"
                                GroupId                   = [string]"N/A"
                                artifactId                = [string]"N/A"
                                Suspected_Processes       = [string]"N/A"
                                Suspected_Ports           = [string]"N/A"
                                Suspected_LocalAddresses  = [string]"N/A"
                                Suspected_FullNetworkInfo = [string]"N/A"                         
                            }
                            $TempObj0 = New-Object -TypeName psobject -Property $ObjProp0
                            $ReportObj += $TempObj0
                            $ReportObj ; Exit
                        }

                        $Counter = 0

                        write-Host "6.) Extracing all found .jar files.."

                        Foreach ($Jar_File in $Jar_Files) {

                            $Counter++

                            $Var_Jar = $Jar_File.Name.trim(".jar")
                            $Var_Jar_Extract = $Jar_File.FullName
                            function Expand-7zip(
                                [String] $aDirectory, [String] $aZipfile) {
                                [string]$pathToZipExe = "C:\Support\Tools\7-Zip\7z.exe";
                                [Array]$arguments = "e", "$aZipfile", "-oC:\Temp\Log4j\Extracted\$Counter\$Var_Jar" , "-y";
                                & $pathToZipExe $arguments;
                            }

                            Expand-7zip -aZipfile $("$Var_Jar_Extract") | Out-Null

                            $ObjProp0 = [ordered]@{    
                                FullPath        = $Jar_File.FullName
                                FileName        = $Jar_File.Name    
                                ReferenceNumber = $Counter
                            }
                            New-Object -TypeName psobject -Property $ObjProp0 | Export-csv "C:\Temp\Log4j\Extracted\Report.csv" -NoTypeInformation -Append
                        }

                        write-Host "7.) Completed."
                        write-Host "8.) Searching extracted .jar files.."

                        $JarProp = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "pom.properties" } |  Select-Object Name, FullName

                        #Setup Regex for version scraping from pom.properties
                        $regex = "^(version=+[0-9]+[.]+[0-9]+[.]+[0-9])"
                        $Regex2 = "C:\\Temp\\Log4j\\Extracted\\[0-9]" 
                        $regex3 = "^(groupId=)"
                        $regex4 = "^(artifactId=)"                        

                        $LinkingObject = Import-csv "C:\Temp\Log4j\Extracted\Report.csv"

                        write-Host "9.) Completed."
                        write-Host "10.) Getting NetTCP Connection Info.."
                        $NetworkStats = get-nettcpconnection | Select-Object local*, remote*, state, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } | Where-Object { ($_.State -eq "Listen") } | Where-Object { ($_.Process -like "*jav*") -and ($_.LocalAddress -eq "127.0.0.1") -and ($_.RemoteAddress -ne "::") }

                        write-Host "11.) Completed."
                        write-Host "12.) Building Report.."

                        Foreach ($PropFile in $JarProp) {

                            $DataMatch = $PropFile.FullName | Select-String $Regex2 -AllMatches | ForEach-Object { $_.Matches.Value }
                            $ReferenceNumber = $DataMatch.Substring($DataMatch.Length - 1)

                            $Log4JFullPathValue = @()

                            $ObjProp1 = @{    
                                ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                                FullPath                  = ([String]$Log4JFullPathValue += Foreach ($Number in $LinkingObject) { If ($Number.ReferenceNumber -eq $ReferenceNumber) { $Number.FullPath } })    
                                Log4JVersion              = (($File = Get-Content $PropFile.FullName) | Select-String -pattern $Regex) -replace "version=", ""
                                GroupId                   = ($GroupId = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex3")) -replace "groupid=", ""
                                artifactId                = ($artifactId = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex4")) -replace "artifactId=", ""
                                Suspected_Processes       = If (-NOT [string]::IsNullOrEmpty($NetworkStats.Process)) { $NetworkStats.Process }  Else { [string]"N/A" } 
                                Suspected_Ports           = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalPort)) { $NetworkStats.LocalPort }  Else { [string]"N/A" }
                                Suspected_LocalAddresses  = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalAddress)) { $NetworkStats.LocalAddress }  Else { [string]"N/A" }
                                Suspected_FullNetworkInfo = If (-NOT [string]::IsNullOrEmpty($NetworkStats)) { $NetworkStats | ConvertTo-Json -Depth 100 -Compress }  Else { [string]"N/A" }
                            }

                            $TempObj = New-Object -TypeName psobject -Property $ObjProp1 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
                            $ReportObj += $TempObj
                        }

                        $ReportObj

                        write-Host "13.) Completed."

                        
                        #Remove-Item -Path "C:\Temp\Log4j\Extracted\" -Recurse | out-Null
                        Remove-Item -Path "C:\Support\Tools\7-Zip\" -Recurse | Out-Null

                    }
                    Get-log4j

                    Start-Sleep -Seconds 10

                    write-Host "14.) Cleaning Up.."
                    write-Host "15.) Completed."
                    write-Host "-------------------"

                }

            }
            Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
        
                $ObjProp4 = @{    
                    ServerName                = $Server
                    FullPath                  = "Error - Windows RM Failed To Connect"    
                    Log4JVersion              = "N/A"
                    GroupId                   = "N/A"
                    artifactId                = "N/A"
                    Suspected_Processes       = "N/A"
                    Suspected_Ports           = "N/A"
                    Suspected_LocalAddresses  = "N/A"
                    Suspected_FullNetworkInfo = "N/A"

                }
                $TempObj4 = New-Object -TypeName psobject -Property $ObjProp4 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
                $ReportObj = @()
                $ReportObj += $TempObj4
                $ReportObj 

                Remove-Item -Path "C:\Temp\Log4j\Extracted\" -Recurse | out-Null
                Remove-Item -Path "C:\Support\Tools\7-Zip\" -Recurse | Out-Null

            }
            Finally {}        
        }
        #C:\Temp\Log4j\log4j-reports reports filename, changed to servername for easy identity failure
        $log4jServerReport = ($ImportCsv.DnsHostName) -replace "$using:DnsDomainSuffix", ""
        $InvokedServers | Export-Csv C:\Temp\Log4j\log4j-reports\$log4jServerReport.csv -NoTypeInformation          
    }       
    
    # Start Job
    $ItemNameServerName = Import-csv $Item
    
    Start-Job -name $ItemNameServerName.DnsHostName -ScriptBlock $ScriptBlock | Out-Null
        
    # Cleanup Completed Jobs
    if (($Counter1 / $Counter1) -eq 1 ) {
        Get-Job -State "Completed" | Remove-Job | Out-Null
    }
    # Limit Running Jobs
    $RunningJobs = (Get-Job -State "Running").Count
    while ($RunningJobs -ge $MaxConcurrentJobs1) {                             
        Start-Sleep 2.5
        $RunningJobs = (Get-Job -State "Running").Count
    }


    
}


#######
# Wait for Jobs to Complete
#####

#Stop Running Jobs after too long

$ThreadTimeout = 1500

#Check for jobs we can timeout

Do {

    $CountingJobs = (get-job -State Running).count
    $RunningJobs = get-job -State Running

    foreach ($RunningJob in $RunningJobs) {
        $CurrentTime = get-date
        $TimeoutTime = $RunningJob.PSBeginTime
        $TimeoutTime = $TimeoutTime.AddSeconds($ThreadTimeout)

        #The equation here is:
        #if the current time is more than the time the job started + 5 minutes (300 seconds)
        #then its time we get the info about the job and then stop it
        if ($CurrentTime -gt $TimeoutTime) {

            $Log = @()
            $ReportObj8 = @()

            $Log = [ordered]@{    
                ServerName                = $RunningJob.Name
                FullPath                  = "Error Timed out"
                Log4JVersion              = $RunningJob.Output
                GroupId                   = $RunningJob.Error
                artifactId                = "N/A"
                Suspected_Processes       = "N/A"
                Suspected_Ports           = "N/A"
                Suspected_LocalAddresses  = "N/A"
                Suspected_FullNetworkInfo = "N/A"
                    
            }

            $TempObj8 = New-Object -TypeName psobject -Property $Log 
            $ReportObj8 += $TempObj8
        
            $ReportObj8 | Export-csv "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Stuck-Job-$DnsShortName.csv" -Append -NoTypeInformation
            #Stop the job
            $RunningJob | Stop-Job
        }
        Else { Start-Sleep 5 }                
    }
} Until ($CountingJobs -eq "0")


Write-host "5.) Complete."
#>
Write-host "6.) Building Report Object.."

$FixOffLineServers_ForReporting = Import-csv "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv"

$ReportObj7 = @()
Foreach ($OffLineServer in $FixOffLineServers_ForReporting) {

    $ObjProp7 = [ordered]@{    
        ServerName                = $OffLineServer.DnsHostName
        FullPath                  = $OffLineServer.Status
        Log4JVersion              = "N/A"
        GroupId                   = "N/A"
        artifactId                = "N/A"
        Suspected_Processes       = "N/A"
        Suspected_Ports           = "N/A"
        Suspected_LocalAddresses  = "N/A"
        Suspected_FullNetworkInfo = "N/A"
                    
    }
    $TempObj7 = New-Object -TypeName psobject -Property $ObjProp7 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
    $ReportObj7 += $TempObj7
}

Start-Sleep -Seconds 3

$ReportObj7 | Export-csv "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv" -Force -NoTypeInformation

Start-Sleep -Seconds 3

$FixEmptyObjects_ForReporting = Get-ChildItem -Path C:\Temp\Log4j\log4j-reports\*.csv | Select-Object Name, FullName, Length | Where-Object { ($_.FullName -ne "C:\Temp\Log4j\log4j-reports\Log4J-Server-Report-$DnsShortName.csv") -and ($_.Length -eq "0") }

#$FixEmptyObjects_ForReporting = Get-ChildItem -Path C:\Temp\Log4j\log4j-reports2\NoResults-*.csv | Select-Object Name, FullName, Length | Where-Object { ($_.FullName -ne "C:\Temp\Log4j\log4j-reports\Log4J-Server-Report-$DnsShortName.csv") -and ($_.Length -eq "0") }
$FixEmptyObjects_ForReporting1 = $FixEmptyObjects_ForReporting.name -replace ".csv", "$DnsDomainSuffix"

If ($FixEmptyObjects_ForReporting1.Length -ne "0") {

    $ReportObj9 = @()
    Foreach ($EmptyObjects in $FixEmptyObjects_ForReporting1) {

        $ObjProp9 = [ordered]@{    
            ServerName                = $EmptyObjects
            FullPath                  = "Error, Script Failed"
            Log4JVersion              = "N/A"
            GroupId                   = "N/A"
            artifactId                = "N/A"
            Suspected_Processes       = "N/A"
            Suspected_Ports           = "N/A"
            Suspected_LocalAddresses  = "N/A"
            Suspected_FullNetworkInfo = "N/A"
                    
        }
        $TempObj9 = New-Object -TypeName psobject -Property $ObjProp9 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
        $ReportObj9 += $TempObj9
    }

    Start-Sleep -Seconds 3

    $ReportObj9 | Export-csv "C:\Temp\Log4j\log4j-reports\Log4J-Servers-EmptyResults-$DnsShortName.csv" -Force -NoTypeInformation
}

#Remove-Item "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv"

$ReportingCsvs = Get-ChildItem -Path C:\Temp\Log4j\log4j-reports\*.csv | Select-Object Name, FullName | Where-Object { ($_.FullName -ne "C:\Temp\Log4j\log4j-reports\Log4J-Server-Report-$DnsShortName.csv") -and ($_.FullName -notlike "C:\Temp\Log4j\log4j-reports\NoResults-*") }

Start-Sleep -Seconds 3

$Log4jReport = @()

Foreach ($CsvReport in $ReportingCsvs.FullName) {

    $Log4jReport += Import-csv $CSvReport
}

Start-Sleep -Seconds 3
    
$ReportObj3 = @()

Foreach ($Log4jItem in $Log4jReport) { 
    
    $ObjProp3 = [ordered]@{    
        ServerName                = $Log4jItem.ServerName
        FullPath                  = $Log4jItem.FullPath
        Log4JVersion              = $Log4jItem.Log4JVersion
        GroupId                   = $Log4jItem.GroupId
        artifactId                = $Log4jItem.artifactId
        Suspected_Processes       = $Log4jItem.Suspected_Processes
        Suspected_Ports           = $Log4jItem.Suspected_Ports
        Suspected_LocalAddresses  = $Log4jItem.Suspected_LocalAddresses
        Suspected_FullNetworkInfo = $Log4jItem.Suspected_FullNetworkInfo
                    
    }
    $TempObj3 = New-Object -TypeName psobject -Property $ObjProp3 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
    $ReportObj3 += $TempObj3
}

Write-host "7.) Complete."

$ReportObj3 | Sort-Object -Property ServerName, Fullname | Export-csv C:\Temp\Log4j\Log4J-Server-Report-$DnsShortName.csv -NoTypeInformation -Force

Remove-Item "C:\temp\Log4j\Extracted\" -Recurse
Remove-Item "C:\temp\Log4j\log4j-reports" -Recurse   

Write-host "8.) --All Complete--"
Write-host "9.) ------------------" 


    
