#####################################################################################
#
#     Get-log4j-Windows-v2.ps1
#
# Author: Keith Waterman
# Date : 20-Dec-2021
#
#
# Description: Made for CVE-2021-44228
#              Searches AD for all Computer objects with filter. (Made for windows servers)
#              Invokes PowerShell on remote server from central server.
#              Sets up working directory C:\Temp\log4j on remote servers and copy's over 7zip.exe
#              Recursively scans all drives for .jar containers.
#              Extracts all .jar with 7-zip.exe to C:\temp\log4j\Extracted           
#              Gets version number of log4j version.
#              Check if jndilookup.class exists.
#              Attempts a local port scan & exploit with http header - 'User-Agent' = '${jndi:ldap://'Target/x
#              Dynamically creates central csv of where embedded log4j module was located. 
#              Captures failed PS jobs and closes stuck jobs after 25min.
#				
# Created for: Identify all log4j components across all windows servers, entire domain. Can be multi domain. CVE-2021-44228
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
#    20-Dec-2021  -Change Notes: Added Jindilookup.class check, added local web server exploit check.
#
# Notes: you need to modify --replaceme 
#        You need to update info for your domain(s) See line 64.
#        You need to uncomment line 39 for first run.
#        Won't scan the local command-and-control server you're running from.
#        url scaner won't get https sites due to PS cert errors. (working on it).

#$Cred = Get-Credential #Uncomment this when you've entered your DA credentials

$HostServer = (Get-WmiObject Win32_ComputerSystem).name

if (!(($PSVersionTable.PSVersion.Major) -ge "5")) {
    Write-Host -ForegroundColor Yellow "Powershell version to low, requires 5.0+"
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: Powershell 5.0+. Proceeding.." }

if (!(Test-Path -Path "c:\Support\Tools\7-zip")) {
    Write-Host -ForegroundColor Yellow "7-zip tools not installed to C:\Support\Tools\7-zip"
    Write-Host -ForegroundColor Red "ERROR: Stopping Script."
    Write-Host -ForegroundColor Yellow "Please Install 7-zip x32 to C:\Support\Tools"
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: 7-zip tools installed. Proceeding.." }

If ([string]::IsNullOrEmpty($Cred)) {
    Write-Host -ForegroundColor Yellow "No credentials detected, uncomment #`$Cred"
    Write-Host -ForegroundColor Red "ERROR: Stopping Script."
    Write-Host -ForegroundColor Yellow "Please enter in domain admin credentials."
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: Credentials Detected. Proceeding.." }

# Update Domain Here
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain

# Multiple switches listed as an example, done so script can be copy paste / run in other domains with ease. YOU MUST TO UPDATE THIS!
switch ($Domain) {    
    "my.fake.domain.com" { 
        $AdCompSearchPrefix = "dev*" #Enter in your AD Computer object PREFIX eg Dev for DEVAPP001 --replaceme
        $DnsDomainSuffix = ".my.fake.domain.com" # Enter in your Domain names FQDN with a proceeding . eg: .my.happy.domain.com --replaceme
        $DnsShortName = "FAKE" #Enter in your DNS shorname eg DEV for dev.my.happy.domain.com --replaceme
    }
    "another.domain.here" {
        $AdCompSearchPrefix = "another*"# --replaceme #Example
        $DnsDomainSuffix = ".another.domain.here"# --replaceme  #Example
        $DnsShortName = "ANO" # --replaceme  #Example
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

$Servers = $Servers | Sort-Object -Property DnsHostName | Where-Object { ($_.DnsHostName -ne "$($HostServer)$DnsDomainSuffix") } 


######
# SINGLE-MULTI SERVER SELECT - Uncomment if you want to restrict to a few test servers before get all.
####
#$Servers = $Servers | Where-Object { ($_.DnsHostName -like "prd*$DnsDomainSuffix") }

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

If ( $PingObj | Where-Object { $_.Status -contains "Offline" }) {
    $PingObj | Where-Object { $_.Status -eq "Offline" } | Export-csv C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv -NoTypeInformation -Force
}

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

                    Function Get-log4j {

                                  
                        $ReportObj = @()
                        write-Host "1.) Getting Local Drives.."
                        #Get Local Drives
                        $Local_Drives = Get-PSDrive | Select-Object Root | Where-Object { $_.Root -like "*:*" }
                        write-Host "2.) Completed."
                        write-Host "3.) Searching Local Drives.." $Local_Drives.Root
                        $Jar_Files = @()

                        Foreach ($DriveLetter in $Local_Drives) {

                            $Items = Get-ChildItem -ErrorAction SilentlyContinue -Path $DriveLetter.Root -Recurse | Where-Object { $_.Name -like "*.jar" } |  Select-Object Name, FullName | Where-Object { $_.FullName -like "*log4j*" }
                            $Jar_Files += $Items
                        }                                               

                        write-Host "4.) Completed."

                        If (-NOT [string]::IsNullOrEmpty($Jar_Files)) { Write-host "5.) Found .jar files.." } Else {
                            write-Host "5.) No .jar Files Found. Exiting." ; 
                            $ObjProp0 = @{    
                                ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                                FullPath                  = "No .js files found"    
                                JndiLookupClass           = "N/A"
                                Log4JVersion              = "N/A"
                                GroupId                   = "N/A"
                                artifactId                = "N/A"
                                PomPropertiesExist        = "N/A"
                                Suspected_Processes       = "N/A"
                                Suspected_Ports           = "N/A"
                                Suspected_LocalAddresses  = "N/A"
                                WebScan_Ports             = "N/A"
                                WebScan_Result            = "N/A"
                                WebScan_Vulnerable        = "N/A"
                                WebScan_httpStatusCode    = "N/A"
                                WebScan_Local_WebSite     = "N/A"
                                PSVersion                 = ($PSVersionTable.PSVersion)
                                Suspected_FullNetworkInfo = "N/A"                        
                            }
                            $TempObj0 = New-Object -TypeName psobject -Property $ObjProp0
                            $ReportObj += $TempObj0
                            $ReportObj ; Exit
                        }
                       
                        write-Host "6.) Extracing all found .jar files.."

                        $Counter = 0

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

                        write-Host "9.) Completed."
                        write-Host "10.) Getting NetTCP Connection Info.."
                        $NetworkStats = get-nettcpconnection | Select-Object local*, remote*, state, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } | Where-Object { ($_.State -eq "Listen") } | Where-Object { ($_.Process -like "*jav*") -and ($_.LocalAddress -eq "127.0.0.1") -and ($_.RemoteAddress -ne "::") }

                        write-Host "11.) Completed."

                        write-Host "12.) Start local host vulnerability scan.."

                        ####
                        # Web Scanning Start
                        ###
                        

                        #Get all local listening ports
                        $NetworkConnections = get-nettcpconnection | Select-Object local*, remote*, state, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } | Where-Object { ($_.State -eq "Listen") } | Where-Object { ($_.LocalAddress -eq "127.0.0.1") -and ($_.RemoteAddress -ne "::") }
    
                        $LocalListeningPorts = @()

                        Foreach ($NetworkConnection in $NetworkConnections) { 
    
                            $NetworkHash = [ordered]@{    
                                ServerName   = (Get-WmiObject Win32_ComputerSystem).name
                                LocalAddress = $NetworkConnection.LocalAddress
                                LocalPort    = $NetworkConnection.LocalPort
                                State        = $NetworkConnection.State
                                Process      = $NetworkConnection.Process
                                httpUrl      = "http://" + $NetworkConnection.LocalAddress + ":" + $NetworkConnection.LocalPort
                                httpsUrl     = "https://" + $NetworkConnection.LocalAddress + ":" + $NetworkConnection.LocalPort
                                #Vulnerable           = Try {$uar = Invoke-WebRequest  $httpurl -Headers $JsonHeader} Catch { $Uar = $_.Exception}
                            
                            }
                            $TempObjNetwork = New-Object -TypeName psobject -Property $NetworkHash #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
                            $LocalListeningPorts += $TempObjNetwork
                        }


                        #Built http listening port url targets
                        Foreach ($http_LocalListeningPort in $LocalListeningPorts) {

                            $Http_Target = $http_LocalListeningPort.httpUrl
                            $JsonHeader = @{ 'User-Agent' = '${jndi:ldap://' + $($Http_Target) + '/x}' }

                            $ScriptBlockWeb = [scriptblock]::Create(
                                @'
        $Results = Invoke-WebRequest -Uri $Using:Http_Target -Headers $Using:JsonHeader -UseBasicParsing
        Write-output $Results
'@
                            )
                        
                            Start-Job -name $http_LocalListeningPort.httpUrl  -ScriptBlock $ScriptBlockWeb | Out-Null
    
                        }

                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True } #Ignore ssl errors, only set for this ps session. 
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  #connect over tls1.2

                        #Built https listening port url targets, commented out due to cert errors.

                        #
                        #Foreach ($https_LocalListeningPort in $LocalListeningPorts[7]) {
                        #
                        #                    $Https_Target = $https_LocalListeningPort.httpsUrl
                        #                    $JsonHeader = @{ 'User-Agent' = '${jndi:ldap://' + $($Http_Target) + '/x}' }##
                        #
                        #                    $ScriptBlockWeb = { $Results = Invoke-WebRequest -Uri $using:Https_Target -Headers $using:JsonHeader -UseBasicParsing#
                        #
                        #                       Write-output $Results
                        #                    }
                        #                   Start-Job -name $https_LocalListeningPort.httpsUrl  -ScriptBlock $ScriptBlockWeb
                        #  
                        #                 }       

                        #Start a jobs for each target port. This uses ps jobs so it can close stuck invoke-web commands. Alot of ports crashed during testing.
                        #loops through infinitly until all jobs complete or stopped.
                        $WebScan_Results = @()
                        Do {

                            $CountingJobs = (get-job -State Running).count
                            $WebScan_RunningJobs = (Get-Job | Where-Object { $_.State -eq "Running" })

                            Foreach ($WebScan_RunningJob in $WebScan_RunningJobs) {   

                                $WebJobTimeout = 15
                                $CurrentTime = get-date
                                $TimeoutTime = $WebScan_RunningJob.PSBeginTime
                                $TimeoutTime = $TimeoutTime.AddSeconds($WebJobTimeout)

                                #The equation here is:
                                #if the current time is more than the time the job started + 15 seconds.
                                #Then its time we get the info about the job and then stop it
                                if ($CurrentTime -gt $TimeoutTime) {

                                    #Write-Output "Job $($WebScan_RunningJob.Name) stuck, stopping.."

                                    $WebLog2 = @{    
                                        Local_Website  = $WebScan_RunningJob.Name
                                        HttpStatusCode = "N/A"
                                        WebScanResult  = "jndi:ldap:// Failed"
                                        Vulnerable     = $False 
                                        WebScan_Ports  = ($WebScan_RunningJob.Name -replace "https://127\.0\.0\.1:", "") -replace "http://127\.0\.0\.1:", ""                             
                                    }                  

                                    $TempObj12 = New-Object -TypeName psobject -Property $WebLog2 
                                    $WebScan_Results += $TempObj12        

                                    $WebScan_RunningJob | Stop-Job
                                    #Write-Output "Job $($WebScan_RunningJob.Name) stopped."

                                }
                            }

                            $WebScan_CompletedJobs = (Get-Job | Where-Object { $_.State -eq "Completed" })

                            Foreach ($WebScan_CompletedJob in $WebScan_CompletedJobs) {   

                                #Write-Output "Waiting 5 seconds for Job $($WebScan_CompletedJob.Name) to complete.."
                                Start-Sleep -Seconds 5  

                                #Write-Output "Scan $($WebScan_CompletedJob.Name) complete."

                                $WebScan_ChildJob = $WebScan_CompletedJob.ChildJobs[0]
                                $WebScan_ChildJobInfo = $WebScan_ChildJob.Output

                                $WebLog2 = @{    
                                    Local_Website  = $WebScan_CompletedJob.Name
                                    HttpStatusCode = If (-NOT [string]::IsNullOrEmpty($WebScan_ChildJobInfo.StatusCode)) { $WebScan_ChildJobInfo.StatusCode }  Else { "N/A" }  
                                    WebScanResult  = If (-NOT [string]::IsNullOrEmpty($WebScan_ChildJobInfo.StatusCode)) { "jndi:ldap:// Success" }  Else { "jndi:ldap:// Failed" }  
                                    Vulnerable     = If (-NOT [string]::IsNullOrEmpty($WebScan_ChildJobInfo.StatusCode)) { $True }  Else { $False }
                                    WebScan_Ports  = ($WebScan_RunningJob.Name -replace "https://127\.0\.0\.1:", "") -replace "http://127\.0\.0\.1:", ""                
                                }                  

                                $TempObj13 = New-Object -TypeName psobject -Property $WebLog2 
                                $WebScan_Results += $TempObj13

                                $WebScan_CompletedJob | Remove-Job        

                                Start-Sleep 5   
                        
                            } 

                        } 
                        Until ($CountingJobs -eq "0")

                        #Get-job | Stop-Job
                        Get-Job | Remove-Job
                    
                        #Setup all the strings and compress results into 1 line for main report.
                        $WebScan_Vulnerable = $WebScan_Results | Where-Object { $_.Vulnerable -eq $True }
                        $WebScan_Ports = $WebScan_Results | Where-Object { $_.Vulnerable -eq $True }
                        $WebScan_Port = $WebScan_Ports | Select-Object -ExpandProperty WebScan_Ports
                        $WebScan_Port_String = $WebScan_Port -join ', '

                        $WebScanResult_String = $WebScan_Vulnerable.WebScanResult[0]

                        $WebScan_Vulnerable_String = $WebScan_Vulnerable.Vulnerable[0]


                        $WebScan_httpStatusCodes = $WebScan_Results | Where-Object { $_.Vulnerable -eq $True }
                        $WebScan_httpStatusCode = $WebScan_httpStatusCodes | Select-Object -ExpandProperty HttpStatusCode
                        $WebScan_httpStatusCode_String = $WebScan_httpStatusCode -join ', '


                        $WebScan_Local_Website = $WebScan_Results | Where-Object { $_.Vulnerable -eq $True }
                        $WebScan_Local_Website1 = $WebScan_Local_Website | Select-Object -ExpandProperty Local_Website
                        $WebScan_Local_Website_String = $WebScan_Local_Website1 -join ', '
                    
                        #write-Host "13.) Complete." 
                        #write-Host "14.) Building Report.."
                    
                        ####
                        # Web Scanning End
                        ###

                        $ReportObj = @()

                        $JarProp = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "pom.properties" -or $_.Name -eq "Manifest.mf" } |  Select-Object Name, FullName
                        $JndiLookup = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "JndiLookup.class" } |  Select-Object Name, FullName
                        #$ManifestMF = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "Manifest.mf" } |  Select-Object Name, FullName
                        
                        #Setup Regex for version scraping from pom.properties & Manifest.mf if pom.properties doesn't exit
                        $regex = "^(version=+[0-9]+[.]+[0-9]+[.]+[0-9])"
                        $Regex2 = "C:\\Temp\\Log4j\\Extracted\\[0-9]" 
                        $regex3 = "^(groupId=)"
                        $regex4 = "^(artifactId=)"
                        $Regex5 = "^(Manifest-Version:[ ][0-9][.][0-9])"
                        $Regex6 = "^(Ant-Version:.*)" 
                        $Regex6_2 = "^(Implementation-Version:.*)"             
                        $Regex7 = "^(Created-By:.*)"                         

                        $LinkingObject = Import-csv "C:\Temp\Log4j\Extracted\Report.csv"

                        #write-Host "9.) Completed."
                        #write-Host "10.) Getting NetTCP Connection Info.."
                        $NetworkStats = get-nettcpconnection | Select-Object local*, remote*, state, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } | Where-Object { ($_.State -eq "Listen") } | Where-Object { ($_.Process -like "*jav*") -and ($_.LocalAddress -eq "127.0.0.1") -and ($_.RemoteAddress -ne "::") }

                        #write-Host "11.) Completed."
                        #write-Host "12.) Building Report.."

                        Foreach ($PropFile in $JarProp) {

                            #If .jar files have a pom.properties use it, else use the MANIFEST.MF to try get versioning
                            $PomPropertiesExist = If ($TestPath = (test-path ($PropFile.FullName -replace "MANIFEST.MF", "Pom.properties"))) { $TestPath }
                            
                            If ($PomPropertiesExist -eq $True) {
                            
                                #Added jindi file matching
                                $JindiInPom = ($PropFile.FullName -replace "\\Pom.Properties", "") -replace "\\MANIFEST.MF", ""
                                $JindiMatch = ($JndiLookup.FullName -replace "\\JndiLookup.class", "") -replace "\\MANIFEST.MF", ""
                            
                                If ($JindiInPom -in $JindiMatch) { $Jindi = $True } Else { $Jindi = $False }
                            
                                $DataMatch = $PropFile.FullName | Select-String $Regex2 -AllMatches | ForEach-Object { $_.Matches.Value }
                                $ReferenceNumber = $DataMatch.Substring($DataMatch.Length - 1)
                            
                                $Log4JFullPathValue = @()
                            
                                $ObjProp1 = @{    
                                    ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                                    FullPath                  = ([String]$Log4JFullPathValue += Foreach ($Number in $LinkingObject) { If ($Number.ReferenceNumber -eq $ReferenceNumber) { $Number.FullPath } })    
                                    JndiLookupClass           = $Jindi
                                    Log4JVersion              = (($File = Get-Content $PropFile.FullName) | Select-String -pattern $Regex) -replace "version=", ""
                                    GroupId                   = ($GroupId = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex3")) -replace "groupid=", ""
                                    artifactId                = ($artifactId = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex4")) -replace "artifactId=", ""
                                    PomPropertiesExist        = $PomPropertiesExist
                                    Suspected_Processes       = If (-NOT [string]::IsNullOrEmpty($NetworkStats.Process)) { [String]$NetworkStats.Process }  Else { [string]"N/A" } 
                                    Suspected_Ports           = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalPort)) { [String]$NetworkStats.LocalPort }  Else { [string]"N/A" }
                                    Suspected_LocalAddresses  = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalAddress)) { [String]$NetworkStats.LocalAddress }  Else { [string]"N/A" }
                                    PSVersion                 = ($PSVersionTable.PSVersion)
                                    Suspected_FullNetworkInfo = If (-NOT [string]::IsNullOrEmpty($NetworkStats)) { $NetworkStats | ConvertTo-Json -Depth 100 -Compress }  Else { [string]"N/A" }
                                    WebScan_Ports             = If (-NOT [string]::IsNullOrEmpty($WebScan_Port_String)) { [String]$WebScan_Port_String }  Else { [string]"N/A" } 
                                    WebScan_Result            = If (-NOT [string]::IsNullOrEmpty($WebScanResult_String)) { [String]$WebScanResult_String }  Else { [string]"N/A" }
                                    WebScan_Vulnerable        = If (-NOT [string]::IsNullOrEmpty($WebScan_Vulnerable_String)) { [String]$WebScan_Vulnerable_String }  Else { [string]"N/A" }
                                    WebScan_httpStatusCode    = If (-NOT [string]::IsNullOrEmpty($WebScan_httpStatusCode_String)) { [String]$WebScan_httpStatusCode_String }  Else { [string]"N/A" }
                                    WebScan_Local_WebSite     = If (-NOT [string]::IsNullOrEmpty($WebScan_Local_Website_String)) { [String]$WebScan_Local_Website_String }  Else { [string]"N/A" } 
                                }
                            
                                $TempObj = New-Object -TypeName psobject -Property $ObjProp1 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
                                $ReportObj += $TempObj
                            }
                                
                            Else {
                            
                                $PomPropertiesExist = $False
                            
                                #Added jindi file matching
                                $JindiInPom = ($PropFile.FullName -replace "\\Pom.Properties", "") -replace "\\MANIFEST.MF", ""
                                $JindiMatch = ($JndiLookup.FullName -replace "\\JndiLookup.class", "") -replace "\\MANIFEST.MF", ""
                            
                                If ($JindiInPom -in $JindiMatch) { $Jindi = $True } Else { $Jindi = $False }                            
                           
                                $DataMatch = $PropFile.FullName | Select-String $Regex2 -AllMatches | ForEach-Object { $_.Matches.Value }
                                $ReferenceNumber = $DataMatch.Substring($DataMatch.Length - 1)
                            
                                $Log4JFullPathValue = @()
                            
                                $ObjProp1 = @{    
                                    ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                                    FullPath                  = ([String]$Log4JFullPathValue += Foreach ($Number in $LinkingObject) { If ($Number.ReferenceNumber -eq $ReferenceNumber) { $Number.FullPath } })    
                                    JndiLookupClass           = $Jindi
                                    Log4JVersion              = "No Pom.Properties File Found, Tried older MANIFEST.MF:" + ($MF_ImplementationVersion = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex5"))
                                    GroupId                   = If (($NoMF = $MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex6")).length -eq "0") { "No Pom.Properties File Found, Tried older MANIFEST.MF:" + ( $NoMF = $MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex6_2")) } Else { "No Pom.Properties File Found, Tried older MANIFEST.MF:" + ($NoMF = $MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex6")) }
                                    artifactId                = "No Pom.Properties File Found, Tried older MANIFEST.MF:" + ($MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex7")) #-replace "artifactId=", ""
                                    PomPropertiesExist        = $PomPropertiesExist
                                    Suspected_Processes       = If (-NOT [string]::IsNullOrEmpty($NetworkStats.Process)) { [String]$NetworkStats.Process }  Else { [string]"N/A" } 
                                    Suspected_Ports           = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalPort)) { [String]$NetworkStats.LocalPort }  Else { [string]"N/A" }
                                    Suspected_LocalAddresses  = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalAddress)) { [String]$NetworkStats.LocalAddress }  Else { [string]"N/A" }
                                    PSVersion                 = ($PSVersionTable.PSVersion)
                                    Suspected_FullNetworkInfo = If (-NOT [string]::IsNullOrEmpty($NetworkStats)) { $NetworkStats | ConvertTo-Json -Depth 100 -Compress }  Else { [string]"N/A" }
                                    WebScan_Ports             = If (-NOT [string]::IsNullOrEmpty($WebScan_Port_String)) { [String]$WebScan_Port_String }  Else { [string]"N/A" } 
                                    WebScan_Result            = If (-NOT [string]::IsNullOrEmpty($WebScanResult_String)) { [String]$WebScanResult_String }  Else { [string]"N/A" }
                                    WebScan_Vulnerable        = If (-NOT [string]::IsNullOrEmpty($WebScan_Vulnerable_String)) { [String]$WebScan_Vulnerable_String }  Else { [string]"N/A" }
                                    WebScan_httpStatusCode    = If (-NOT [string]::IsNullOrEmpty($WebScan_httpStatusCode_String)) { [String]$WebScan_httpStatusCode_String }  Else { [string]"N/A" }
                                    WebScan_Local_WebSite     = If (-NOT [string]::IsNullOrEmpty($WebScan_Local_Website_String)) { [String]$WebScan_Local_Website_String }  Else { [string]"N/A" } 
                            
                                }
                            
                                $TempObj = New-Object -TypeName psobject -Property $ObjProp1 
                                $ReportObj += $TempObj
                            }
                        }
                            
                            
                        $ReportObj = $ReportObj | Where-Object { $_.Log4JVersion -ne "" }

                        $ReportObj
                                       
                        #write-Host "13.) Completed."
                        
                        Remove-Item -Path "C:\Temp\Log4j\Extracted\" -Recurse | out-Null
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
                    JndiLookupClass           = "N/A"
                    Log4JVersion              = "N/A"
                    GroupId                   = "N/A"
                    artifactId                = "N/A"
                    PomPropertiesExist        = "N/A"
                    Suspected_Processes       = "N/A"
                    Suspected_Ports           = "N/A"
                    Suspected_LocalAddresses  = "N/A"
                    PSVersion                 = "N/A"
                    Suspected_FullNetworkInfo = "N/A"
                    WebScan_Ports             = "N/A"
                    WebScan_Result            = "N/A"
                    WebScan_Vulnerable        = "N/A"
                    WebScan_httpStatusCode    = "N/A"
                    WebScan_Local_WebSite     = "N/A"
                        
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
    #$ItemNameServerName = Import-csv $Item
    
    Start-Job -ScriptBlock $ScriptBlock | Out-Null
        
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

#Stop Running Jobs after 25min - 1500 seconds

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
                JndiLookupClass           = "N/A"
                Log4JVersion              = $RunningJob.Output
                GroupId                   = $RunningJob.Error
                artifactId                = "N/A"
                PomPropertiesExist        = "N/A"
                Suspected_Processes       = "N/A"
                Suspected_Ports           = "N/A"
                Suspected_LocalAddresses  = "N/A"
                PSVersion                 = "N/A"
                Suspected_FullNetworkInfo = "N/A"
                WebScan_Ports             = "N/A"
                WebScan_Result            = "N/A"
                WebScan_Vulnerable        = "N/A"
                WebScan_httpStatusCode    = "N/A"
                WebScan_Local_WebSite     = "N/A"
                    
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
Write-host "6.) Building Report Object.."

If (Test-Path "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv") {

    $FixOffLineServers_ForReporting = Import-csv "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv"

    $ReportObj7 = @()
    Foreach ($OffLineServer in $FixOffLineServers_ForReporting) {

        $ObjProp7 = [ordered]@{    
            ServerName                = $OffLineServer.DnsHostName
            FullPath                  = $OffLineServer.Status
            JndiLookupClass           = "N/A"
            Log4JVersion              = "N/A"
            GroupId                   = "N/A"
            artifactId                = "N/A"
            PomPropertiesExist        = "N/A"
            Suspected_Processes       = "N/A"
            Suspected_Ports           = "N/A"
            Suspected_LocalAddresses  = "N/A"
            PSVersion                 = "N/A"
            Suspected_FullNetworkInfo = "N/A"
            WebScan_Ports             = "N/A"
            WebScan_Result            = "N/A"
            WebScan_Vulnerable        = "N/A"
            WebScan_httpStatusCode    = "N/A"
            WebScan_Local_WebSite     = "N/A"
                    
        }
        $TempObj7 = New-Object -TypeName psobject -Property $ObjProp7 #| Export-csv C:\Temp\Log4j\Extracted\Report2.csv -NoTypeInformation -Append
        $ReportObj7 += $TempObj7
    }
}

Start-Sleep -Seconds 3
$ReportObj7 | Export-csv "C:\Temp\Log4j\log4j-reports\Log4J-Servers-Offline-$DnsShortName.csv" -Force -NoTypeInformation
Start-Sleep -Seconds 3

$FixEmptyObjects_ForReporting = Get-ChildItem -Path C:\Temp\Log4j\log4j-reports\*.csv | Select-Object Name, FullName, Length | Where-Object { ($_.FullName -ne "C:\Temp\Log4j\log4j-reports\Log4J-Server-Report-$DnsShortName.csv") -and ($_.Length -eq "0") }
$FixEmptyObjects_ForReporting1 = $FixEmptyObjects_ForReporting.name -replace ".csv", "$DnsDomainSuffix"

If ($FixEmptyObjects_ForReporting1.Length -ne "0") {

    $ReportObj9 = @()
    Foreach ($EmptyObjects in $FixEmptyObjects_ForReporting1) {

        $ObjProp9 = [ordered]@{    
            ServerName                = [String]$EmptyObjects
            FullPath                  = "Error, Script Returned Empty Objects"
            JndiLookupClass           = "N/A"
            Log4JVersion              = "N/A"
            GroupId                   = "N/A"
            artifactId                = "N/A"
            PomPropertiesExist        = "N/A"
            Suspected_Processes       = "N/A"
            Suspected_Ports           = "N/A"
            Suspected_LocalAddresses  = "N/A"
            PSVersion                 = "N/A"
            Suspected_FullNetworkInfo = "N/A"
            WebScan_Ports             = "N/A"
            WebScan_Result            = "N/A"
            WebScan_Vulnerable        = "N/A"
            WebScan_httpStatusCode    = "N/A"
            WebScan_Local_WebSite     = "N/A"
                    
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
        JndiLookupClass           = $Log4jItem.JndiLookupClass
        Log4JVersion              = $Log4jItem.Log4JVersion
        WebScan_Vulnerable        = $Log4jItem.WebScan_Vulnerable
        GroupId                   = $Log4jItem.GroupId
        artifactId                = $Log4jItem.artifactId        
        WebScan_Ports             = $Log4jItem.WebScan_Ports
        WebScan_Result            = $Log4jItem.WebScan_Result        
        WebScan_httpStatusCode    = $Log4jItem.WebScan_httpStatusCode 
        WebScan_Local_WebSite     = $Log4jItem.WebScan_Local_WebSite
        PomPropertiesExist        = $Log4jItem.PomPropertiesExist
        Suspected_Processes       = $Log4jItem.Suspected_Processes
        Suspected_Ports           = $Log4jItem.Suspected_Ports
        Suspected_LocalAddresses  = $Log4jItem.Suspected_LocalAddresses
        PSVersion                 = $Log4jItem.PSVersion
        Suspected_FullNetworkInfo = $Log4jItem.Suspected_FullNetworkInfo                    
    }
    $TempObj3 = New-Object -TypeName psobject -Property $ObjProp3 
    $ReportObj3 += $TempObj3
}

Write-host "7.) Complete."

$ReportObj3 | Sort-Object -Property ServerName, Fullname | Export-csv C:\Temp\Log4j\Log4J-Server-Report-$DnsShortName.csv -NoTypeInformation -Force

Remove-Item "C:\temp\Log4j\Extracted\" -Recurse
Remove-Item "C:\temp\Log4j\log4j-reports" -Recurse   

Write-host "8.) --All Complete--"
Write-host "9.) ------------------"     
    
