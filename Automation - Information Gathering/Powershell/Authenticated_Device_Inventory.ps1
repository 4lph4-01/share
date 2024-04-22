########################################################################################################################################################################################
# Powershell automated Information Gathering Script By: 41ph4-01 for simulation 11/04/2024
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################


# ==============================================================================================
# Functions Section
# ==============================================================================================
# Function Name 'WMILookup' - Gathers info using WMI and places results in Excel
# ==============================================================================================
Function WMILookup {
foreach ($StrComputer in $colComputers) {

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing ComputerSystem data" -id 1
		$GenItems1 = gwmi Win32_ComputerSystem -Comp $StrComputer

        # when inventorying all domain servers, this computer is ID'ed as "0".  Do not inventory this computer.
		if($StrComputer -eq "0") {continue}

        # If unable to capture system info, computer is not accessbile.  Skip to next computer.
        if(!$GenItems1){
			Write-Host "$StrComputer not found" -ForegroundColor Red
			continue
		}

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing OperatingSystem data" -id 1
		$GenItems2 = gwmi Win32_OperatingSystem -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing BIOS data" -id 1
		$SysItems1 = gwmi Win32_BIOS -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing TimeZone data" -id 1
		$SysItems2 = gwmi Win32_TimeZone -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing WMISetting data" -id 1
		$SysItems3 = gwmi Win32_WmiSetting -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing Processor data" -id 1
		$ProcItems1 = gwmi Win32_Processor -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing PhysicalMemory data" -id 1
		$MemItems1 = gwmi Win32_PhysicalMemory -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing PhysicalMemoryArray data" -id 1
		$memItems2 = gwmi Win32_PhysicalMemoryArray -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing LogicalDisk data" -id 1
		$DiskItems = gwmi Win32_LogicalDisk -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing NetworkAdapterConfiguration data" -id 1
		$NetItems = gwmi Win32_NetworkAdapterConfiguration -Comp $StrComputer | where{$_.IPEnabled -eq "True"}

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing Installed Product data" -id 1
		$SoftwareItems = gwmi Win32_Product -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing Roles and Features data" -id 1
        $FeaturesItems = gwmi Win32_ServerFeature -Comp $StrComputer

        Write-Progress -Activity "Getting Inventory" -status "$StrComputer - Capturing Scheduled Task data" -id 1
        $TaskItems = Get-SchTasks -ComputerName $StrComputer | where {$_.ID -eq 'Author'}
				
# Populate General Sheet(1) with information

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing OperatingSystem data" -id 1
	foreach ($objItem in $GenItems1){
		$Sheet1.Cells.Item($intRow, 1) = $StrComputer
		Switch($objItem.DomainRole)
			{
			0{$Sheet1.Cells.Item($intRow, 2) = "Stand Alone Workstation"}
			1{$Sheet1.Cells.Item($intRow, 2) = "Member Workstation"}
			2{$Sheet1.Cells.Item($intRow, 2) = "Stand Alone Server"}
			3{$Sheet1.Cells.Item($intRow, 2) = "Member Server"}
			4{$Sheet1.Cells.Item($intRow, 2) = "Back-up Domain Controller"}
			5{$Sheet1.Cells.Item($intRow, 2) = "Primary Domain Controller"}
			default{$Sheet1.Cells.Item($intRow, 2) = "Undetermined"}
			}
		$Sheet1.Cells.Item($intRow, 3) = $objItem.Manufacturer
		$Sheet1.Cells.Item($intRow, 4) = $objItem.Model
		$Sheet1.Cells.Item($intRow, 5) = $objItem.SystemType
		$Sheet1.Cells.Item($intRow, 6) = $objItem.NumberOfProcessors
		$Sheet1.Cells.Item($intRow, 7) = $objItem.TotalPhysicalMemory / 1024 / 1024
		}

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing OperatingSystem data" -id 1
	foreach ($objItem in $GenItems2){
		$Sheet1.Cells.Item($intRow, 8) = $objItem.Caption
		$Sheet1.Cells.Item($intRow, 9) = $objItem.csdversion
		}
			
#Populate Systems Sheet

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing BIOS data" -id 1
	foreach ($objItem in $SysItems1){
		$Sheet2.Cells.Item($intRow, 1) = $StrComputer
		$Sheet2.Cells.Item($intRow, 2) = $objItem.Name
		$Sheet2.Cells.Item($intRow, 3) = $objItem.SMBIOSbiosVersion
		$Sheet2.Cells.Item($intRow, 4) = $objItem.SerialNumber
		}

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing TimeZone data" -id 1
	foreach ($objItem in $SysItems2){	
		$Sheet2.Cells.Item($intRow, 5) = $objItem.Caption
		}

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing WMISetting data" -id 1
	foreach ($objItem in $SysItems3){
		$Sheet2.Cells.Item($intRow, 6) = $objItem.BuildVersion
		}
				
#Populate Processor Sheet		

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing Processor data" -id 1   
	foreach ($objItem in $ProcItems1){
		$Sheet3.Cells.Item($intRowCPU, 1) = $StrComputer
		$Sheet3.Cells.Item($intRowCPU, 2) = $objItem.DeviceID+" "+$objItem.Name
		$Sheet3.Cells.Item($intRowCPU, 3) = $objItem.Description
		$Sheet3.Cells.Item($intRowCPU, 4) = $objItem.family
		$Sheet3.Cells.Item($intRowCPU, 5) = $objItem.currentClockSpeed
		$Sheet3.Cells.Item($intRowCPU, 6) = $objItem.l2cacheSize
		$Sheet3.Cells.Item($intRowCPU, 7) = $objItem.UpgradeMethod
		$Sheet3.Cells.Item($intRowCPU, 8) = $objItem.SocketDesignation
		$intRowCPU = $intRowCPU + 1
		}
				
#Populate Memory Sheet
$bankcounter = 1
	Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing PhysicalMemoryArray data" -id 1
    foreach ($objItem in $memItems2){
		$MemSlots = $objItem.MemoryDevices +1
			
	Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing PhysicalMemory data" -id 1
    foreach ($objItem in $MemItems1){
		$Sheet4.Cells.Item($intRowMem, 1) = $StrComputer
		$Sheet4.Cells.Item($intRowMem, 2) = "Bank " +$bankcounter
	if($objItem.BankLabel -eq ""){
		$Sheet4.Cells.Item($intRowMem, 3) = $objItem.DeviceLocator}
	Else{$Sheet4.Cells.Item($intRowMem, 3) = $objItem.BankLabel}
		$Sheet4.Cells.Item($intRowMem, 4) = $objItem.Capacity/1024/1024
		$Sheet4.Cells.Item($intRowMem, 5) = $objItem.FormFactor
		$Sheet4.Cells.Item($intRowMem, 6) = $objItem.TypeDetail
		$intRowMem = $intRowMem + 1
		$bankcounter = $bankcounter + 1
		}
	while($bankcounter -lt $MemSlots)	
		{
		$Sheet4.Cells.Item($intRowMem, 1) = $StrComputer
		$Sheet4.Cells.Item($intRowMem, 2) = "Bank " +$bankcounter
		$Sheet4.Cells.Item($intRowMem, 3) = "is Empty"
		$Sheet4.Cells.Item($intRowMem, 4) = ""
		$Sheet4.Cells.Item($intRowMem, 5) = ""
		$Sheet4.Cells.Item($intRowMem, 6) = ""
		$intRowMem = $intRowMem + 1
		$bankcounter = $bankcounter + 1
		}
	}
			
			
#Populate Disk Sheet

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing LogicalDisk data" -id 1
	foreach ($objItem in $DiskItems){
		$Sheet5.Cells.Item($intRowDisk, 1) = $StrComputer
        Switch($objItem.DriveType)
		    {
		    2{$Sheet5.Cells.Item($intRowDisk, 2) = "Floppy"}
		    3{$Sheet5.Cells.Item($intRowDisk, 2) = "Fixed Disk"}
		    5{$Sheet5.Cells.Item($intRowDisk, 2) = "Removable Media"}
            default{$Sheet5.Cells.Item($intRowDisk, 2) = "Undetermined"}
		    }
		$Sheet5.Cells.Item($intRowDisk, 3) = $objItem.DeviceID
		$Sheet5.Cells.Item($intRowDisk, 4) = $objItem.Size/1024/1024
		$Sheet5.Cells.Item($intRowDisk, 5) = $objItem.FreeSpace/1024/1024
		$intRowDisk = $intRowDisk + 1
		}
		
#Populate Network Sheet

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing NetworkAdapterConfiguration data" -id 1
	foreach ($objItem in $NetItems){
		$Sheet6.Cells.Item($intRowNet, 1) = $StrComputer
		$Sheet6.Cells.Item($intRowNet, 2) = $objItem.Caption+" (enabled)"
		$Sheet6.Cells.Item($intRowNet, 3) = $objItem.DHCPEnabled
		$Sheet6.Cells.Item($intRowNet, 4) = $objItem.IPAddress
		$Sheet6.Cells.Item($intRowNet, 5) = $objItem.IPSubnet
		$Sheet6.Cells.Item($intRowNet, 6) = $objItem.DefaultIPGateway
		$Sheet6.Cells.Item($intRowNet, 7) = $objItem.DNSServerSearchOrder
		$Sheet6.Cells.Item($intRowNet, 8) = $objItem.FullDNSRegistrationEnabled
		$Sheet6.Cells.Item($intRowNet, 9) = $objItem.WINSPrimaryServer
		$Sheet6.Cells.Item($intRowNet, 10) = $objItem.WINSSecondaryServer
		$Sheet6.Cells.Item($intRowNet, 11) = $objItem.WINSEnableLMHostsLookup
		$intRowNet = $intRowNet + 1
		}

#Populate Software Inventory Sheet

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing Installed Product data" -id 1
	foreach ($objItem in $SoftwareItems){
		$Sheet7.Cells.Item($intRowSoftware, 1) = $StrComputer
		$Sheet7.Cells.Item($intRowSoftware, 2) = $objItem.Name
		$Sheet7.Cells.Item($intRowSoftware, 3) = $objItem.Vendor
		$Sheet7.Cells.Item($intRowSoftware, 4) = $objItem.Version
		$Sheet7.Cells.Item($intRowSoftware, 5) = $objItem.IdentifyingNumber
		$intRowSoftware = $intRowSoftware + 1
		}		

#Populate Roles and Features Sheet

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing Roles and Features data" -id 1
	foreach ($objItem in $FeaturesItems){
		$Sheet8.Cells.Item($intRowFeature, 1) = $StrComputer
		$Sheet8.Cells.Item($intRowFeature, 2) = $objItem.Name
		$intRowFeature = $intRowFeature + 1
		}		

#Populate Scheduled Tasks Sheet

    Write-Progress -Activity "Writing Inventory" -status "$StrComputer - Writing Scheduled Task data" -id 1
	foreach ($objItem in $TaskItems){
		$Sheet9.Cells.Item($intRowTask, 1) = $StrComputer
		$Sheet9.Cells.Item($intRowTask, 2) = $objItem.ID
		$Sheet9.Cells.Item($intRowTask, 3) = $objItem.Name
		$Sheet9.Cells.Item($intRowTask, 4) = $objItem.Command
		$Sheet9.Cells.Item($intRowTask, 5) = $objItem.Arguments
		$Sheet9.Cells.Item($intRowTask, 6) = $objItem.Enabled
		$Sheet9.Cells.Item($intRowTask, 7) = $objItem.StartDateTime
		$Sheet9.Cells.Item($intRowTask, 8) = $objItem.DayInterval
		$Sheet9.Cells.Item($intRowTask, 9) = $objItem.TimeLimit
		$Sheet9.Cells.Item($intRowTask, 10) = $objItem.RunAsAccount
		$Sheet9.Cells.Item($intRowTask, 11) = $objItem.RunLevel
		$Sheet9.Cells.Item($intRowTask, 12) = $objItem.Location
		$intRowTask = $intRowTask + 1
		}		

$intRow = $intRow + 1
$intRowCPU = $intRowCPU + 1
$intRowMem = $intRowMem + 1
$intRowDisk = $intRowDisk + 1
$intRowNet = $intRowNet + 1
$intRowSoftware = $intRowSoftware + 1
$intRowFeature = $intRowFeature + 1
$intRowTask = $intRowTask + 1
}
}



# ========================================================================
# Function Name Get-SchTasks 
# $tasks = Get-SchTasks -ComputerName servername | where {$_.ID -eq 'Author'}
# ========================================================================

function Get-SchTasks{
    Param(
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyname=$True)]
        $ComputerName = $Env:ComputerName
        )
[xml]$SchTasks = schtasks /query /XML ONE /S $ComputerName
$Tasks = $SchTasks.Tasks.Task
$Tasks | %{
    $TaskURI = $_.RegistrationInfo.URI
    if ($TaskURI -ne $null ) {
        $Name = Split-Path $TaskURI -Leaf;
        $Location = Split-Path $TaskURI -Parent;
    }
    else
    {
    $Name = $null
    $Location = $null
    }
    
    New-Object PSObject -Property @{
        ID = $_.Principals.Principal.ID
        Name = $Name
        Command = $_.Actions.Exec.Command
        Arguments = $_.Actions.Exec.Arguments
        Enabled = $_.Settings.Enabled
        StartDateTime = $_.Triggers.CalendarTrigger.StartBoundary
        DayInterval = $_.Triggers.CalendarTrigger.ScheduleByDay.DaysInterval
        TimeLimit = $_.Settings.ExecutionTimeLimit
        RunAsAccount = $_.Principals.Principal.UserID
        RunLevel = $_.Principals.Principal.RunLevel
        Location = $Location
        }
    }
}


# =============================================================================================
# Function Name 'ListComputers' - Enumerates ALL computer objects in AD
# ==============================================================================================
Function ListComputers {
$strCategory = "computer"

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.Filter = ("(objectCategory=$strCategory)")

$colProplist = "name"
foreach ($i in $colPropList){$objSearcher.PropertiesToLoad.Add($i)}

$colResults = $objSearcher.FindAll()

foreach ($objResult in $colResults)
    {$objComputer = $objResult.Properties; $objComputer.name}
}

# ==============================================================================================
# Function Name 'ListServers' - Enumerates ALL Servers objects in AD
# ==============================================================================================
Function ListServers {
$strCategory = "computer"
$strOS = "Windows*Server*"

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.Filter = ("(&(objectCategory=$strCategory)(OperatingSystem=$strOS))")

$colProplist = "name"
foreach ($i in $colPropList){$objSearcher.PropertiesToLoad.Add($i)}

$colResults = $objSearcher.FindAll()

foreach ($objResult in $colResults)
    {$objComputer = $objResult.Properties; $objComputer.name}
}

#
# ========================================================================
# Function Name Select-FileDialog #
###############################

# Example use:
# $file = Select-FileDialog -Title "Select a file" -Directory "D:\scripts" -Filter "Powershell Scripts|(*.ps1)"

function Select-FileDialog
{
param([string]$Title,[string]$Directory,[string]$Filter)
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$objForm = New-Object System.Windows.Forms.OpenFileDialog
$objForm.InitialDirectory = $Directory
$objForm.Filter = $Filter
$objForm.Title = $Title
$Show = $objForm.ShowDialog()
If ($Show -eq "OK") 
{
Return $objForm.FileName
} 
Else 
{
Write-Error "Operation cancelled by user."
}
}
# 

# ========================================================================
# Function Name 'ListTextFile' - Enumerates Computer Names in a text file
# Create a text file and enter the names of each computer. One computer
# name per line. Supply the path to the text file when prompted.
# ========================================================================
Function ListTextFile {
	$strText = Select-FileDialog -Title "Select a file" -Directory "c:" -Filter "Text Files (*.txt)|*.txt"
	$colComputers = Get-Content $strText
}

# ========================================================================
# Function Name 'SingleEntry' - Enumerates Computer from user input
# ========================================================================
Function ManualEntry {
	$colComputers = Read-Host "Enter Computer Name or IP" 
}



# ==============================================================================================
# Script Body
# ==============================================================================================
$erroractionpreference = "SilentlyContinue"


#Gather info from user.
Write-Host "********************************" 	-ForegroundColor Green
Write-Host "Computer Inventory Script" 		-ForegroundColor Green
Write-Host "Adapted By: 4lpha-01" 		-ForegroundColor Green
Write-Host "Created: 05/08/2014" 		-ForegroundColor Green
Write-Host "********************************"   -ForegroundColor Green
Write-Host                                  	-ForegroundColor Green
Write-Host " "
Write-Host "Which computer resources would you like in the report?"	-ForegroundColor Green
$strResponse = Read-Host "[1] All Domain Computers, [2] All Domain Servers, [3] Computer names from a File, [4] Choose a Computer manually"
If($strResponse -eq "1"){$colComputers = ListComputers | Sort-Object}
	elseif($strResponse -eq "2"){$colComputers = ListServers | Sort-Object}
	elseif($strResponse -eq "3"){. ListTextFile}
	elseif($strResponse -eq "4"){. ManualEntry}
	else{Write-Error "You did not supply a correct response, Please run script again." -foregroundColor Red}
Write-Progress -Activity "Getting Inventory" -status "Running..." -id 1

#New Excel Application
$culture = [System.Globalization.CultureInfo]"en-US"
$oldCulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
$Excel = New-Object -Com Excel.Application
$Excel.visible = $True

# Create 9 worksheets
$Excel = $Excel.Workbooks.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()
$Sheet = $Excel.Worksheets.Add()

# Assign each worksheet to a variable and
# name the worksheet.
$Sheet1 = $Excel.Worksheets.Item(1)
$Sheet2 = $Excel.WorkSheets.Item(2)
$Sheet3 = $Excel.WorkSheets.Item(3)
$Sheet4 = $Excel.WorkSheets.Item(4)
$Sheet5 = $Excel.WorkSheets.Item(5)
$Sheet6 = $Excel.WorkSheets.Item(6)
$Sheet7 = $Excel.WorkSheets.Item(7)
$Sheet8 = $Excel.WorkSheets.Item(8)
$Sheet9 = $Excel.WorkSheets.Item(9)
$Sheet1.Name = "General"
$Sheet2.Name = "System"
$Sheet3.Name = "Processor"
$Sheet4.Name = "Memory"
$Sheet5.Name = "Disk"
$Sheet6.Name = "Network"
$Sheet7.Name = "Software"
$Sheet8.Name = "Features"
$Sheet9.Name = "Tasks"

#Create Heading for General Sheet
$Sheet1.Cells.Item(1,1) = "Device_Name"
$Sheet1.Cells.Item(1,2) = "Role"
$Sheet1.Cells.Item(1,3) = "HW_Make"
$Sheet1.Cells.Item(1,4) = "HW_Model"
$Sheet1.Cells.Item(1,5) = "HW_Type"
$Sheet1.Cells.Item(1,6) = "CPU_Count"
$Sheet1.Cells.Item(1,7) = "Memory_MB"
$Sheet1.Cells.Item(1,8) = "Operating_System"
$Sheet1.Cells.Item(1,9) = "SP_Level"

#Create Heading for System Sheet
$Sheet2.Cells.Item(1,1) = "Device_Name"
$Sheet2.Cells.Item(1,2) = "BIOS_Name"
$Sheet2.Cells.Item(1,3) = "BIOS_Version"
$Sheet2.Cells.Item(1,4) = "HW_Serial_#"
$Sheet2.Cells.Item(1,5) = "Time_Zone"
$Sheet2.Cells.Item(1,6) = "WMI_Version"

#Create Heading for Processor Sheet
$Sheet3.Cells.Item(1,1) = "Device_Name"
$Sheet3.Cells.Item(1,2) = "Processor(s)"
$Sheet3.Cells.Item(1,3) = "Type"
$Sheet3.Cells.Item(1,4) = "Family"
$Sheet3.Cells.Item(1,5) = "Speed_MHz"
$Sheet3.Cells.Item(1,6) = "Cache_Size_MB"
$Sheet3.Cells.Item(1,7) = "Interface"
$Sheet3.Cells.Item(1,8) = "#_of_Sockets"

#Create Heading for Memory Sheet
$Sheet4.Cells.Item(1,1) = "Device_Name"
$Sheet4.Cells.Item(1,2) = "Bank_#"
$Sheet4.Cells.Item(1,3) = "Label"
$Sheet4.Cells.Item(1,4) = "Capacity_MB"
$Sheet4.Cells.Item(1,5) = "Form"
$Sheet4.Cells.Item(1,6) = "Type"

#Create Heading for Disk Sheet
$Sheet5.Cells.Item(1,1) = "Device_Name"
$Sheet5.Cells.Item(1,2) = "Disk_Type"
$Sheet5.Cells.Item(1,3) = "Drive_Letter"
$Sheet5.Cells.Item(1,4) = "Capacity_MB"
$Sheet5.Cells.Item(1,5) = "Free_Space_MB"

#Create Heading for Network Sheet
$Sheet6.Cells.Item(1,1) = "Device_Name"
$Sheet6.Cells.Item(1,2) = "Network_Card"
$Sheet6.Cells.Item(1,3) = "DHCP_Enabled"
$Sheet6.Cells.Item(1,4) = "IP_Address"
$Sheet6.Cells.Item(1,5) = "Subnet_Mask"
$Sheet6.Cells.Item(1,6) = "Default_Gateway"
$Sheet6.Cells.Item(1,7) = "DNS_Servers"
$Sheet6.Cells.Item(1,8) = "DNS_Reg"
$Sheet6.Cells.Item(1,9) = "Primary_WINS"
$Sheet6.Cells.Item(1,10) = "Secondary_WINS"
$Sheet6.Cells.Item(1,11) = "WINS_Lookup"

#Create Heading for Software Inventory Sheet
$Sheet7.Cells.Item(1,1) = "Device_Name"
$Sheet7.Cells.Item(1,2) = "Title"
$Sheet7.Cells.Item(1,3) = "Vendor"
$Sheet7.Cells.Item(1,4) = "Version"
$Sheet7.Cells.Item(1,5) = "Identifying_Number"

#Create Heading for Roles and Features Sheet
$Sheet8.Cells.Item(1,1) = "Device_Name"
$Sheet8.Cells.Item(1,2) = "Role or Feature"

#Create Heading for Scheduled Tasks Sheet
$Sheet9.Cells.Item(1,1) = "Device_Name"
$Sheet9.Cells.Item(1,2) = "Job_Id"
$Sheet9.Cells.Item(1,3) = "Name"
$Sheet9.Cells.Item(1,4) = "Command"
$Sheet9.Cells.Item(1,5) = "Arguments"
$Sheet9.Cells.Item(1,6) = "Enabled"
$Sheet9.Cells.Item(1,7) = "StartDateTime"
$Sheet9.Cells.Item(1,8) = "DayInterval"
$Sheet9.Cells.Item(1,9) = "TimeLimit"
$Sheet9.Cells.Item(1,10) = "RunAsAccount"
$Sheet9.Cells.Item(1,11) = "RunLevel"
$Sheet9.Cells.Item(1,12) = "Location"

$colSheets = ($Sheet1, $Sheet2, $Sheet3, $Sheet4, $Sheet5, $Sheet6, $Sheet7, $Sheet8, $Sheet9)
foreach ($colorItem in $colSheets){
$intRow = 2
$intRowCPU = 2
$intRowMem = 2
$intRowDisk = 2
$intRowNet = 2
$intRowSoftware = 2
$intRowFeature = 2
$intRowTask = 2
$WorkBook = $colorItem.UsedRange
$WorkBook.Interior.ColorIndex = 20
$WorkBook.Font.ColorIndex = 11
$WorkBook.Font.Bold = $True
}

#Capture information for the selected devices
WMILookup

#Auto Fit all sheets in the Workbook
foreach ($colorItem in $colSheets){
    $WorkBook = $colorItem.UsedRange															
    $WorkBook.EntireColumn.AutoFit()
    clear
}

Write-Host "*******************************" -ForegroundColor Green
Write-Host "The Report has been completed."  -ForeGroundColor Green
Write-Host "*******************************" -ForegroundColor Green
# ========================================================================
# END of Script
# ========================================================================
