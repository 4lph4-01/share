#########################################################################################################################################################################################################################
# Basic powershell script to make a comparison between a set of spreadsheets and highligh duplicates (under construction): By 41ph4-01 23/04/2024 & our community. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################


# Import Data
$cves1 = Import-Csv -Path "C:\path\to\cves1.csv"
$cves2 = Import-Csv -Path "C:\path\to\cves2.csv"

# Identify Duplicates Within Each Set
$duplicatesCves1 = $cves1 | Group-Object -Property CVE_ID | Where-Object { $_.Count -gt 1 }
$duplicatesCves2 = $cves2 | Group-Object -Property CVE_ID | Where-Object { $_.Count -gt 1 }

# Identify Duplicates Between the Two Sets
$duplicatesBetweenSets = Compare-Object -ReferenceObject $cves1 -DifferenceObject $cves2 -Property CVE_ID -IncludeEqual -ExcludeDifferent | Where-Object { $_.SideIndicator -eq "==" }

# Prepare the output list
$output = @()

# Add duplicates within cves1.csv to the output
$output += $duplicatesCves1 | ForEach-Object {
    [PSCustomObject]@{
        CVE_ID = $_.Name
        Source = "Data1"
        Count = $_.Count
    }
}

# Add duplicates within cves2.csv to the output
$output += $duplicatesCves2 | ForEach-Object {
    [PSCustomObject]@{
        CVE_ID = $_.Name
        Source = "Data2"
        Count = $_.Count
    }
}

# Add duplicates between the two sets to the output
$output += $duplicatesBetweenSets | ForEach-Object {
    [PSCustomObject]@{
        CVE_ID = $_.CVE_ID
        Source = "Both"
        Count = 1
    }
}

# Output results to the console
$output | Format-Table -AutoSize

# Optional: Export vulnerabilities to a CSV file
$output | Export-Csv -Path "C:\Scripts\vulnerabilities.csv" -NoTypeInformation


###############################################################################################################################################
#Import Data: Load CVE data from two CSV files using Import-Csv.
#Identify Duplicates Within Each Set: Use Group-Object to find duplicates within each dataset.
#Identify Duplicates Between the Two Sets: Use Compare-Object to find CVEs present in both datasets.
#Prepare the Output List: Combine all identified duplicates into a single list with a clear indication of their source (Data1, Data2, or Both).
#Output Results: Display the results in a formatted table and optionally export them to a CSV file.
###############################################################################################################################################
