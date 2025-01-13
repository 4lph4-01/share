#########################################################################################################################################################################################################################
# Basic python script to make a comparison between a set of spreadsheets and highlight duplicates. The script will produce a DataFrame listing all CVEs found in both CSV files (under construction): 41ph4-01 01/06/2024 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

import pandas as pd

# Banner
def display_splash_screen():
    splash = r"""
   
_________   _____________   ____  _________                                      .__                                   _____  ____.____   __________  ___ ___    _____           _______  ____ 
\_   ___ \ /   _____/\   \ /   /  \_   ___ \   ____   _____ ______ _____  _______|__| ______ ____   ____              /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
/    \  \/ \_____  \  \   Y   /   /    \  \/  /  _ \ /     \\____ \\__  \ \_  __ \  |/  ___//  _ \ /    \   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
\     \____/        \  \     /    \     \____(  <_> )  Y Y  \  |_> >/ __ \_|  | \/  |\___ \(  <_> )   |  \ /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 \______  /_______  /   \___/______\______  / \____/|__|_|  /   __/(____  /|__|  |__/____  >\____/|___|  /          \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
        \/        \/        /_____/       \/              \/|__|        \/               \/            \/                |__|             \/               \/      |__|                 \/   

  (_ _)
   | |____....----....____         _
   | |\                . .~~~~---~~ |
   | | |         __\\ /(/(  .       |
   | | |      <--= '|/_/_( /|       |
   | | |       }\~) | / _(./      ..|
   | | |.:::::::\\/      --...::::::|
   | | |:::::::::\//::\\__\:::::::::|
   | | |::::::::_//_:_//__\\_:::::::|
   | | |::::::::::::::::::::::::::::|
   | |/:::''''~~~~'''':::::::::::::'~
   | | 
                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("CSV Comparison 41PH4-01\n")

# Step 1: Import Data
cves1 = pd.read_csv("cves1.csv")
cves2 = pd.read_csv("cves2.csv")

# Step 2: Identify Duplicates Between the Two Sets
merged_cves = pd.merge(cves1, cves2, on='CVE_ID', how='inner', suffixes=('_Data1', '_Data2'))

# Step 3: Prepare the Output
output = pd.DataFrame(columns=['CVE_ID', 'Source'])

# Add duplicates between the two sets to the output
for cve_id in merged_cves['CVE_ID'].unique():
    output = output.append({'CVE_ID': cve_id, 'Source': 'Both'}, ignore_index=True)

# Output results
print(output)

# Optional: Export vulnerabilities to a CSV file
output.to_csv("vulnerabilities.csv", index=False)

###########################################################################################################################################################################################################################
#Import Data: Load CVE data from two CSV files using pd.read_csv.
#Identify Duplicates Between the Two Sets: Use pd.merge to find CVEs present in both DataFrames. This identifies duplicates between the two datasets.
#Prepare the Output: Create a new DataFrame to store the results, indicating the CVEs found in both datasets.
#Output Results: Print the results and optionally export them to a CSV file.
###########################################################################################################################################################################################################################
