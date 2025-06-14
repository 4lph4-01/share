########################################################################################################################################################################################################################
# Python  script to identify accounts suceptible Kerberoasting By  41ph4-01 23/04/2024 & our community.  
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#########################################################################################################################################################################################################################

from pyad import adquery

# Banner
def display_splash_screen():
    splash = r"""
   
 ____  __.            ___.                                __  .__                       _____                                     __                      _____  ____         .__       _____           _______  ____ 
|    |/ _|____ _______\_ |_________  _________    _______/  |_|__| ____   ____         /  _  \   ____   ____   ____  __ __  _____/  |_ ______            /  |  |/_   |______  |  |__   /  |  |          \   _  \/_   |
|      <_/ __ \\_  __ \| __ \_  __ \/  _ \__  \  /  ___/\   __\  |/    \ / ___\       /  /_\  \_/ ___\_/ ___\ /  _ \|  |  \/    \   __|  ___/  ______   /   |  |_|   |\____ \ |  |  \ /   |  |_  ______ /  /_\  \|   |
|    |  \  ___/ |  | \/| \_\ \  | \(  <_> ) __ \_\___ \  |  | |  |   |  | /_/  >     /    |    \  \___\  \___(  <_> )  |  /   |  \  | \___ \  /_____/  /    ^   /|   ||  |_> >|   Y  |    ^   / /_____/ \  \_/   \   |
|____|__ \___  >|__|   |___  /__|   \____(____  /____  > |__| |__|___|  |___  /______\____|__  /\___  >\___  >\____/|____/|___|  /__|/____  >          \____   | |___||   __/ |___|  |____   |           \_____  /___|
        \/   \/            \/                 \/     \/               \/_____//_____/        \/     \/     \/                  \/         \/                |__|      |__|         \/     |__|                 \/     
        
                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/      (_ _)
                                 /\      {====}     )___(        | |____....----....____         _
                      (\=,      //\\      )__(     /_____\       | |\                . .~~~~---~~ |
      __    |'-'-'|  //  .\    (    )    /____\     |   |        | | |         __\\ /(/(  .       |
     /  \   |_____| (( \_  \    )__(      |  |      |   |        | | |      <--= '|/_/_( /|       |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |        | | |       }\~) | / _(./      ..|
    /____\   |   |  (/     \    |  |      |  |      |   |        | | |.:::::::\\/      --...::::::|
     |  |    |   |   | _.-'|    |  |      |  |      |   |        | | |:::::::::\//::\\__\:::::::::|
     |__|    )___(    )___(    /____\    /____\    /_____\       | | |::::::::_//_:_//__\\_:::::::| 
    (====)  (=====)  (=====)  (======)  (======)  (=======)      | | |::::::::::::::::::::::::::::|
    }===={  }====={  }====={  }======{  }======{  }======={      | |/:::''''~~~~'''':::::::::::::'~
   (______)(_______)(_______)(________)(________)(__________)    | |
   
 
"""

    print(splash)
    print("Accounts Suceptible to Kerbroasting 41PH4-01 & Our Community\n")

def audit_kerberoasting(domain):
    # Connect to Active Directory
    ad_query = adquery.ADQuery()

    # Define query to retrieve user accounts with service principal names (SPNs)
    query = "(&(objectClass=user)(servicePrincipalName=*))"

    # Execute the query
    ad_query.execute_query(attributes=["sAMAccountName"], where_clause=query)

    # Display results
    print("Vulnerable User Accounts (with SPNs):")
    for row in ad_query.get_results():
        print(row["sAMAccountName"])

if __name__ == "__main__":
    # Define the target Active Directory domain
    domain = "jurassic.park"

    # Perform Kerberoasting vulnerability audit
    audit_kerberoasting(domain)
