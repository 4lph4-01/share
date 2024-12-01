########################################################################################################################################################################################################################
# Python script to identify accounts suceptible ASRepRoast By 41ph4-01 23/04/2024 
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
    splash = """
   def display_splash_screen():
    splash = """

\033[36m   _____    ___________________                                              __  .__                       _____                                     __                       _____  ____.____   __________  ___ ___    _____           _______  ____ 
\033[34m  /  _  \  /   _____/\______   \  ____  ______ _______  _________    _______/  |_|__| ____   ____         /  _  \   ____   ____   ____  __ __  _____/  |_ ______             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
\033[35m /  /_\  \ \_____  \  |       _/_/ __ \ \____ \\_  __ \/  _ \__  \  /  ___/\   __\  |/    \ / ___\       /  /_\  \_/ ___\_/ ___\ /  _ \|  |  \/    \   __|  ___/   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
\033[36m/    |    \/        \ |    |   \\  ___/ |  |_> >|  | \(  <_> ) __ \_\___ \  |  | |  |   |  | /_/  >     /    |    \  \___\  \___(  <_> )  |  /   |  \  | \___ \   /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
\033[34m \____|__  /_______  / |____|_  / \___  >|   __/ |__|   \____(____  /____  > |__| |__|___|  |___  /______\____|__  /\___  >\___  >\____/|____/|___|  /__|/____  >           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
\033[35m         \/        \/         \/      \/ |__|                     \/     \/               \/_____//_____/        \/     \/     \/                  \/         \/                 |__|             \/               \/      |__|                 \/     

\033[37m_:_
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
   
 \033[0m 
"""

    print(splash)
    print("Accounts Suceptible to ASReproasting 41PH4-01\n")

def audit_asreproast(domain):
    # Connect to Active Directory
    ad_query = adquery.ADQuery()

    # Define query to retrieve user accounts with pre-authentication disabled
    query = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

    # Execute the query
    ad_query.execute_query(attributes=["sAMAccountName"], where_clause=query)

    # Display results
    print("Vulnerable User Accounts:")
    for row in ad_query.get_results():
        print(row["sAMAccountName"])

if __name__ == "__main__":
    # Define the target Active Directory domain
    domain = "jurassic.park"

    # Perform ASRepRoasting vulnerability audit
    audit_asreproast(domain)
