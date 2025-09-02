######################################################################################################################################################################################################################
# Python script for DHCP resilience/starvation testing. By 41ph4-01, and our community. Note: Be mindful of the scope of work, & rules of engagement.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import argparse
from utils import run_test
from report_generator import generate_report

# Banner
def print_banner():
    banner = r"""
________    ___ ___  _____________________________              .__.__  .__                              ___________              __                _____ ______________  ___ ___    _____           _______  ____ 
\______ \  /   |   \ \_   ___ \______   \______   \ ____   _____|__|  | |__| ____   ____   ____  ____    \__    ___/___   _______/  |_             /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
 |    |  \/    ~    \/    \  \/|     ___/|       _// __ \ /  ___/  |  | |  |/ __ \ /    \_/ ___\/ __ \     |    |_/ __ \ /  ___/\   __\  ______   /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    `   \    Y    /\     \___|    |    |    |   \  ___/ \___ \|  |  |_|  \  ___/|   |  \  \__\  ___/     |    |\  ___/ \___ \  |  |   /_____/  /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
/_______  /\___|_  /  \______  /____|____|____|_  /\___  >____  >__|____/__|\___  >___|  /\___  >___  >____|____| \___  >____  > |__|            \____   ||___||____|    \___|_  /\____   |           \_____  /___|
        \/       \/          \/    /_____/      \/     \/     \/                \/     \/     \/    \/_____/          \/     \/                       |__|                     \/      |__|                 \/     

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

"""
    print(banner)
    print("DHCP Resilience Testing - 41PH4-01 & Our Community\n")

def main():
    parser = argparse.ArgumentParser(description="DHCP Resilience Tester (Ethical Use Only)")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("--count", type=int, default=100, help="Number of DHCPDISCOVER packets to send")
    parser.add_argument("--mode", choices=["simulation", "live"], default="simulation", help="Test mode")
    parser.add_argument("--report", action="store_true", help="Generate report at the end")

    print("\n[!] WARNING: Authorised use only. Misuse may be illegal.\n")
    args = parser.parse_args()

    log = run_test(args.interface, args.count, args.mode)

    if args.report:
        generate_report(log)

if __name__ == "__main__":
    main()

