import argparse
from utils import run_test
from report_generator import generate_report

# Banner
def print_banner():
    banner = r"""
________    ___ ___ _________ __________  __________                 .__.__   .__                                   ___________                __                  
\______ \  /   |   \\_   ___ \\______   \ \______   \  ____    ______|__|  |  |__|  ____    ____   ____   ____      \__    ___/____    _______/  |_   ____ _______ 
 |    |  \/    ~    |    \  \/ |     ___/  |       _/_/ __ \  /  ___/|  |  |  |  |_/ __ \  /    \_/ ___\_/ __ \       |    | _/ __ \  /  ___/\   __\_/ __ \\_  __ \
 |    `   \    Y    |     \____|    |      |    |   \\  ___/  \___ \ |  |  |__|  |\  ___/ |   |  \  \___\  ___/       |    | \  ___/  \___ \  |  |  \  ___/ |  | \/
/_______  /\___|_  / \______  /|____|______|____|_  / \___  >/____  >|__|____/|__| \___  >|___|  /\___  >\___  >______|____|  \___  >/____  > |__|   \___  >|__|   
        \/       \/         \/      /_____/       \/      \/      \/                   \/      \/     \/     \//_____/            \/      \/             \/        

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

    print("\n[!] WARNING: Authorized use only. Misuse may be illegal.\n")
    args = parser.parse_args()

    log = run_test(args.interface, args.count, args.mode)

    if args.report:
        generate_report(log)

if __name__ == "__main__":
    main()

