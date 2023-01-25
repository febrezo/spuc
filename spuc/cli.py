import argparse
import json
import logging

import spuc
from spuc.exceptions import SPUCException
from spuc.conversors.kql import KQLConversor
from spuc.conversors.snort import SnortConversor
from spuc.conversors.tql import TQLConversor
from spuc.conversors.xql import XQLConversor


CONVERSOR_CHOICES = {
    # "crowdstrike",
    # "cytomic",
    # "elastic",
    "kql": KQLConversor,
    # "sigma", 
    "snort": SnortConversor,
    # "splunk", 
    # "suricata", 
    "tql": TQLConversor, 
    "xql": XQLConversor,
    # "yara"
}


def main():
    """Main function that starts the loop"""

    parser = argparse.ArgumentParser(
        description='SPUC: STIX Pattern Universal Conversor.',
        add_help=False
    )
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        '-f', '--file',
        metavar='<STIX_FILE>',
        nargs="+",
        help='STIX 2 file from where the STIX Indicators will be grabbed.'
    )
    action_group.add_argument(
        '-i', '--interactive',
        default=False,
        action='store_true',
        help='Whether to run in interactive mode.'
    )
    action_group.add_argument(
        '-l', '--list-conversors',
        default=False,
        action='store_true',
        help='Shows the available list of conversors.'
    )
    action_group.add_argument(
        '-p', '--patterns',
        metavar='<STIX_PATTERN>',
        nargs="+",
        help='Pattern (or patterns) to be translated.'
    )
    action_group.add_argument(
        '-V', '--validate',
        metavar='<STIX_PATTERN>',
        nargs="+",
        help='Pattern (or patterns) to be validated.'
    )


    # Processing options
    # ------------------
    group_processing = parser.add_argument_group(
        'Processing options',
        'Setting processing flags and options.'
    )
    group_processing.add_argument(
        '-c', '--conversors',
        metavar='<CONVERSOR>',
        nargs="+",
        choices=["all"] + list(CONVERSOR_CHOICES.keys()),
        default=["all"],
        help='Conversors to which the pattern will be translated.'
    )
    group_processing.add_argument(
        '-L', '--log-level',
        metavar='<LEVEL>',
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help='The log level to be used by the app. Valid values: DEBUG, INFO, WARNING, and ERROR.'
    )

    # Metadata options
    # ----------------
    group_metadata = parser.add_argument_group(
        'Metadata info',
        'Set default metadata for the newly created rules.'
    )
    group_metadata.add_argument(
        '-a', '--author-name',
        metavar='<NAME>',
        action='store',
        default="Félix Brezo (@febrezo)",
        help='Sets the author name.'
    )
    group_metadata.add_argument(
        '-d', '--description',
        metavar='<DESCRIPTION>',
        action='store',
        default="Rule automatically created using SPUC",
        help='Sets the description message.'
    )
    group_metadata.add_argument(
        '-e', '--author-email',
        metavar='<EMAIL>',
        action='store',
        default="contacto@felixbrezo.com",
        help='Sets the author email.'
    )
    group_metadata.add_argument(
        '-r', '--reference',
        metavar='<URL>',
        action='store',
        nargs='+',
        default=["https://github.com/febrezo/spuc"],
        help='Sets additional references for the rules.'
    )

    # About options
    # -------------
    groupAbout = parser.add_argument_group(
        'About this package',
        'Get additional information about this package.'
    )
    groupAbout.add_argument(
        '-h', '--help',
        action='help',
        help='shows this help and exits.'
    )
    groupAbout.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {spuc.__version__}',
        help='shows the version of this package and exits.'
    )

    args = parser.parse_args()

    FORMAT = '%(asctime)s | [%(levelname)s] %(message)s'
    logging.basicConfig(format=FORMAT, level=args.log_level)

    if args.list_conversors:
        print(f"Available conversors in this version of SPUC are: {', '.join(list(CONVERSOR_CHOICES.keys()))}.")
    elif args.patterns:
        print("Starting SPUC CLI conversor for the parameters provided…")
        for pattern in args.patterns:
            print(f">>> {pattern}")
            for i, c in enumerate(args.conversors):
                conversor = CONVERSOR_CHOICES[c]()
                try:
                    rules = conversor.translate(pattern)
                    print(f"    {i+1}/{len(args.conversors)} {c.title()} rules conversion status: [SUCCESS]")
                    for r in rules:
                        print(f"\t\t{r}")
                except SPUCException as _:
                    print(f"    {i+1}/{len(args.conversors)} {c.title()} rules conversion status: [ERROR] {_}")
    elif args.file:
        print(f"Not yet implemented. Exiting…")
        sys.exit(-1)
    else:
        print("Starting SPUC in interactive mode.")
        print("Press <Ctrl + C> to exit.")
        try:
            while 1:
                pattern = input(">>> ")
                for i, c in enumerate(args.conversors):
                    conversor = CONVERSOR_CHOICES[c]()                            
                    try:
                        rules = conversor.translate(pattern)
                        print(f"    {i+1}/{len(args.conversors)} {c.title()} rules conversion status: [SUCCESS]")
                        for r in rules:
                            print(f"\t\t{r}")
                    except SPUCException as _:
                        print(f"    {i+1}/{len(args.conversors)} {c.title()} rules conversion status: [ERROR] {_}")
        except KeyboardInterrupt as _:
            print("\nManually interrupted by the user.")

if __name__ == "__main__":
    main()
