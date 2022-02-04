# greaseweazle/tools/pin.py
#
# Greaseweazle control script: Set a floppy interface pin to specified level.
#
# Written & released by Keir Fraser <keir.xen@gmail.com>
#
# This is free and unencumbered software released into the public domain.
# See the file COPYING for more details, or visit <http://unlicense.org>.

description = "Change the setting of a user-modifiable interface pin."

import sys, argparse

from greaseweazle.tools import util
from greaseweazle import usb as USB

def level(letter):
    levels = { 'H': True, 'L': False }
    if not letter.upper() in levels:
        raise argparse.ArgumentTypeError("invalid pin level: '%s'" % letter)
    return levels[letter.upper()]

def pin_set(argv):

    parser = util.ArgumentParser(usage='%(prog)s [options] pin level')
    parser.add_argument("--device", help="device name (COM/serial port)")
    parser.add_argument("pin", type=int, help="pin number")
    parser.add_argument("level", type=level, help="pin level (H,L)")
    parser.description = description
    parser.prog += ' pin set'
    args = parser.parse_args(argv[3:])

    try:
        usb = util.usb_open(args.device)
        usb.set_pin(args.pin, args.level)
        print("Pin %u is set %s" %
              (args.pin, ("Low (0v)", "High (5v)")[args.level]))
    except USB.CmdError as error:
        print("Command Failed: %s" % error)

def _pin_get(usb, args, **_kwargs):
    """Get the specified pin value.
    """
    value = usb.get_pin(args.pin)
    print("Pin %u is %s" %
          (args.pin, ("Low (0v)", "High (5v)")[value]))

def pin_get(argv):

    parser = util.ArgumentParser(usage='%(prog)s [options] pin')
    parser.add_argument("--device", help="device name (COM/serial port)")
    parser.add_argument("--drive", type=util.drive_letter, default='A',
                        help="drive to read (A,B,0,1,2)")
    parser.add_argument("pin", type=int, help="pin number")
    parser.description = description
    parser.prog += ' pin get'
    args = parser.parse_args(argv[3:])

    try:
        usb = util.usb_open(args.device)
        util.with_drive_selected(_pin_get, usb, args, motor=False)
    except USB.CmdError as error:
        print("Command Failed: %s" % error)

def usage(argv):
    print("usage: gw pin get|set [-h] ...")
    print("  get|set  Get or set a pin")
    sys.exit(1)

def main(argv):

    if len(argv) < 3:
        usage(argv)

    if argv[2] == 'get':
        pin_get(argv)
    elif argv[2] == 'set':
        pin_set(argv)
    else:
        usage(argv)

if __name__ == "__main__":
    main(sys.argv)

# Local variables:
# python-indent: 4
# End:
