# greaseweazle/tools/seek.py
#
# Greaseweazle control script: Seek to specified cylinder.
#
# Written & released by Keir Fraser <keir.xen@gmail.com>
#
# This is free and unencumbered software released into the public domain.
# See the file COPYING for more details, or visit <http://unlicense.org>.

description = "Seek to the specified cylinder."

import struct, sys

from greaseweazle.tools import util
from greaseweazle import error
from greaseweazle import usb as USB
from greaseweazle.flux import Flux


def seek(usb, args, **_kwargs):
    """Seeks to the cylinder specified in args.
    """
    usb.seek(args.cylinder, 0)


def main(argv):

    parser = util.ArgumentParser(usage='%(prog)s [options] cylinder')
    parser.add_argument("--device", help="device name (COM/serial port)")
    parser.add_argument("--drive", type=util.drive_letter, default='A',
                        help="drive to read (A,B,0,1,2)")
    parser.add_argument("--force", action="store_true",
                        help="allow extreme cylinders with no prompt")
    parser.add_argument("--motor-on", action="store_true",
                        help="seek with drive motor activated")
    parser.add_argument("cylinder", type=int, help="cylinder to seek")
    parser.description = description
    parser.prog += ' ' + argv[1]
    args = parser.parse_args(argv[2:])

    try:
        struct.pack('b', args.cylinder)
    except struct.error:
        raise error.Fatal("Cylinder %d out of range" % args.cylinder)
    if not 0 <= args.cylinder <= 83 and not args.force:
        answer = input("Seek to extreme cylinder %d, Yes/No? " % args.cylinder)
        if answer != "Yes":
            return
    
    try:
        usb = util.usb_open(args.device)
        util.with_drive_selected(seek, usb, args, motor=args.motor_on)
    except USB.CmdError as err:
        print("Command Failed: %s" % err)


if __name__ == "__main__":
    main(sys.argv)

# Local variables:
# python-indent: 4
# End:
