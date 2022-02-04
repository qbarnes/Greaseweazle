# greaseweazle/tools/write.py
#
# Greaseweazle control script: Write Image to Disk.
#
# Written & released by Keir Fraser <keir.xen@gmail.com>
#
# This is free and unencumbered software released into the public domain.
# See the file COPYING for more details, or visit <http://unlicense.org>.

description = "Write a disk from the specified image file."

import sys

from greaseweazle.tools import util
from greaseweazle import error, track
from greaseweazle import usb as USB
from greaseweazle.codec import formats

# Read and parse the image file.
def open_image(args, image_class):
    try:
        image = image_class.from_file(args.file)
        args.raw_image_class = True
    except TypeError:
        image = image_class.from_file(args.file, args.fmt_cls)
        args.raw_image_class = False
    return image

# write_from_image:
# Writes the specified image file to floppy disk.
def write_from_image(usb, args, image):

    # Measure drive RPM.
    # We will adjust the flux intervals per track to allow for this.
    drive = usb.read_track(2)
    del drive.list

    verified_count, not_verified_count = 0, 0

    for t in args.tracks:

        cyl, head = t.cyl, t.head

        track = image.get_track(cyl, head)
        if track is None and not args.erase_empty:
            continue

        usb.seek(t.physical_cyl, t.physical_head)

        if track is None:
            print("T%u.%u: Erasing Track" % (cyl, head))
            usb.erase_track(drive.ticks_per_rev * 1.1)
            continue

        if args.raw_image_class and args.fmt_cls is not None:
            track = args.fmt_cls.decode_track(cyl, head, track)
            error.check(track.nr_missing() == 0,
                        'T%u.%u: %u missing sectors in input image'
                        % (cyl, head, track.nr_missing()))
            track = track.raw_track()

        if args.precomp is not None:
            track.precomp = args.precomp.track_precomp(cyl)
        flux = track.flux_for_writeout()

        # @factor adjusts flux times for speed variations between the
        # read-in and write-out drives.
        factor = drive.ticks_per_rev / flux.index_list[0]

        # Convert the flux samples to Greaseweazle sample frequency.
        rem = 0.0
        flux_list = []
        for x in flux.list:
            y = x * factor + rem
            val = round(y)
            rem = y - val
            flux_list.append(val)

        # Encode the flux times for Greaseweazle, and write them out.
        verified = False
        for retry in range(args.retries+1):
            s = "T%u.%u: Writing Track" % (cyl, head)
            if retry != 0:
                s += " (Verify Failure: Retry #%u)" % retry
            else:
                s += " (%s)" % flux.summary_string()
            print(s)
            usb.write_track(flux_list = flux_list,
                            cue_at_index = flux.index_cued,
                            terminate_at_index = flux.terminate_at_index)
            try:
                no_verify = args.no_verify or track.verify is None
            except AttributeError: # track.verify undefined
                no_verify = True
            if no_verify:
                not_verified_count += 1
                verified = True
                break
            v_revs, v_ticks = track.verify_revs, 0
            if isinstance(v_revs, float):
                v_ticks = int(drive.ticks_per_rev * v_revs)
                v_revs = 2
            v_flux = usb.read_track(revs = v_revs, ticks = v_ticks)
            v_flux.scale(flux.time_per_rev / drive.time_per_rev)
            verified = track.verify.verify_track(v_flux)
            if verified:
                verified_count += 1
                break
        error.check(verified, "Failed to verify Track %u.%u" % (cyl, head))

    if not_verified_count == 0:
        print("All tracks verified")
    else:
        if verified_count == 0:
            s = "No tracks verified "
        else:
            s = ("%d tracks verified; %d tracks *not* verified "
                 % (verified_count, not_verified_count))
        s += ("(Reason: Verify %s)"
              % ("unavailable", "disabled")[args.no_verify])
        print(s)


class PrecompSpec:
    def __str__(self):
        s = "Precomp %s" % track.Precomp.TYPESTRING[self.type]
        for e in self.list:
            s += ", %d-:%dns" % e
        return s

    def track_precomp(self, cyl):
        for c,s in reversed(self.list):
            if cyl >= c:
                return track.Precomp(self.type, s)
        return None

    def importspec(self, spec):
        self.list = []
        self.type = track.Precomp.MFM
        for x in spec.split(':'):
            k,v = x.split('=')
            if k == 'type':
                self.type = track.Precomp.TYPESTRING.index(v.upper())
            else:
                self.list.append((int(k), int(v)))
        self.list.sort()

    def __init__(self, spec):
        try:
            self.importspec(spec)
        except:
            raise ValueError
        

def main(argv):

    epilog = "FORMAT options:\n" + formats.print_formats()
    parser = util.ArgumentParser(usage='%(prog)s [options] file',
                                 epilog=epilog)
    parser.add_argument("--device", help="device name (COM/serial port)")
    parser.add_argument("--drive", type=util.drive_letter, default='A',
                        help="drive to write (A,B,0,1,2)")
    parser.add_argument("--format", help="disk format")
    parser.add_argument("--tracks", type=util.TrackSet, metavar="TSPEC",
                        help="which tracks to write")
    parser.add_argument("--erase-empty", action="store_true",
                        help="erase empty tracks (default: skip)")
    parser.add_argument("--no-verify", action="store_true",
                        help="disable verify")
    parser.add_argument("--retries", type=int, default=3, metavar="N",
                        help="number of retries on verify failure")
    parser.add_argument("--precomp", type=PrecompSpec,
                        help="write precompensation")
    parser.add_argument("file", help="input filename")
    parser.description = description
    parser.prog += ' ' + argv[1]
    args = parser.parse_args(argv[2:])

    try:
        image_class = util.get_image_class(args.file)
        if not args.format and hasattr(image_class, 'default_format'):
            args.format = image_class.default_format
        def_tracks, args.fmt_cls = None, None
        if args.format:
            try:
                args.fmt_cls = formats.formats[args.format]()
            except KeyError as ex:
                raise error.Fatal("""\
Unknown format '%s'
Known formats:\n%s"""
                                  % (args.format, formats.print_formats()))
            def_tracks = args.fmt_cls.default_tracks
        if def_tracks is None:
            def_tracks = util.TrackSet('c=0-81:h=0-1')
        if args.tracks is not None:
            def_tracks.update_from_trackspec(args.tracks.trackspec)
        args.tracks = def_tracks
        usb = util.usb_open(args.device)
        image = open_image(args, image_class)
        print("Writing " + str(args.tracks))
        if args.precomp is not None:
            print(args.precomp)
        if args.format:
            print("Format " + args.format)
        util.with_drive_selected(write_from_image, usb, args, image)
    except USB.CmdError as err:
        print("Command Failed: %s" % err)


if __name__ == "__main__":
    main(sys.argv)

# Local variables:
# python-indent: 4
# End:
