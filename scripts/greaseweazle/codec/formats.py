# greaseweazle/codec/formats.py
#
# Written & released by Keir Fraser <keir.xen@gmail.com>
#
# This is free and unencumbered software released into the public domain.
# See the file COPYING for more details, or visit <http://unlicense.org>.

from greaseweazle.tools import util

class Format:
    img_compatible = False
    default_trackset = 'c=0-79:h=0-1'
    max_trackset = 'c=0-81:h=0-1'
    def __init__(self):
        self.default_tracks = util.TrackSet(self.default_trackset)
        self.max_tracks = util.TrackSet(self.max_trackset)

class Format_Amiga_AmigaDOS(Format):
    def __init__(self):
        import greaseweazle.codec.amiga.amigados as m
        self.fmt = m.AmigaDOS
        self.default_revs = m.default_revs
        self.decode_track = m.decode_track
        super().__init__()
    
class Format_IBM_180(Format):
    img_compatible = True
    default_trackset = 'c=0-39:h=0'
    max_trackset = 'c=0-41:h=0'
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.IBM_MFM_720
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_IBM_360(Format):
    img_compatible = True
    default_trackset = 'c=0-39:h=0-1'
    max_trackset = 'c=0-41:h=0-1'
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.IBM_MFM_720
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_IBM_720(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.IBM_MFM_720
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_IBM_800(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.IBM_MFM_800
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_IBM_1440(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.IBM_MFM_1440
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()

class Format_IBM_1200(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.IBM_MFM_1200
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()

class Format_AtariST_360(Format):
    img_compatible = True
    default_trackset = 'c=0-79:h=0'
    max_trackset = 'c=0-81:h=0'
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.AtariST_SS_9SPT
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_AtariST_400(Format):
    img_compatible = True
    default_trackset = 'c=0-79:h=0'
    max_trackset = 'c=0-81:h=0'
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.AtariST_10SPT
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_AtariST_440(Format):
    img_compatible = True
    default_trackset = 'c=0-79:h=0'
    max_trackset = 'c=0-81:h=0'
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.AtariST_11SPT
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_AtariST_720(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.AtariST_DS_9SPT
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_AtariST_800(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.AtariST_10SPT
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
class Format_AtariST_880(Format):
    img_compatible = True
    def __init__(self):
        import greaseweazle.codec.ibm.mfm as m
        self.fmt = m.AtariST_11SPT
        self.default_revs = m.default_revs
        self.decode_track = self.fmt.decode_track
        super().__init__()
    
    
formats = {
    'amiga.amigados': Format_Amiga_AmigaDOS,
    'ibm.180': Format_IBM_180,
    'ibm.360': Format_IBM_360,
    'ibm.720': Format_IBM_720,
    'ibm.1200': Format_IBM_1200,
    'ibm.1440': Format_IBM_1440,
    'atarist.360': Format_AtariST_360,
    'atarist.400': Format_AtariST_400,
    'atarist.440': Format_AtariST_440,
    'atarist.720': Format_AtariST_720,
    'atarist.800': Format_AtariST_800,
    'atarist.880': Format_AtariST_880,
    'commodore.1581': Format_IBM_800,
}

def print_formats(f = None):
    s = ''
    for k, v in sorted(formats.items()):
        if not f or f(k, v):
            if s:
                s += '\n'
            s += '  ' + k
    return s
