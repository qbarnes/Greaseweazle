import sys
import time
import binascii
from bitarray import bitarray
from bitarray.util import ba2hex, hex2ba, ba2int, int2ba


def fm_encode(data, clks=None) -> bitarray:
    """
    FM encode data and clock bits returning as bitarray.

    Parameters:
    - data: The data bitstream to encode as FM.  The argument may be
      an integer, list/tuple of integers, or a bitarray.
    - clks: The bitstream of clock pulses.  Only needs to be given if
      the pulses encode out-of-band data such as for access marks.

    The integer arguments may be substituted with strings if the
    strings are hexadecimal numbers.

    Returns: FM encoded bitstream as bitarray.
    """

    def fm_encode_convert_type(bits) -> bitarray:
        """Convert various types to bitarray."""
        if type(bits) is bitarray:
            pass
        elif type(bits) is int:
            bits = int2ba(bits,8)
        elif type(bits) is str:
            bits = hex2ba(bits)
        elif type(bits) is list or type(bits) is tuple:
            enc = bitarray([])
            for byte in bits:
                    enc.extend(fm_encode_convert_type(byte))
            bits = enc
        else:
            raise TypeError("Cannot convert '" + \
                            type(bits).__name__ + "' to 'bitarray'.")
        return bits

    data = fm_encode_convert_type(data)

    if clks is None:
        clks = bitarray('1' * len(data))
    else:
        clks = fm_encode_convert_type(clks)

    fm_bits = [None] * (len(data) * 2)
    fm_bits[::2]  = clks
    fm_bits[1::2] = data
    return bitarray(fm_bits)


def main(argv):
    cw2dmk_fm_encodings = (
        ('fc', 'd7', '8aa2a2a88'),  # 0xfc / 0xd7: Index address mark
        ('fe', 'c7', '8aa222aa8'),  # 0xfe / 0xc7: ID address mark
        ('f8', 'c7', '8aa222888'),  # 0xf8 / 0xc7: Standard deleted DAM
        ('f9', 'c7', '8aa22288a'),  # 0xf9 / 0xc7: WD1771 user-defined DAM or
                                    #              RX02 deleted DAM
        ('fa', 'c7', '8aa2228a8'),  # 0xfa / 0xc7: WD1771 user-defined DAM
        ('fb', 'c7', '8aa2228aa'),  # 0xfb / 0xc7: Standard DAM
        ('fd', 'c7', '8aa222a8a')   # 0xfd / 0xc7: RX02 DAM
    )

    test_vector = (
        # Test with two bitarrays.
        (hex2ba('fc'), hex2ba('d7'), bitarray('1111011101111010')),

        # Test with two hex ints.
        (0xfc, 0xd7, bitarray('1111011101111010')),

        # Test with two lists of hex ints.
        ([0x00, 0xfc], [0xff, 0xd7],
            bitarray('10101010101010101111011101111010')),

        # Test with two tuples of hex ints.
        ((0x00, 0xfa), (0xff, 0xc7),
            bitarray('10101010101010101111010101101110')),

        # Test with one tuple of ints and no specified clock.
        ((0xff, 0x07), None,
            bitarray('11111111111111111010101010111111'))
    )

    ret = 0

    try:
        for d, c, ans in cw2dmk_fm_encodings:
            res1 = fm_encode(hex2ba('0' + d), hex2ba('f' + c))[6:]
            # Insert spaces for 4x Catweasel timings.
            res = ba2hex(fm_encode(bitarray('0' * len(res1)), res1))
            if res == ans:
                print(f"Good:   0x{d} 0x{c} -> {res}")
            else:
                print(f"ERROR!: 0x{d} 0x{c} -> {res} != {ans}")
                ret = 1

        print()
        for a1, a2, ans in test_vector:
            res = fm_encode(a1, a2)
            if res == ans:
                print(f"Good: fm_encode({a1}, {a2}) = {res}")
            else:
                print(f"ERROR!: fm_encode({a1}, {a2}) = {res} != {ans}")
                ret = 1

        # Test with invalidly typed argument.
        print()
        try:
            idmark = fm_encode('a string')
            print("fm_encode('a string') =", idmark)
        except binascii.Error as err:
            if str(err) == 'Non-hexadecimal digit found':
                print("Expected error triggered: \"" \
                      "binascii.Error: {}\"".format(err))
            else:
                raise
    except Exception as err:
        print("Unexpected error caught: {}.".format(err))
        return 2

    if ret == 0:
        print("\nAll tests successful.")
    else:
        print("\nTest failures found!")

    return ret


if sys.version_info.major != 3:
    sys.stderr.write("Must run with Python 3.\n")
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main(sys.argv))


# Local variables:
# python-indent: 4
# End:
