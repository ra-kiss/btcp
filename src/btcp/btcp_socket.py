import struct
import logging
from enum import IntEnum
from btcp.constants import *


logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    """Enum class that helps you implement the bTCP state machine.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.

    These states are NOT exhaustive! We left out at least one state that you
    will need to implement the bTCP state machine correctly. The intention of
    this enum is to give you some idea for states and how simple the
    transitions between them are.

    Feel free to implement your state machine in a different way, without
    using such an enum.
    """
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    ESTABLISHED = 4 # There's an obvious state that goes here. Give it a name. (done, ESTABLISHED)
    FIN_SENT    = 5
    CLOSING     = 6
    # __          = 7 # If you need more states, extend the Enum like this.
    # raise NotImplementedError("Check btcp_socket.py's BTCPStates enum. We left out some states you will need.")


class BTCPSignals(IntEnum):
    """Enum class that you can use to signal from the Application thread
    to the Network thread.

    For example, rather than explicitly change state in the Application thread,
    you could put one of these in a variable that the network thread reads the
    next time it ticks, and handles the state change in the network thread.
    """
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """
    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self._window = window
        self._timeout = timeout
        self._state = BTCPStates.CLOSED
        logger.debug("Socket initialized with window %i and timeout %i",
                     self._window, self._timeout)


    @staticmethod
    def in_cksum(segment):
        """Compute the internet checksum of the segment given as argument.
        Consult lecture 3 for details.

        Our bTCP implementation always has an even number of bytes in a segment.

        Remember that, when computing the checksum value before *sending* the
        segment, the checksum field in the header should be set to 0x0000, and
        then the resulting checksum should be put in its place.
        """
        # Step 1: Take the pseudo-header and data
        # Step 2: If odd number of bytes, pad with 1 byte of zeroes at the end. 
        # Should not be necessary here, just added for completion to follow the steps in the lecture
        if len(segment) % 2 != 0:
            segment += b'\x00'

        # Step 3: Divide into 16-bit words.
        words = [segment[i:i+2] for i in range(0, len(segment), 2)]

        # Step 4: Add all words together, using end-around carry to deal with overflow.
        checksum = 0
        for word in words:
            # Convert the 16-bit word to integer value
            value = (word[0] << 8) + word[1]
            checksum += value
            # Deal with overflow
            checksum = (checksum & 0xffff) + (checksum >> 16)

        # Step 5: Take the one’s complement of the result (invert the bits).
        checksum = ~checksum & 0xffff

        return checksum


    @staticmethod
    def verify_checksum(segment):
        """Verify that the checksum indicates is an uncorrupted segment.

        Mind that you change *what* signals that to the correct value(s).
        """
        logger.debug("verify_cksum() called")
        # Get header from segment
        header = segment[:HEADER_SIZE]
        # Get checksum from header
        _, _, _, _, _, _, _, checksum = BTCPSocket.unpack_segment_header(header)
        # raise NotImplementedError("No implementation of in_cksum present. Read the comments & code of btcp_socket.py.")
        # Compare calculated checksum to checksum extracted from header
        return BTCPSocket.in_cksum(segment) == checksum


    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        """Pack the method arguments into a valid bTCP header using struct.pack

        This method is given because historically students had a lot of trouble
        figuring out how to pack and unpack values into / out of the header.
        We have *not* provided an implementation of the corresponding unpack
        method (see below), so inspect the code, look at the documentation for
        struct.pack, and figure out what this does, so you can implement the
        unpack method yourself.

        Of course, you are free to implement it differently, as long as you
        do so correctly *and respect the network byte order*.

        You are allowed to change the SYN, ACK, and FIN flag locations in the
        flags byte, but make sure to do so correctly everywhere you pack and
        unpack them.

        The method is written to have sane defaults for the arguments, so
        you don't have to always set all flags explicitly true/false, or give
        a checksum of 0 when creating the header for checksum computation.
        """
        logger.debug("build_segment_header() called")
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        logger.debug("build_segment_header() done")
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)


    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header.

        Remember that Python supports multiple return values through automatic
        tupling, so it's easy to simply return all of them in one go rather
        than make a separate method for every individual field.
        """
        logger.debug("unpack_segment_header() called")
        # Unpack with struct.unpack
        seqnum, acknum, flag_byte, window, length, checksum = struct.unpack("!HHBBHH", header)
        # Extract the flag bits from the flag_byte
        syn_set = (flag_byte >> 2) & 1
        ack_set = (flag_byte >> 1) & 1
        fin_set = flag_byte & 1
        # Debug statement and return all values
        logger.debug("unpack_segment_header() done")
        return seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum
        # raise NotImplementedError("No implementation of unpack_segment_header present. Read the comments & code of btcp_socket.py. You should really implement the packing / unpacking of the header into field values before doing anything else!")

    @staticmethod
    def log_segment(segment, payload=True, received=True):
        (seqnum, acknum, syn_set, ack_set, fin_set, 
            window, length, checksum) = BTCPSocket.unpack_segment_header(segment[0:HEADER_SIZE])
        logger.warning(f"----------------------------------------")
        logger.warning(f"Segment {'Received' if received else 'Sent'} with seq#{seqnum} ack#{acknum}")
        logger.warning(f"syn?{syn_set} ack?{ack_set} fin?{fin_set}")
        logger.warning(f"window size {window} and length {length}")
        if payload: logger.warning(f"and payload {segment[HEADER_SIZE:-1]}")
        logger.warning(f"----------------------------------------")
