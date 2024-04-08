from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import logging
import random
import time
import copy


logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use Queues, or a similar thread safe collection.
    """


    def __init__(self, window, timeout):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call connect from here.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        self._state = BTCPStates.CLOSED 
        # Current sequence number, acknowledgement number, and queue of unconfirmed (not ack'd) packets
        self._cur_seq_num = 1
        self._expected_ack = 0
        self._unconfirmed = queue.Queue() # Maybe to be removed, depending on how we implement go-back-n
        self._server_rcv_window = 0

        # Variables required for Go-back-N
        self._go_back_n = 3
        self._send_base = 1
        self._timer = None
        self._to_resend = queue.Queue()

        self._syn_timer = None
        self._fin_timer = None
        self._retries = RETRIES # Hard-coded retries value

        self._shutdownable = False
        self._closable = False
        self._synchronized = False

        logger.info("Socket initialized with sendbuf size 1000")


    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival.                                                            ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

        Remember, we expect you to implement this *as a state machine!*
        You have quite a bit of freedom in how you do this, but we at least
        expect you to *keep track of the state the protocol is in*,
        *perform the appropriate state transitions based on events*, and
        *alter behaviour based on that state*.

        So when you receive the segment, do the processing that is common
        for all states (verifying the checksum, parsing it into header values
        and data...).
        Then check the protocol state, do appropriate state-based processing
        (e.g. a FIN is not an acceptable segment in ACCEPTING state, whereas a
        SYN is).
        Finally, do post-processing that is common to all states.

        You could e.g. implement the state-specific processing in a helper
        function per state, and simply call the appropriate helper function
        based on which state you are in.
        In that case, it will be very helpful to split your processing into
        smaller helper functions, that you can combine as needed into a larger
        function for each state.

        If you are on Python 3.10, feel free to use the match ... case
        statement.
        If you are on an earlier Python version, an if ... elif ...  elif
        construction can be used; just make sure to check the same variable in
        each elif.
        """
        logger.debug("lossy_layer_segment_received called")
        logger.info("Received segment.")
        match self._state:
            case BTCPStates.SYN_SENT:
                self._syn_sent_segment_received(segment)
            case BTCPStates.ESTABLISHED:
                self._established_segment_received(segment)
            case BTCPStates.FIN_SENT:
                self._fin_sent_segment_received(segment)
        # raise NotImplementedError("No implementation of lossy_layer_segment_received present. Read the comments & code of client_socket.py.")

    def _syn_sent_segment_received(self, segment):
        (seqnum, acknum, syn_set, ack_set, fin_set, 
        window, length, checksum) = BTCPSocket.unpack_segment_header(segment[0:HEADER_SIZE])
        BTCPSocket.log_segment(segment, payload=False)
        # Check if segment contains SYN and ACK flag
        if syn_set == 1 and ack_set == 1:
            # Check if ACK number is as expected
            logger.warning(f"SYN ACK received, validating acknum {acknum} expected {self._expected_ack}")
            if acknum == self._expected_ack:
                # If it is, send back ACK, set sequence number, 
                # confirm _synchronized and update window
                logger.warning("SYN ACK validating, sending ACK, SYNCHRONIZED")
                ack_segment = self.build_segment_header(seqnum=acknum, acknum=seqnum+1, ack_set=True)
                self._lossy_layer.send_segment(ack_segment)
                self._cur_seq_num = 1
                self._synchronized = True
                self._server_rcv_window = window
                # Remove syn timer, no longer needed since already synchronized
                self._syn_timer = None
        pass

    def _established_segment_received(self, segment):
        # If I receive segment from server
        (seqnum, acknum, syn_set, ack_set, fin_set, 
        window, length, checksum) = BTCPSocket.unpack_segment_header(segment[0:HEADER_SIZE])
        BTCPSocket.log_segment(segment, payload=False)
        ## Check if ACK set
        if ack_set == 1:
            '''Not sure whether to do this here or after confirming in-order, 
            but since any ACK means there is now 1 more space in receive window
            I think it is okay to do it here'''
            self._server_rcv_window += 1
            ## Check if ACK number is next-up SYN number and in-order (Maybe using Queue?)
            logger.warning(f" >> Received acknum {acknum}")
            logger.warning(f" >> Expected acknum {self._expected_ack}")
            logger.warning(f" >> Correct acknum? {acknum == self._expected_ack}")
            if acknum == self._expected_ack:
                if not self._unconfirmed.empty(): self._unconfirmed.get_nowait()
                self._send_base += 1
                # Restart timers since valid ACK
                self._expire_timer()
                self._start_timer()
                logger.warning(f"Timer reset and started")
                logger.warning(f"{self._unconfirmed.qsize()} unconfirmed segments after rcv")
                self._shutdownable = True

    def _fin_sent_segment_received(self, segment):
        # If I receive segment from server
        (seqnum, acknum, syn_set, ack_set, fin_set, 
            window, length, checksum) = BTCPSocket.unpack_segment_header(segment[0:HEADER_SIZE])
        BTCPSocket.log_segment(segment, payload=False)
        ## Check if segment contains FIN and ACK flag
        if fin_set == 1 and ack_set == 1:
            ### If it does, send ACK and move to BTCPStates.CLOSED
            final_ack_segment = self.build_segment_header(seqnum=self._cur_seq_num, acknum=0, ack_set=True)
            # self._lossy_layer.send_segment(final_ack_segment)
            self._closable = True
        ## Check if segment contains ACK but no FIN (?)
        elif fin_set == 0 and ack_set == 1:
            ### If it does, register ACK
            # Handle resend (?)
            pass
        pass

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.warning("lossy_layer_tick called")
        match self._state:
            case BTCPStates.SYN_SENT:
                self._expire_syn_timer()
                pass
            case BTCPStates.FIN_SENT:
                self._expire_fin_timer()
                pass
            case BTCPStates.ESTABLISHED:
                self._established_tick()
                
        # raise NotImplementedError("Only rudimentary implementation of lossy_layer_tick present. Read the comments & code of client_socket.py, then remove the NotImplementedError.")

    def _established_tick(self):
        # Actually send all chunks available for sending.
        # Relies on an eventual exception to break from the loop when no data
        # is available.
        # You should be checking whether there's space in the window as well,
        # and storing the segments for retransmission somewhere.
        try:
            if self._server_rcv_window <= 0:
                logger.warning("No space in window, will retry sending next tick")
                return
            if not self._cur_seq_num < (self._send_base + self._go_back_n):
                self._expire_timer()
                logger.warning("Timer expired")
                logger.warning("Can't send segment, does not fit in Go-back-N window")
                logger.warning(f"Unconfirmed queue of {self._unconfirmed.qsize()}")
                return
            # while True:
            logger.warning(f"----------------------------------------")
            logger.warning(f"Can send packets with seqnum between {self._send_base} and {(self._send_base+self._go_back_n)-1}")
            logger.warning(f"----------------------------------------")
            logger.debug("Getting chunk from buffer.")
            # Segment still sending, therefore not shutdownable yet
            self._shutdownable = False
            # Get chunk from buffer and send
            chunk = self._sendbuf.get_nowait()
            datalen = len(chunk)
            logger.debug("Got chunk with length %i:",
                            datalen)
            logger.debug(chunk)
            logger.debug(f"{self._sendbuf.qsize()} chunks left in buffer")
            if datalen < PAYLOAD_SIZE:
                logger.debug("Padding chunk to full size")
                chunk = chunk + b'\x00' * (PAYLOAD_SIZE - datalen)
            logger.debug("Building segment from chunk.")
            pre_cksm_segment = (self.build_segment_header(seqnum=self._cur_seq_num, 
                                                    acknum=0, length=datalen, checksum=0x0000)
                        + chunk)
            internet_checksum = BTCPSocket.in_cksum(pre_cksm_segment)
            segment = (self.build_segment_header(seqnum=self._cur_seq_num, 
                                                    acknum=0, length=datalen, checksum=internet_checksum)
                        + chunk)
            self._expected_ack = self._cur_seq_num
            # logger.warning(f"----------------------------------------")
            logger.warning(f"Advertised window size of {self._server_rcv_window}")
            logger.warning(f"----------------------------------------")
            logger.info("Sending segment.")
            logger.warning(f"----------------------------------------")
            logger.warning(f"Trying to send Segment with seq#{self._cur_seq_num} expecting ack#{self._expected_ack}")
            logger.warning(f"and payload {chunk}")
            logger.warning(f"----------------------------------------") 
            self._cur_seq_num = self._expected_ack + 1
            logger.warning(f"Timer reset and started")
            self._unconfirmed.put_nowait(segment)
            self._lossy_layer.send_segment(segment)
            # Decrease receive window by 1 since 1 packet just sent
            self._server_rcv_window -= 1
            logger.warning(f"{self._unconfirmed.qsize()} unconfirmed segments after send")
        except queue.Empty:
            logger.info("No (more) data was available for sending right now.")

    def _start_timer(self):
        if not self._timer:
            logger.debug("Starting main timer.")
            # Time in *nano*seconds, not milli- or microseconds.
            # Using a monotonic clock ensures independence of weird stuff
            # like leap seconds and timezone changes.
            self._timer = time.monotonic_ns()
        else:
            logger.debug("Main timer already running.")

    def _start_syn_timer(self):
        if not self._syn_timer:
            logger.debug("Starting syn timer.")
            self._syn_timer = time.monotonic_ns()
        else:
            logger.debug("Syn timer already running.")

    def _start_fin_timer(self):
        if not self._fin_timer:
            logger.debug("Starting fin timer.")
            self._fin_timer = time.monotonic_ns()
        else:
            logger.debug("Fin timer already running.")


    def _expire_timer(self):
        curtime = time.monotonic_ns()
        if not self._timer:
            logger.debug("Main timer not running.")
        elif curtime - self._timer > self._timeout * 1_000_000:
            logger.debug("Main timer elapsed.")
            self._timer = None
            if self._unconfirmed.qsize() == self._go_back_n:
                # Resend segments in _unconfirmed
                self._to_resend = copy.copy(self._unconfirmed)
                logger.warning(f"unconfirmed segments {self._unconfirmed.qsize()}")
                logger.warning(f"to resend segments {self._to_resend.qsize()}")
                self._expected_ack -= self._unconfirmed.qsize() - 1
                for _ in range(self._unconfirmed.qsize()):
                    segment = self._to_resend.get_nowait()
                    if segment: logger.warning("Retrieved segment from _to_resend, attempting to send")
                    self._lossy_layer.send_segment(segment)
        else:
            logger.debug("Main timer not yet elapsed.")

    def _expire_syn_timer(self):
        curtime = time.monotonic_ns()
        if not self._syn_timer:
            logger.debug("Syn timer not running.")
        elif curtime - self._syn_timer > (self._timeout*2) * 1_000_000:
            logger.warning("Syn timer elapsed.")
            self._syn_timer = None
            # If I don't receive anything in SYN_SENT (timeout)
            ## Check if retries exceeded, if not
            if self._retries > 0:
                ### Re-send SYN
                seqnum_x = random.randint(0, 65535)
                # [PROBLEM] implement checksum here too
                syn_segment = self.build_segment_header(seqnum=seqnum_x, acknum=0, syn_set=True)
                BTCPSocket.log_segment(syn_segment, received=False)
                self._expected_ack = seqnum_x+1
                self._lossy_layer.send_segment(syn_segment)
                self._retries -= 1
                self._start_syn_timer()
            ## If yes
            else:
                ### Move to BTCPStates.CLOSED
                self._state = BTCPStates.CLOSED
        else:
            logger.debug("Syn timer not yet elapsed.")
    
    def _expire_fin_timer(self):
        curtime = time.monotonic_ns()
        if not self._fin_timer:
            logger.debug("Fin timer not running.")
        elif curtime - self._fin_timer > (self._timeout*2) * 1_000_000:
            logger.debug("Fin timer elapsed.")
            self._fin_timer = None
            # If I don't recieve anything in FIN_SENT (check if timeout)
            ## Check if retries exceeded, if not
            if self._retries > 0:
                ### Re-send FIN
                # [PROBLEM] implement checksum here too
                fin_segment = BTCPSocket.build_segment_header(seqnum=self._cur_seq_num, acknum=0, fin_set=True)
                BTCPSocket.log_segment(fin_segment, received=False)
                self._lossy_layer.send_segment(fin_segment)
                self._retries -= 1
                self._start_fin_timer()
            ## If yes
            else:
                ### Move to BTCPStates.CLOSED
                self._state = BTCPStates.CLOSED
                
        else:
            logger.debug("Fin timer not yet elapsed.")

    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### connect, shutdown (disconnect), send data, etc. Conceptually, this  ###
    ### happens in "the application thread".                                ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety.                               ###
    ###                                                                     ###
    ### Note that because this is the client socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no recv() method available to the applications. You should still    ###
    ### be able to receive segments on the lossy layer, however, because    ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.

        connect should *block* (i.e. not return) until the connection has been
        successfully established or the connection attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the syn/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        Since Python uses duck typing, and Queues can handle mixed types,
        you could even use the same queue to send a "connect signal", then
        all data chunks, then a "shutdown signal", into the network thread.
        That will take some tricky handling, however.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        logger.debug("connect called")
        seqnum_x = random.randint(0, 65535)
        # while True:
            # continue
        # [PROBLEM] implement checksum here too
        syn_segment = self.build_segment_header(seqnum=seqnum_x, acknum=0, syn_set=True)
        self._expected_ack = seqnum_x+1
        logger.warning(f"Expected ack {self._expected_ack}")
        self._lossy_layer.send_segment(syn_segment)
        self._expire_syn_timer()
        self._start_syn_timer()
        self._state = BTCPStates.SYN_SENT
        while True:
            # Block waiting for _synchronized (recv SYN|ACK)
            logger.debug("LOCKED WAITING FOR _synchronized")
            if self._synchronized:
                self._state = BTCPStates.ESTABLISHED
                # Reset retries since connection succesful
                self._retries = RETRIES
                logger.warning("Client moving to ESTABLISHED")
                break
            continue
        # self._state = BTCPStates.ESTABLISHED
        # raise NotImplementedError("No implementation of connect present. Read the comments & code of client_socket.py.")


    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.

        This method should *NOT* block waiting for acknowledgement of the data.


        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "send" operates on a "send buffer".
        Once (part of) the data has been successfully put "in the send buffer",
        the send method returns the number of bytes it was able to put in the
        buffer. The actual sending of the data, i.e. turning it into segments
        and sending the segments into the lossy layer, happens *outside* of the
        send method (e.g. in the network thread).
        If the socket does not have enough buffer space available, it is up to
        the application to retry sending the bytes it was not able to buffer
        for sending.

        Again, you should feel free to deviate from how this usually works.
        Note that our rudimentary implementation here already chunks the data
        in maximum 1008-byte bytes objects because that's the maximum a segment
        can carry. If a chunk is smaller we do *not* pad it here, that gets
        done later.
        """
        logger.warning("send called")
        # raise NotImplementedError("Only rudimentary implementation of send present. Read the comments & code of client_socket.py, then remove the NotImplementedError.")

        # Example with a finite buffer: a queue with at most 1000 chunks,
        # for a maximum of 985KiB data buffered to get turned into packets.
        # See BTCPSocket__init__() in btcp_socket.py for its construction.
        datalen = len(data)
        logger.debug("%i bytes passed to send", datalen)
        sent_bytes = 0
        logger.debug("Queueing data for transmission")
        try:
            while sent_bytes < datalen:
                logger.debug("Cumulative data queued: %i bytes", sent_bytes)
                # Slide over data using sent_bytes. Reassignments to data are
                # too expensive when data is large.
                chunk = data[sent_bytes:sent_bytes+PAYLOAD_SIZE]
                logger.debug("Putting chunk in send queue.")
                self._sendbuf.put_nowait(chunk)
                sent_bytes += len(chunk)
        except queue.Full:
            logger.info("Send queue full.")
        logger.info("Managed to queue %i out of %i bytes for transmission",
                    sent_bytes,
                    datalen)
        return sent_bytes


    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        logger.debug("shutdown called")
        while True:
            # Check if both queues are empty
            if self._unconfirmed.empty() and self._sendbuf.empty() and self._shutdownable:
                # logger.warning(f"ON SHUTDOWN: {self._unconfirmed.qsize()} segments unconfirmed")
                # logger.warning(f"ON SHUTDOWN: {self._sendbuf.qsize()} chunks left to send")
                # Send FIN
                # [PROBLEM] no checksum yet, add pls
                fin_segment = BTCPSocket.build_segment_header(seqnum=self._cur_seq_num, acknum=0, fin_set=True)
                self._lossy_layer.send_segment(fin_segment)
                self._state = BTCPStates.FIN_SENT
                self._start_fin_timer()
                # Receive FIN/ACK, send ACK, mark as _closable (handled in network thread)
                # Block waiting for _closable
                while True:
                    if self._closable:
                        break
                    continue
                break
            # If not, continue to wait
            continue
        # raise NotImplementedError("No implementation of shutdown present. Read the comments & code of client_socket.py.")


    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
        """
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close() 
