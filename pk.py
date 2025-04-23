import random
import socket
import struct
import threading
import time
import os
import crcmod

HEAD_FORMAT = "!BIH"  # Flag - 1 byte, Seq - 4 bytes , CheckSum - 2 bytes
HEAD_FORMAT_CHECKSUM = "!BI"  # Flag, Seq
HEAD_SIZE = struct.calcsize(HEAD_FORMAT)

# Flags for header
SYN = 0
SYN_ACK = 1
MESS = 2
ACK = 3
END = 4
KEEP_ALIVE = 5
NACK = 6
FILE_START = 7  # Indicates the start of a file transfer
CHUNK = 8  # Indicates message/file chunk
FILE_END = 9
MESS_END = 10

SAVE_ADDRESS = r"C:\" # Adress for saving incoming files
HAND_ACK_TIMEOUT = 5  # Seconds to wait for handshake
ACK_TIMEOUT = 3  # Seconds to wait fo mess ack
KEEP_ALIVE_INTERVAL = 5  # Seconds for sending keep-alive messages
KEEP_ALIVE_TIMEOUT = 15
SEND_TRY = 5  # How many times code tries to send message if failed
control = 0
ERROR = False
CHUNK_SIZE = 1024 - HEAD_SIZE
counter = 0


def counter_res():
    global counter
    counter = 0


def counter_add():
    global counter
    counter += 1


def counter_reduce():
    global counter
    counter -= 1


def error_set():
    global ERROR
    ERROR = True


def error_reset():
    global ERROR
    ERROR = False


def control_add():
    global control
    control = 1


def calculate_checksum(data):
    crc16 = crcmod.predefined.mkCrcFun('crc-ccitt-false')
    if not ERROR:
        return crc16(data) & 0xFFFF
    return crc16(data) & 0xAFFA  # modified mask for errors


def change_receive():
    global SAVE_ADDRESS
    SAVE_ADDRESS = input("Save address: ")


def chunk_set():
    global CHUNK_SIZE
    new = 0
    while not (1 <= new <= 1024 - HEAD_SIZE):
        print(f"Chunk size for data without header can be set from {1024 - HEAD_SIZE} to 1.\n"
              f"Currently set to {CHUNK_SIZE}.")
        new = int(input("New chunk size: "))
    CHUNK_SIZE = new
    print(f"Chunk size set to {CHUNK_SIZE}.")


def info():
    print("\nCommands: \n"
          "<message> --> send message to peer\n"
          "-<command> <message> --> ignores command, send command as message\n"
          "-e <message> --> try to send corrupted message to peer\n"
          "-file --> ask for file path to send to peer\n"
          "-e -file --> ask for file path to send to peer, with chance of corrupting sent packs\n"
          "-save -->  ask for path, where received files should be saved\n"
          "-chunk --> ask for chunks size, in which data shall be send\n"
          "-help --> show list of available commands\n")


class Peer:
    def __init__(self, my_ip, my_port, peer_ip, peer_port) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((my_ip, my_port))
        self.peer_address = (peer_ip, peer_port)
        self.sequence_number = 0
        self.ack_received = threading.Event()
        self.running = True
        self.last_keep_alive = time.time()
        self.last_keep_alive_send = time.time()
        self.transfer_start = time.time()

    def handshake(self):
        initiate = input("Initiate handshake? (yes/no): ").strip().lower() == "yes"

        if initiate:
            # Send SYN and wait for SYN_ACK
            print("Sending SYN to initiate handshake.")
            self.sock.sendto(self.header_pack(SYN, self.sequence_number), self.peer_address)
            if self.wait_for_response(SYN_ACK):
                # Received SYN_ACK, complete handshake by sending ACK
                print("Received SYN_ACK. Sending ACK to complete handshake.")
                self.sock.sendto(self.header_pack(ACK, self.sequence_number), self.peer_address)
                print("Handshake completed.")
                return 1
        else:
            # Wait for SYN and respond with SYN_ACK
            print("Waiting for peer to initiate handshake.")
            if self.wait_for_response(SYN):
                print("Received SYN. Sending SYN_ACK.")
                self.sock.sendto(self.header_pack(SYN_ACK, self.sequence_number), self.peer_address)
                # Wait for ACK to complete handshake
                if self.wait_for_response(ACK):
                    print("Received ACK. Handshake completed.")
                    return 1

    def wait_for_response(self, expected_flag):
        self.sock.settimeout(HAND_ACK_TIMEOUT)
        try:
            while self.running:

                data, peer_inf = self.sock.recvfrom(1024)
                flag, seq = self.header_unpack(data[:HEAD_SIZE], data[HEAD_SIZE:])

                if flag == expected_flag:
                    return True
        except socket.timeout:
            print("Timeout waiting for response. Handshake not completed.")
            return False
        finally:
            self.sock.settimeout(None)  # Reset to blocking mode

    def keep_alive(self):
        time.sleep(0.2)
        while self.running:
            time.sleep(1)
            if time.time() - self.last_keep_alive_send > KEEP_ALIVE_INTERVAL:
                # print("Sending keep-alive.")
                self.sock.sendto(self.header_pack(KEEP_ALIVE, self.sequence_number), self.peer_address)
                self.last_keep_alive_send = time.time()

            # Check if last keep-alive was received within timeout
            if time.time() - self.last_keep_alive > KEEP_ALIVE_TIMEOUT:
                print("No keep-alive received from peer. Assuming peer is disconnected.")
                self.running = False
                break

    def send_file(self, filename):
        try:
            # Load the file and ensure it exists
            if ERROR:
                error = True
            else:
                error = False
            error_reset()
            with open(filename, "rb") as file:
                # Read the entire file into a buffer
                file_buffer = file.read()

            # Send FILE_START with just the basename of the file
            self.transfer_start = time.time()
            self.sequence_number += 1
            basename = os.path.basename(filename)

            self.sock.sendto(self.header_pack(FILE_START, self.sequence_number, basename.encode()), self.peer_address)

            # Wait for ACK from peer

            for attempt in range(SEND_TRY):
                self.ack_received.clear()
                if self.wait_for_ack():  # ACK received
                    break
                print(f"Retrying (attempt {attempt + 1}/{SEND_TRY})...")
                self.sock.sendto(self.header_pack(FILE_START, self.sequence_number, basename.encode()),
                                 self.peer_address)

            if attempt == SEND_TRY - 1:
                print(f"Failed to initiate file transfer after {SEND_TRY} attempts. Aborting file transfer.")
                return False

            # Send file in chunks
            chunk_size = CHUNK_SIZE  # Max payload
            total_chunks = (len(file_buffer) + chunk_size - 1) // chunk_size  # total chunks
            for chunk_id in range(total_chunks):
                start = chunk_id * chunk_size
                end = start + chunk_size
                chunk = file_buffer[start:end]

                self.sequence_number += 1
                if error:
                    if random.randint(0, 1000) == 27:
                        error_set()
                self.sock.sendto(self.header_pack(CHUNK, self.sequence_number, chunk), self.peer_address)
                error_reset()
                # Retry sending the chunk

                for attempt in range(SEND_TRY):
                    self.ack_received.clear()
                    if self.wait_for_ack():  # ACK received
                        break
                    print(f"Retrying chunk {chunk_id} (attempt {attempt + 1}/{SEND_TRY})...")
                    self.sock.sendto(self.header_pack(CHUNK, self.sequence_number, chunk), self.peer_address)

                if attempt == SEND_TRY - 1:
                    print(f"Failed to send chunk {chunk_id} after {SEND_TRY} attempts. Aborting file transfer.")
                    return False

                # print(f"Chunk {chunk_id + 1}/{total_chunks} sent and acknowledged.")

            # Send FILE_END to signal transfer completion
            self.sequence_number += 1
            end_packet = self.header_pack(FILE_END, self.sequence_number)
            self.sock.sendto(end_packet, self.peer_address)

            if self.wait_for_ack():
                print(
                    f"File {basename} with size of {os.path.getsize(filename)} bytes, transferred successfully in {total_chunks} chunks,\n"
                    f"with size of {chunk_size} (last chunk was in size of {len(chunk)}).")
                print(f"File transfer completed in {(time.time() - self.transfer_start):.2f} seconds.")
                return True
            else:
                print("File transfer end not acknowledged. Peer may not have received the file.")
                return False
        # Errors handling
        except FileNotFoundError:
            print(f"File '{filename}' not found.")
            return False

        except MemoryError:
            print(f"File '{filename}' is too large to load into memory. Consider chunked processing instead.")
            return False

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return False

    def send_message(self):
        while self.running:
            error_reset()
            message = input("Send this to peer --> \n")
            # Commands handling
            if message[:2].lower().strip() == "-e":
                message = message[3:]
                error_set()

            if message.lower().strip() == "end":
                self.sock.sendto(self.header_pack(END, self.sequence_number, message.encode()), self.peer_address)
                print("You ended the connection.")
                self.running = False
                break

            if message[:5].lower().strip() == "-file":
                file_name = input("Type the name of the file to send: \n")
                self.send_file(file_name)

            elif message[:5].lower().strip() == "-save":
                if (input(f"Change save address from {SAVE_ADDRESS}? (yes/*)")) == "yes":
                    change_receive()

            elif message[:5].lower().strip() == "-help":
                info()

            elif message[:6].lower().strip() == "-chunk":
                chunk_set()

            elif len(message) > CHUNK_SIZE:  # Split long messages into chunks
                print(f"Message exceeds {CHUNK_SIZE} bytes, sending in chunks.")
                if message[:2].strip() == "--":
                    message = message[1:]
                self.send_chunked_message(message)

            else:
                if message[:2].strip() == "--":
                    message = message[1:]
                self.sequence_number += 1
                self.sock.sendto(self.header_pack(MESS, self.sequence_number, message.encode()), self.peer_address)

                ack_reset = 0
                error_reset()
                # Wait for ACK
                while not self.wait_for_ack() and self.running:
                    if ack_reset >= SEND_TRY:
                        print("Failed to sned message")
                        break
                    print("ACK not received. Retrying...")
                    ack_reset += 1
                    self.sock.sendto(self.header_pack(MESS, self.sequence_number, message.encode()), self.peer_address)

    def send_chunked_message(self, message):
        chunk_size = CHUNK_SIZE
        if ERROR:
            error = True
        else:
            error = False
        error_reset()
        total_chunks = (len(message) + chunk_size - 1) // chunk_size
        self.transfer_start = time.time()
        for chunk_id in range(total_chunks):
            start = chunk_id * chunk_size
            end = start + chunk_size
            chunk = message[start:end]

            self.sequence_number += 1

            if error:
                if random.randint(0, 10) == 5:
                    error_set()
            self.sock.sendto(self.header_pack(CHUNK, self.sequence_number, chunk.encode()), self.peer_address)
            error_reset()
            ack_reset = 0
            while not self.wait_for_ack() and self.running:
                if ack_reset >= SEND_TRY:
                    print(f"Failed to send chunk {chunk_id + 1}/{total_chunks}. Aborting.")
                    return False
                print(f"ACK not received for chunk {chunk_id + 1}/{total_chunks}. Retrying...")
                ack_reset += 1
                self.sock.sendto(self.header_pack(CHUNK, self.sequence_number, chunk.encode()), self.peer_address)

        self.sequence_number += 1
        self.sock.sendto(self.header_pack(MESS_END, self.sequence_number), self.peer_address)
        if self.wait_for_ack():
            print(f"Message sent successfully in {total_chunks} chunks,\n"
                  f"with size of {chunk_size} (last chunk was in size of {len(chunk)}).")
            print(f"Message was sent in {(time.time() - self.transfer_start):.2f} seconds.")
            return True
        else:
            print("Message transfer end not acknowledged. Peer may not have received message.")
            return False

    def wait_for_ack(self):
        self.ack_received.clear()
        return self.ack_received.wait(ACK_TIMEOUT)

    def header_pack(self, flag, seq, payload=b''):
        data = struct.pack(HEAD_FORMAT_CHECKSUM, flag, seq) + payload
        checksum = calculate_checksum(data)
        self.last_keep_alive_send = time.time()
        return struct.pack(HEAD_FORMAT, flag, seq, checksum) + payload

    def header_unpack(self, header, payload):
        flag, seq, received_checksum = struct.unpack(HEAD_FORMAT, header)
        calculated_checksum = calculate_checksum(header[:struct.calcsize(HEAD_FORMAT_CHECKSUM)] + payload)

        if calculated_checksum != received_checksum:
            return None, seq

        return flag, seq

    def receive_message(self):
        buff = ""
        first = True
        prev_seq = 0
        while self.running:
            try:
                data, peer_inf = self.sock.recvfrom(1024)
                header = data[:HEAD_SIZE]
                message = data[HEAD_SIZE:]

                flag, seq = self.header_unpack(header, message)

                if flag is None:
                    # print("Corrupted packet detected. Dropping packet.")
                    self.sock.sendto(self.header_pack(NACK, seq), peer_inf)
                    continue

                if seq == prev_seq and flag != ACK and flag != KEEP_ALIVE:
                    flag = None
                    self.sock.sendto(self.header_pack(ACK, seq), peer_inf)

                prev_seq = seq
                message = message.decode()

                if flag == MESS:
                    print(f"Received from peer {peer_inf}: {message}")
                    print("Send this to peer -->")
                    # Send an ACK back to the sender
                    self.sock.sendto(self.header_pack(ACK, seq), peer_inf)
                    first = True

                elif flag == ACK:
                    # print(f"ACK received for message {seq}")
                    time.sleep(0.0001)
                    self.ack_received.set()

                elif flag == NACK:
                    # print("Corrupted packet detected, sending again.")
                    self.ack_received.clear()

                elif flag == KEEP_ALIVE:
                    time.sleep(00.1)
                    # print("Received keep-alive from peer.")

                elif flag == FILE_START:
                    print(f"Receiving file: {message}")
                    full_path = os.path.join(SAVE_ADDRESS, message)
                    self.sock.sendto(self.header_pack(ACK, seq), peer_inf)
                    counter_res()
                    first = True

                elif flag == CHUNK:
                    if first:
                        self.transfer_start = time.time()
                    first = False
                    buff += message
                    self.sock.sendto(self.header_pack(ACK, seq), peer_inf)  # Send ACK for this chunk
                    counter_add()
                    print("Receiving chunk num", counter)

                elif flag == FILE_END:
                    file = open(full_path, "w")
                    file.write(buff)
                    file.close()
                    buff = ""
                    first = True
                    self.sock.sendto(self.header_pack(ACK, seq), peer_inf)  # Send final ACK

                    print("File transfer completed.\n"
                          f"File saved in {SAVE_ADDRESS}, file size is {os.path.getsize(full_path)} bytes.\n"
                          f"Received {counter} fragments in {(time.time() - self.transfer_start):.2f} seconds.\n")
                    counter_res()

                elif flag == MESS_END:
                    print("Message received successfully.\n"
                          f"Received {counter} fragments in {(time.time() - self.transfer_start):.2f} seconds.\n")
                    print(f"Received from peer {peer_inf}:", buff)
                    buff = ""
                    first = True
                    self.sock.sendto(self.header_pack(ACK, seq), peer_inf)
                    counter_res()


                elif flag == END or message.lower() == "end":
                    print(f"Peer ended the connection: {message}")
                    self.running = False
                    break

                self.last_keep_alive = time.time()  # Reset the keep-alive timer
            # Error handling
            except ConnectionResetError as e:
                print(f"Connection forcibly closed: {e}")
                continue

            except OSError as e:
                print(f"Socket error occurred: {e}")
                continue

    def quit(self):
        self.sock.close()
        print("Peer connection closed.")


if __name__ == "__main__":

    MY_IP = str(input("Own IP: "))
    MY_PORT = int(input("Own port: "))
    PEER_IP = str(input("Peer IP: "))
    PEER_PORT = int(input("Peer port: "))
    
    # FOR TESTING
    # First peer
    '''
    MY_IP = "127.0.0.1"
    MY_PORT = 50601
    PEER_IP = "127.0.0.1"
    PEER_PORT = 50605
   
    # Second peer
    
    MY_IP = "127.0.0.1"
    MY_PORT = 50605
    PEER_IP = "127.0.0.1"
    PEER_PORT = 50601
    
    MY_IP = "169.254.5.37"
    MY_PORT = 50602
    PEER_IP = "169.254.190.28"
    PEER_PORT = 55000
    '''

    while 1:
        peer = Peer(MY_IP, MY_PORT, PEER_IP, PEER_PORT)

        if peer.handshake() == 1:
            info()
            peer.last_keep_alive = time.time()

            send_thread = threading.Thread(target=peer.send_message)
            receive_thread = threading.Thread(target=peer.receive_message)
            keep_alive_thread = threading.Thread(target=peer.keep_alive)

            send_thread.start()
            receive_thread.start()
            keep_alive_thread.start()

            send_thread.join()
            receive_thread.join()
            keep_alive_thread.join()

        peer.quit()
        repeat = input("Try again? (*/no): ").strip().lower()

        if repeat == "no":
            break
