import pprint
from threading import Thread, Event
import io
import time
import select
import socket
import errno

def pp(o):
    pp = pprint.PrettyPrinter()
    pp.pprint(o)


# class PollThread(Thread):
#     def __init__(self, s, q):
#         super(PollThread, self).__init__()
#         self.s = s
#         self.q = q
#         self.stop = Event()
#
#     def __enter__(self):
#         return self
#
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         self.s.close()
#
#     def run(self):
#         while not self.stop.isSet():
#             read_ready, _, _ = select.select([self.s], None, None)
#             if self.s in read_ready:
#                 buf = ''
#                 read_socket = True
#                 while not self.stop.isSet() and read_socket:
#                     try:
#                         buf += self.s.recv(1024)
#                     except BlockingIOError as e:
#                         print(str(e))
#                         break
#                     except socket.error as e:
#                         if e.errno != errno.EWOULDBLOCK:
#                             self.stop.set()
#                         read_socket = False
#
#                 s = buf.decode()
#                 print("data:", s)
#                 for p in s.splitlines(True):
#                     print("'%s'" % p)
#                     buf.write(p)
#
#                 if s.endswith('\n'):
#                     break
#
#             time.sleep(0.01)
#             s = buf.getvalue()
#             if s:
#                 print("data_s:", s)
#             self.q.put(s)
#
#     def join(self, timeout=None):
#         self.stop.set()
#         super(PollThread, self).join(timeout)
