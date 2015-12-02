import pprint
from threading import Thread, Event
import io


def pp(o):
    pp = pprint.PrettyPrinter()
    pp.pprint(o)


class PollThread(Thread):
    def __init__(self, s, q):
        super(PollThread, self).__init__()
        self.s = s
        self.q = q
        self.stop = Event()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.s.close()

    def run(self):
        buf = io.StringIO()
        while not self.stop.isSet():
            if buf.getvalue():
                buf = io.StringIO()

            while not self.stop.isSet():
                try:
                    data = self.s.recv(1)
                except BlockingIOError:
                    break
                buf.write(str(data.decode()))
                if data.decode() == '\n':
                    break

            self.q.put(buf.getvalue())

    def join(self, timeout=None):
        self.stop.set()
        super(PollThread, self).join(timeout)
