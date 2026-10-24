import csv
import re
import threading
import time

from .bmv2 import run_cli
from .tables import SAMPLED

READING = re.compile(r"([\w.]+)\[(\d+)\]=\s*(?:\((\d+) bytes, (\d+) packets\)|(\d+))")


def parse_readings(output):
    values = {}
    for name, index, _, packets, register in READING.findall(output):
        values[name, int(index)] = int(packets or register)
    return values


class Collector:
    def __init__(
        self,
        path,
        interval=0.5,
        sw="s1",
        spec=SAMPLED,
    ) -> None:
        self.path, self.interval, self.sw, self.spec = path, interval, sw, spec
        self._commands = [
            f"{'register_read' if kind == 'register' else 'counter_read'} {name} {index}"
            for _, kind, name, index in spec
        ]
        self._stop = threading.Event()
        self._samples = 0

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        self._file = open(self.path, "w", newline="")  # noqa: SIM115
        self._writer = csv.writer(self._file)
        self._writer.writerow(["t"] + [column for column, *_ in self.spec])
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join()
        self._file.close()

    def _loop(self):
        while not self._stop.is_set():
            began = time.time()
            values = parse_readings(run_cli(self.sw, self._commands))
            ended = time.time()

            self._writer.writerow(
                [f"{(began + ended) / 2:.3f}"]
                + [values.get((name, index), "") for _, _, name, index in self.spec]
            )

            self._file.flush()
            self._samples += 1
            self._stop.wait(max(0.0, self.interval - (ended - began)))
