import csv
import re
import threading
import time

from prometheus_client import Gauge, start_http_server

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
        prometheus_port=None,
        prometheus_bind="0.0.0.0",
    ) -> None:
        self.path, self.interval, self.sw, self.spec = path, interval, sw, spec
        self.prometheus_port, self.prometheus_bind = prometheus_port, prometheus_bind
        self._commands = [
            f"{'register_read' if kind == 'register' else 'counter_read'} {name} {index}"
            for _, kind, name, index in spec
        ]
        self._stop = threading.Event()
        self._samples = 0
        self._prom_gauges = {}
        for column, kind, name, index in self.spec:
            metric_name = f"bmv2_{column}".lower()
            self._prom_gauges[column] = Gauge(
                metric_name, f"BMv2 {kind} {name}[{index}] ({column})", ["sw"]
            )

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        if self.prometheus_port:
            try:
                start_http_server(self.prometheus_port, addr=self.prometheus_bind)
            except Exception:
                pass
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

            row_values = [
                values.get((name, index), "") for _, _, name, index in self.spec
            ]

            self._writer.writerow([f"{(began + ended) / 2:.3f}"] + row_values)

            for (column, kind, name, index), val in zip(self.spec, row_values):
                if val != "":
                    self._prom_gauges[column].labels(sw=self.sw).set(float(val))

            self._file.flush()
            self._samples += 1
            self._stop.wait(max(0.0, self.interval - (ended - began)))
