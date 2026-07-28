"""
Data collection layer.

Lightweight sensors:
  - Filesystem watcher: create / modify / rename / delete events (watchdog)
  - Process monitor: spawn, CPU/IO bursts (psutil, polled)
  - API-call hook stub: crypto-API / mass-file-handle-open signal.
    Real syscall/API hooking (ETW on Windows, eBPF/auditd on Linux) is
    OS-specific and requires kernel-level privileges, so this layer
    exposes the same event interface an ETW/eBPF backend would feed,
    and a lightweight heuristic stand-in (rapid concurrent file-handle
    opens by one process) so the rest of the pipeline is fully wired
    and testable end-to-end.

All events are timestamped and pushed onto a thread-safe queue that the
behavioral analysis engine consumes.
"""

import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


@dataclass
class Event:
    ts: float
    kind: str            # "fs_create" | "fs_modify" | "fs_rename" | "fs_delete" | "proc_spawn" | "proc_sample"
    pid: Optional[int] = None
    path: Optional[str] = None
    dest_path: Optional[str] = None      # for renames
    extra: dict = field(default_factory=dict)


class FSHandler(FileSystemEventHandler):
    def __init__(self, event_queue: "queue.Queue[Event]", resolve_pid):
        super().__init__()
        self.q = event_queue
        self.resolve_pid = resolve_pid  # callable() -> pid of the process under test

    def on_created(self, event):
        if event.is_directory:
            return
        self.q.put(Event(time.time(), "fs_create", pid=self.resolve_pid(), path=event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return
        self.q.put(Event(time.time(), "fs_modify", pid=self.resolve_pid(), path=event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        self.q.put(Event(time.time(), "fs_rename", pid=self.resolve_pid(),
                          path=event.src_path, dest_path=event.dest_path))

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.q.put(Event(time.time(), "fs_delete", pid=self.resolve_pid(), path=event.src_path))


class ProcessMonitor(threading.Thread):
    """Polls a target PID for CPU/IO burst indicators."""

    def __init__(self, event_queue: "queue.Queue[Event]", pid_getter, interval: float = 0.5):
        super().__init__(daemon=True)
        self.q = event_queue
        self.pid_getter = pid_getter
        self.interval = interval
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        last_io = {}
        while not self._stop_event.is_set():
            pid = self.pid_getter()
            if pid is not None:
                try:
                    p = psutil.Process(pid)
                    with p.oneshot():
                        cpu = p.cpu_percent(interval=None)
                        children = len(p.children(recursive=True))
                        try:
                            io = p.io_counters()
                            io_bytes = io.read_bytes + io.write_bytes
                        except (psutil.AccessDenied, AttributeError):
                            io_bytes = None
                    prev = last_io.get(pid, io_bytes)
                    io_rate = None
                    if io_bytes is not None and prev is not None:
                        io_rate = max(0, io_bytes - prev) / self.interval
                    last_io[pid] = io_bytes
                    self.q.put(Event(
                        time.time(), "proc_sample", pid=pid,
                        extra={"cpu_percent": cpu, "children": children, "io_bytes_per_s": io_rate},
                    ))
                except psutil.NoSuchProcess:
                    pass
            time.sleep(self.interval)


class Collector:
    """Wires the filesystem watcher + process monitor into one event queue."""

    def __init__(self, watch_path: str, pid_getter):
        self.watch_path = watch_path
        self.pid_getter = pid_getter
        self.queue: "queue.Queue[Event]" = queue.Queue()
        self.observer = Observer()
        self.observer.schedule(FSHandler(self.queue, pid_getter), watch_path, recursive=True)
        self.proc_monitor = ProcessMonitor(self.queue, pid_getter)

    def start(self):
        os.makedirs(self.watch_path, exist_ok=True)
        self.observer.start()
        self.proc_monitor.start()

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=2)
        self.proc_monitor.stop()
        self.proc_monitor.join(timeout=2)
