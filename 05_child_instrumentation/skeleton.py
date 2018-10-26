from __future__ import print_function
import frida
import json
from frida.application import Reactor
import sys
import threading


class Analyzer(object):

  def __init__(self, launch_args=[]):
    self._launch_args = launch_args
    self._stop_requested = threading.Event()
    self._reactor = Reactor(run_until_return=lambda _:
        self._stop_requested.wait())

    self._device = frida.get_local_device()
    self._sessions = set()

    self._device.on('child-added', lambda child:
        self._reactor.schedule(
          lambda: self._on_delivered(child)))

  def run(self):
    self._reactor.schedule(lambda: self._start())
    self._reactor.run()

  def _start(self):
    argv = ['myapp.exe']
    print('spawning with argv={}'.format(self._launch_args))
    pid = self._device.spawn(self._launch_args)
    self._instrument(pid)

  def _stop_if_idle(self):
    if len(self._sessions) == 0:
      self._stop_requested.set()

  def _instrument(self, pid):
    print('attaching to PID={}'.format(pid))
    session = self._device.attach(pid)
    session.on('detached', lambda reason:
        self._reactor.schedule(lambda:
          self._on_detached(pid, session, reason)))
    print('enabling child_gating()')
    session.enable_child_gating()
    with open('script.js', 'r') as temp_js:
      script = session.create_script(temp_js.read())

    script.on('message', lambda message, data:
        self._reactor.schedule(
          lambda: self._on_message(pid, message)))
    print('loading script...')
    script.load()
    print('resuming PID={}'.format(pid))
    self._device.resume(pid)
    self._sessions.add(session)


  def _on_delivered(self, child):
    print('delivered={}'.format(child))
    self._instrument(child.pid)

  def _on_detached(self, pid, session, reason):
    print('detached from PID={}, reason="{}"'.format(pid, reason))
    self._reactor.schedule(self._stop_if_idle, delay=0.5)

  def _on_message(self, pid, message):
    print('message: PID={}, payload={}'.format(pid, json.dumps(message['payload'])))


app = Analyzer(sys.argv[1:])
app.run()
