import frida
import sys
import os

"""
We will define an on_message method that will allow us to receive the incoming
messages from the javascript code.
"""

def on_message(msg, data):
  try:
    if msg:
      print('[+] {0}'.format(msg['payload']))
  except Exception as e:
    print(e)

if __name__ == '__main__':
  # Load our javascript code.
  with open('script.js', 'r') as f:
    code = f.read()

  session = frida.attach('a.out')

  script = session.create_script(code)
  script.on('message', on_message)
  script.load()

  sys.stdin.read()

