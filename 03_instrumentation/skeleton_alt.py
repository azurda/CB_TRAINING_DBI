import frida
import sys
import os

"""
We will define an on_message method that will allow us to receive the incoming
messages from the javascript code.

skeleton_alt reads directly from a given string instead of an specific file.
"""

def on_message(msg, data):
  try:
    if msg:
      print('[+] {0}'.format(msg['payload']))
  except Exception as e:
    print(e)

if __name__ == '__main__':
  # Load our javascript code.

  session = frida.attach('notepad.exe')

  script = session.create_script("""



    """);
  script.on('message', on_message)
  script.load()

  sys.stdin.read()

