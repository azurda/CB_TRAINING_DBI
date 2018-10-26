import frida
import sys

session = frida.attach('hello') # We attach to the program name or PID that we need.
# It's possible to pass as an argument a string, however it's more readable
# and safer to just write it in a separate file
with open('script.js', 'r') as f:
  code = f.read()

script = session.create_script(code) # it's possible to pass as an argument a string, but it's more readable to have
script.load()

sys.stdin.read()
