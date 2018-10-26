function log_instr(msg) {
  send({
    name: 'message',
    payload: msg,
  });
}

function createHook(func_obj, interceptor_body) {
  if(func_obj == null)
    return;
  Interceptor.attach(func_obj, interceptor_body);
}

// For this part, we are going to get information from a program
// and then we will also patch things on the fly without having access
// to the source code.
//
// For this example we are going to be using pafish, a program that tests
// whether a VM can be detected or not.
//
// The source code is avaiable on the internet, however for this part of the
// training we are going to act as if we didn't have access to it.
//
// This program shows valuable virtual machine detections that malware uses.
//
// Firstly, we are going to read the output that we obtain from the application.
//
// Secondly, we are going to try to figure out how it's detecting our virtual
// machine.
//
// Third, we are going to patch these checks as much as possible.
//

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680345(v=vs.85).aspx
var IsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
// 1. Find the usages of this API call in the disassembly
// 2. Print the information to inspect what is being checked
// Interesting strings found: /vbox/ /VBox/ /virtualbox/
// 3. Do a dummy replacement of all the calls.
// 4. Replace calls only given certain conditions.
var GetFileAttributesA = Module.findExportByName("kernel32.dll", "GetFileAttributesA");

// In this case, IsDebugerPresent is being called. In case that we want to avoid
// being dettected by this technique, we can replace the return value.
// For training purposes, we are going to force the this function to return
// 1, which means that we are debugging it.
//
// Also, we will send the return value to our application.

createHook(IsDebuggerPresent, {
  onEnter: function(args) {
    retval.replace(0x1);
    send({
      name: 'message',
      payload: retval.toInt32(),
    });
  }
});

createHook(GetFileAttributesA, {
  onEnter: function(args) {
    var buf = Memory.allocAnsiString(Memory.readAnsiString(args[1]));
    this.buf = buf;
    args[0] = buf;
    send({
      name: 'message',
      payload: Memory.readAnsiString(args[1]),
    });
  }
});

// After the first example, allow the student to perform this actions on his
// behalf.
//
// Firstly, they will have to locate what API call is being used to query
// registry keys
//
// Secondly, try to inspect what is being queried by the api calls
//
// Finally, try to redirect these suspicious queries.
//
// Why ANSI String?
// Why did you use that to replace?
createHook(RegOpenKeyExA, {
  onEnter: function(args) {
    this.temp = Memory.readAnsiString(args[1]);
    this.temp = this.temp.replace('VBOX', 'VXOX');
    var buf = Memory.allocAnsiString(this.temp);
    this.buf = buf;
    args[1] = buf;
    send({
      name: 'message',
      payload: Memory.readAnsiString(args[1]),
    });
  }
});


// How is the program detecting our disk size? Can we manipulate it?
// Let's investigate.
//
// CreateFileW is being called to open PhysicalDrive0. This means that
// if we cut the access to this file, the program won't be able to figure out
// our VM size by using this technique.
//
// We can patch it so that it tries to open a different file instead.
//
// Students:
// Our virtualmachine is being detected by doing certain queries to devices.
//
// Can you figure out how to stop them?
//
// Firstly, a way to check if a device is accessible or exists is to try to
// open it. In case that we can retrieve a handle to the device, then it's
// present. But... what devices are present? let's figure out.
//
// Firstly, we can see some references to the CreateFileW, which is being called
// to perform queries to PhysicalDrive0.
createHook(CreateFileA, {

});


// There isn't a single method to check for the DiskSize. So in this case,
// we are going to aim for the second method of detecting our virtual machine.
//
// The application calls GetDiskFreeSpaceExA and checks if the size is less than
// 60gb
//
// The return size is in bytes, however it's stored un ULARGE_INTEGER. Therefore,
// we need to read by calling Memory.readU64
//
// We can fake this size to return a different value. For this purpose,
// we are going to reutilize the technique that we have used before.
//
// Let the students figure out how to read the value.
//
// Get the disk size
//
// Replace it by a value chosen by the user
//
// This time, it's unneeded to use a dummy value. it's enough if we use the
// Memory.write* method

createHook(GetFreeDiskSpaceExA, {
  onEnter: function(args) {
    this.buf = args[2]; // We get the argument that returns the total number of bytes
    // However, we are not able to read it here so we need to find a way to read it.
  },
  onLeave: function(retval) {
    // First part, getting the conversion number, retrieving the value.
    this.aux_conversion = 1024*1024*1024;

    // Second part, rewrite the value.
    // Use the return value and multiply it by 3.
    Memory.writeU64(this.buf, Memory.readU64(this.buf)*2);
    send({
      name: 'message',
      payload: Memory.readU64(this.buf) / this.aux_conversion,
    });
  }
});


// Another well known check is related to the available RAM in the device
// in this case, it will check for a low amount of RAM, 1Gb. Most systems
// today run on superior hardware, meaning that there is at lest 2 or 4Gbs of
// RAM available in the device.
//
// In this case, we can't read the raw pointer that is returned when we
// access args[0].
//
// In fact, this is a struct (can be read in slide)
//
// For this situation, we need to use .add() and move through the structure
//
// Since the first two elements are DWORDS, we are able to read the structure
// required by summing 0x8
//
// Once we have the correct address, we can read it and modify it.

createHook(GlobalMemoryStatusEx, {
  onEnter: function(args) {
    this.buf = args[0];
  },
  onLeave: function(retval) {
    this.tmp = (1024*1024*1024);
    send({
      name: 'message',
      payload: Memory.readU64(this.buf.add(0x8)) / this.tmp,
    });
  }
});
