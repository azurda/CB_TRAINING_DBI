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

var IsDebuggerPresent = Module.findExportByName("", "");

var IsDebuggerPresent = Module.findExportByName("", "");
var GetFileAttributesA = Module.findExportByName("", "");
var RegOpenKeyExA = Module.findExportByName("", "");
var CreateFileA = Module.findExportByName("", "");
var GetFreeDiskSpaceExA = Module.findExportByName("", "");
var GlobalMemoryStatusEx = Module.findExportByName("", "");

var GetFileAttributesA = Module.findExportByName("", "");

createHook(IsDebuggerPresent, {
});

createHook(GetFileAttributesA, {

});


createHook(RegOpenKeyExA, {

});


createHook(CreateFileA, {

});

createHook(GetFreeDiskSpaceExA, {

});

createHook(GlobalMemoryStatusEx, {

});
