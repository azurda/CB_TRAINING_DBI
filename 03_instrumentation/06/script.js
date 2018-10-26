var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");

Interceptor.attach(CreateFileW, {
  onEnter: function(args) {
    send({
    	name: 'msg',
    	payload: Memory.readUtf16String(args[0]),
    });
}
});
