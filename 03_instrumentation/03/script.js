
Interceptor.attach(ptr('0x10e990eb0'), {
  onLeave: function(retval) {
    console.log('myfunction returned: ' + retval.toInt32());
  }
});

Interceptor.replace(ptr('0x10e990ec0'), new NativeCallback(function () {
	Thread.sleep(0.05);
}, 'uint', []));

/*
	Syntax

	.replace(pointer, new NativeCallBack(function () {
		// contents
	}, returntype, [argument_types]))
*/