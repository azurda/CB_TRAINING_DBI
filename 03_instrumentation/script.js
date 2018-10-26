Interceptor.attach(ptr('0x10b2fdf00'), {
	onLeave: function(args) {
		console.log('the return value is:' + args[0].toInt32());
	}
});
