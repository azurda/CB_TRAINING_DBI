Interceptor.attach(ptr('0x101238ee0'), {
  onEnter: function(args) {
    send({
    	name: 'msg',
    	payload: args[0].toInt32(),
    });
}
});
