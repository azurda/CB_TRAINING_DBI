Interceptor.attach(ptr('0x1026a7ee0'), {
  onEnter: function(args) {
    console.log('myfunction was called: ' + args[0].toInt32());
}
});
