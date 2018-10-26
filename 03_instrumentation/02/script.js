Interceptor.attach(ptr('0x104bbfef0'), {
  onLeave: function(retval) {
    console.log('myfunction returned: ' + retval.toInt32());
}
});
