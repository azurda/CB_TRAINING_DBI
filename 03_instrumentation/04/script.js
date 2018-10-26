/*
	We can also call functions of which we have a ptr reference to. For example,
	in this example we will get the ptr() of the function from sample_01 and
	then create a func_ptr that will allow us to call it.

	Another possible example, would be to call a native windows function from
	JS itself. But we will see that later.

	Syntax:

	new NativeFunction(ptr(), return_type, [arg_types]);
*/


var f = new NativeFunction(ptr('0x10cb30ef0'), 'int', ['int']);

f(10); // calling the native function

// next, send info to py script
// hook native widows func
// call native windows functions from frida