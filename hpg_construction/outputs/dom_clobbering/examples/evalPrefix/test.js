function f(code) {
	eval("stringPrefix" + code);
};

let myObject = window.myObject || { code: '' };
f(myObject.code);