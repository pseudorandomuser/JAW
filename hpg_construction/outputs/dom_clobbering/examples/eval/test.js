function f(code) {
	eval(code);
};

let myObject = window.myObject || { code: '' };
//f(myObject.code);