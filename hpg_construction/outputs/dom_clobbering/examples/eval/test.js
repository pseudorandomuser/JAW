function f(obj) {
	eval(obj.code);
};

let myObject = window.myObject || { code: '' };
f(myObject);