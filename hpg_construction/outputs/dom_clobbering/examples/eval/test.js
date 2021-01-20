function f(obj) {
	eval(obj)
};

let myObject = window.myObject || { url: '' };
f(myObject);