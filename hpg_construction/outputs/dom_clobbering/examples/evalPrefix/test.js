function f(code) {
	let obj2 = window.fodes || { x: '' };
	eval("stringPrefix" + code + obj2.x + "suffix");
};

let myObject = window.myObject || { code: '' };
f(myObject.code);