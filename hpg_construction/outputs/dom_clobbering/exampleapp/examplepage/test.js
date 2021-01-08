window.onload = function() {
	let myObject = window.myObject || { url: '' };
	let script = document.createElement('script');
	script.src = myObject.url;
	document.body.appendChild(script);
};
