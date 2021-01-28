(function() {
	let myObject = window.myObject || { arg: 'some data' };
	$(myObject.arg).append("fodes");
})();