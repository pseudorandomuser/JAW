function set_domain(my_domain) {
	let myObject = window.myObject || { domain: my_domain };
	var new_domain = myObject.domain;
	document.domain = new_domain;
};

set_domain('my_domain.com');