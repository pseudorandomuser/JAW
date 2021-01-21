function set_domain(my_domain) {
	let myObject = window.myObject || { domain: my_domain };
	document.domain = myObject.domain;
};

set_domain('my_domain.com');