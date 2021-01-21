function f(json_param) {
    let myObject = window.myObject || { json_str: json_param };
    window.location = myObject.location;
    window.location.assign(myObject.location);
}
f('{"auth_state":1}');