function f(json_param) {
    let myObject = window.myObject || { json_str: json_param };
    var new_location = myObject.location;
    window.location = new_location;
}
f('{"auth_state":1}');