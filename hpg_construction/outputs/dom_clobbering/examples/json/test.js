let myObject = window.myObject || { json_value: '{}' };
let json_str = myObject.json_value;
let settingsObj = JSON.parse(json_str);