let myObject = window.myObject || { safe_mode: true };
let settingsStr = JSON.stringify(myObject);
let cookie_data = "settings=" + settingsStr;
document.cookie = cookie_data;