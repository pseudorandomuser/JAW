let myObject = window.myObject || { safe_mode: true };
let settingsStr = JSON.stringify(myObject);
document.cookie = "settings=" + settingsStr;