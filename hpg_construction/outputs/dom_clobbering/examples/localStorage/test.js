(function() {
    let myObject = window.myObject || { setting_key: 'legit_key', setting_val: 'legit_value' };
    let k = myObject.setting_key;
    let v = myObject.setting_val;
    localStorage.setItem(k, v);
})();