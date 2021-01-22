(function() {
    let myObjectK = window.myObject || { setting_key: 'legit_key' };
    let myObjectV = window.myObject || { setting_val: 'legit_value' };
    let k = myObjectK.setting_key;
    localStorage.setItem(k, myObjectV.setting_val);
})();