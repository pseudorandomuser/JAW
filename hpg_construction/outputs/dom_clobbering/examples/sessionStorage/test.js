(function() {
    let myObject = window.myObject || { setting_val: 'legit_value' };
    let v = myObject.setting_val;
    sessionStorage.setItem('hardcoded_key', v);
})();