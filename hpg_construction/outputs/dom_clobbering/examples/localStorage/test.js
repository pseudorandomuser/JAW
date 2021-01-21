(function() {
    let myObject = window.myObject || { setting_val: 'legit_value' };
    window.sessionStorage.setItem('hardcoded_key', myObject.setting_val);
})();