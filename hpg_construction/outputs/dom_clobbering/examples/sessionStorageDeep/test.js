(function() {
    let myObject = window.myObject || { setting_val: 'legit_value' };
    let wrapper = { obj: myObject };
    sessionStorage.setItem('hardcoded_key', wrapper.obj.setting_val);
})();