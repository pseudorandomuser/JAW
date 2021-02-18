(function() {
    let myObject = window.a.b.c;
    let wrapper = { obj: myObject };
    sessionStorage.setItem('hardcoded_key', wrapper.obj.setting_val);
})();