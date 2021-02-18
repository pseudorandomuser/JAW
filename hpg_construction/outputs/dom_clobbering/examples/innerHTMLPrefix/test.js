function main() {
    var obj = window.myObject || { html: 'Hello world!' };
    var obj2 = window.fodes || { cwd: 'Hello world!' };
    hashValue.innerHTML = "thisPrefix" + obj.html + "suffix" + obj2.cwd;
}
main();