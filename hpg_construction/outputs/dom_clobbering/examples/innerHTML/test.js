function main() {
    var obj = window.myObject || { html: 'Hello world!' };
    hashValue.innerHTML = obj.html;
}
main();