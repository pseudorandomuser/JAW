function main() {
    var myObject = window.myObject || { html: 'Hello world!' };
    hashValue.innerHTML = myObject.html;
}
main();