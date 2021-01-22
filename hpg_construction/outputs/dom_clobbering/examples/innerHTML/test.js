function main() {
    var myObject = window.myObject || { html: 'Hello world!' };
    var new_html = myObject.html;
    hashValue.innerHTML = new_html;
}
main();