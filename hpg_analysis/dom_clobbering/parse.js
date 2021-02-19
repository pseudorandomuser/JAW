var fs = require('fs');
var esprima = require('esprima');

var program_path = process.argv[2];
var code = fs.readFileSync(program_path, "utf8");

try {
    esprima.parse(code, {range: true, loc: true, tolerant: true})
    console.log('Parsing successful!');
    process.exit(0);
} catch (error) {
    console.log('Parsing failed: ' + error);
    process.exit(-1);
}