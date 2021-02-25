var fs = require('fs');
var esprima = require('esprima');

var program_path = process.argv[2];
var code = fs.readFileSync(program_path, "utf8");

try {
    esprima.parse(code, {range: true, loc: true})
    process.exit(0);
} catch (error) {
    process.exit(-1);
}