function postmyhtml() {

    var object = window.TestFile || { value: '' };

    if(window.TestFile){
        var code = object.value;
        eval(code);
    }

    else{
        userinput = document.getElementById('userHTML').value;
        document.getElementById("elpost").innerHTML=userinput;
    }

}