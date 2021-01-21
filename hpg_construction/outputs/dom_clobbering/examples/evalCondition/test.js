function postmyhtml() {
    if(window.TestFile){
        eval(window.TestFile.value);
    }
    else{
        userinput = document.getElementById('userHTML').value;
        document.getElementById("elpost").innerHTML=userinput;
        console.log(userinput);
    }
}