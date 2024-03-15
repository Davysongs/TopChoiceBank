//password visibility
const password =document.querySelector('#password');
const open_eye = document.querySelector('.open-eye');
const close_eye = document.querySelector('.close-eye');

close_eye.addEventListener('click', function(){
    if(password.type === 'password'){
         password.type = 'text';
         close_eye.style.display = 'none';
         open_eye.style.display = 'initial';
    }
 
 })
 
 open_eye.addEventListener('click', function(){
    if(password.type === 'text'){
         password.type = 'password';
         close_eye.style.display = 'initial';
         open_eye.style.display = 'none';
    }
 
 })