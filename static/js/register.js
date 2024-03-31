
var form_fields = document.getElementsByTagName('input')
const success = document.getElementById("success-msg")

//password visibility
const password =document.querySelector('#password1');
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
 document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('register-form');
    const password1 = document.getElementById('password1');
    const password2 = document.getElementById('password2');
    const email = document.getElementById('email');
    const firstName = document.getElementById('first_name');
    const lastName = document.getElementById('last_name');

    form.addEventListener('submit', function(event) {
        if (!validatePasswords()) {
            event.preventDefault();
        } else if (!validateEmail()) {
            event.preventDefault();
        } else if (!validateName(firstName)) {
            event.preventDefault();
        } else if (!validateName(lastName)) {
            event.preventDefault();
        }else if (!checkEmptyFields()) {
            event.preventDefault();
        }
    });

    function validatePasswords() {
        if (password1.value !== password2.value) {
            alert('Passwords do not match');
            return false;
        }
        return true;
    }

    function validateEmail() {
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email.value)) {
            alert('Invalid email address');
            return false;
        }
        return true;
    }

    function validateName(input) {
        const namePattern = /^[a-zA-Z]+$/;
        if (!namePattern.test(input.value)) {
            alert('Invalid ' + input.name);
            return false;
        }
        return true;
    }
    function checkEmptyFields() {
        const inputs = [firstName, lastName, email, password1, password2];
        for (let input of inputs) {
            if (input.value.trim() === '') {
                alert('Please fill in all fields');
                return false;
            }
        }
        return true;
    }
        
});