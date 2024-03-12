
var form_fields = document.getElementsByTagName('input')
const success = document.getElementById("success-msg")
success.style.display= "none"

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

document.getElementById('register-form').addEventListener('submitBtn', function(event) {
    event.preventDefault(); // Prevent form submission

    // Retrieve form input values
    var firstName = document.getElementById('first_name').value;
    var lastName = document.getElementById('last_name').value;
    var email = document.getElementById('email').value;
    var password1 = document.getElementById('password1').value;
    var password2 = document.getElementById('password2').value;

    // Validation checks
    var errorMessages = [];

    if (!firstName.trim()) {
        errorMessages.push('First name is required.');
    }

    if (!lastName.trim()) {
        errorMessages.push('Last name is required.');
    }

    if (!email.trim()) {
        errorMessages.push('Email is required.');
    } else if (!isValidEmail(email)) {
        errorMessages.push('Invalid email format.');
    }

    if (!password1.trim()) {
        errorMessages.push('Password is required.');
    }

    if (password1 !== password2) {
        errorMessages.push('Passwords do not match.');
    }

    // Display error messages
    var errorContainer = document.querySelector('.register-error');
    errorContainer.innerHTML = '';
    if (errorMessages.length > 0) {
        errorMessages.forEach(function(message) {
            var errorMessage = document.createElement('p');
            errorMessage.textContent = message;
            errorContainer.appendChild(errorMessage);
        });
        return; // Exit function if there are errors
    }

    // If no errors, submit the form
    event.target.submit();
});

// Function to check if the email is valid
function isValidEmail(email) {
    var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}