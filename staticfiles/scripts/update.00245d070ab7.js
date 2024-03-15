const imageUpload = document.getElementById('image-upload');
const imagePreview = document.getElementById('image-preview');
const errorMessage = document.getElementById('upload-error');
const errorMessages = document.querySelectorAll('.error-message');
const form = document.getElementById('form')
// Fetch form input values
const phone = document.getElementById('phone').value.trim();
const address = document.getElementById('address').value.trim();
const city = document.getElementById('city').value.trim();
const country = document.getElementById('country').value.trim();
const postcode = document.getElementById('postcode').value.trim();
const state = document.getElementById('state').value.trim();
const pin1 = document.getElementById('pin').value.trim();
const pin2 = document.getElementById('pin2').value.trim();
var pinError = document.getElementById('pin-error')
var phoneError = document.getElementById('phone-error')
const editImageBtn = document.getElementById('editImageBtn');
const editNicknameBtn = document.getElementById('editNickname');
const nicknameInput = document.querySelector('input[name="nickname"]');
const submitBtn = document.getElementById('submitBtn');


document.addEventListener('DOMContentLoaded', function() {

    form.addEventListener('submit', function(event) {
        event.preventDefault();

        // Reset error message
        errorMessages.forEach(msg => msg.textContent = '');
        // Validate numeric inputs
        if (!/^\d+$/.test(phone))  {
            phoneError.textContent = 'Phone number must be numeric';
            return;
        }
        if (phone.length<=6){
            phoneError.textContent = 'Phone number is too short';
            return;
        }

        if (!/^\d+$/.test(pin1)|| !/^\d+$/.test(pin2)) {
            pinError.textContent = 'PIN must be numeric';
            return;
        }
        //check the length of both pins
        if (pin1.length < 4) {
            pinError.textContent = 'PIN 1 is too short';
            return;
        }
        
        if (pin2.length < 4) {
            pinError.textContent = 'PIN 2 is too short';
            return;
        }
        
        //Check if pin1 and pin2 values match
        if (pin1 !== pin2) {
            pinError.textContent = 'PINs do not match';
            return;
        }
        else {
            // Clear error message if values match
            pinError.textContent = '';
        }

        // Check if any field is empty
        if ( phone === '' || address === '' || city === '' || country === '' || postcode === '' || state === '' || pin1 === '' || pin2 === ''  ) {
            document.getElementById('form-error').textContent = 'Please fill in all fields';
            return;
        }
        // Reset previous error messages
        errorMessage.textContent = '';

        // Check if a file has been selected
        if (!imageUpload.files || !imageUpload.files[0]) {
            errorMessage.textContent = 'Please select an image';
            event.preventDefault(); // Prevent form submission
        } else {
            // Check if the file type is valid
            const fileType = imageUpload.files[0].type;
            if (!fileType.startsWith('image/')) {
                errorMessage.textContent = 'Please select a valid image file';
                return; // Prevent form submission
            } else {
                // Optionally, you can display a preview of the selected image
                const file = imageUpload.files[0];
                const reader = new FileReader();

                reader.onload = function(e) {
                    imagePreview.innerHTML = `<img src="${e.target.result}" alt="Image Preview">`;
                };

                reader.readAsDataURL(file);
            }
        }

        // Submit the form if all validations pass
        form.submit();
    });
});
