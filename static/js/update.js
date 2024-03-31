document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('form');
    const imageUpload = document.getElementById('image-upload');
    const imagePreview = document.getElementById('image-preview');
    const errorMessage = document.getElementById('upload-error');
    const errorMessages = document.querySelectorAll('.error-message');
    const phoneInput = document.getElementById('phone');
    const addressInput = document.getElementById('address');
    const cityInput = document.getElementById('city');
    const countryInput = document.getElementById('country');
    const postcodeInput = document.getElementById('postcode');
    const stateInput = document.getElementById('state');
    const pinInput1 = document.getElementById('pin');
    const pinInput2 = document.getElementById('pin2');
    const pinError = document.getElementById('pin-error');
    const phoneError = document.getElementById('phone-error');
    const submitBtn = document.getElementById('submitBtn');

    form.addEventListener('submit', function(event) {
        event.preventDefault();

        // Reset error messages
        errorMessages.forEach(msg => msg.textContent = '');
        document.getElementById('form-error').textContent = '';

        // Validate numeric inputs
        if (!/^\d+$/.test(phoneInput.value)) {
            phoneError.textContent = 'Phone number must be numeric';
            phoneInput.focus();
            return;
        }

        if (phoneInput.value.length <= 6) {
            phoneError.textContent = 'Phone number is too short';
            phoneInput.focus();
            return;
        }

        if (!/^\d+$/.test(pinInput1.value) || !/^\d+$/.test(pinInput2.value)) {
            pinError.textContent = 'PIN must be numeric';
            pinInput1.focus();
            return;
        }

        // Check the length of both pins
        if (pinInput1.value.length < 4) {
            pinError.textContent = 'PIN 1 is too short';
            pinInput1.focus();
            return;
        }

        if (pinInput2.value.length < 4) {
            pinError.textContent = 'PIN 2 is too short';
            pinInput2.focus();
            return;
        }

        // Check if pin1 and pin2 values match
        if (pinInput1.value !== pinInput2.value) {
            pinError.textContent = 'PINs do not match';
            pinInput2.focus();
            return;
        }

        // Check if any field is empty
        const requiredInputs = [phoneInput, addressInput, cityInput, countryInput, postcodeInput, stateInput, pinInput1, pinInput2];
        for (const input of requiredInputs) {
            if (!input.value.trim()) {
                document.getElementById('form-error').textContent = 'Please fill in all fields';
                input.focus();
                return;
            }
        }

        // Check if a file has been selected
        if (!imageUpload.files || !imageUpload.files[0]) {
            errorMessage.textContent = 'Please select an image';
            return;
        }

        // Check if the file type is valid
        const fileType = imageUpload.files[0].type;
        if (!fileType.startsWith('image/')) {
            errorMessage.textContent = 'Please select a valid image file';
            return;
        }

        // Optionally, display a preview of the selected image
        const file = imageUpload.files[0];
        const reader = new FileReader();

        reader.onload = function(e) {
            imagePreview.innerHTML = `<img src="${e.target.result}" alt="Image Preview">`;
        };

        reader.readAsDataURL(file);
        // Submit the form manually
        form.submit();
    });

    // Add event listener to the edit nickname button
    const url = window.location.href
    const changeBtn = document.getElementById('change');
    const imageBtn = document.getElementById('image-change');
    const editNicknameBtn = document.getElementById('editNickname');
    const nicknameInput = document.querySelector('input[name="nickname"]');
    const closeError = document.getElementById('close-msg2');
    const closeSuccess = document.getElementById('close-msg');
    const alerts = document.getElementById("alerts")
    closeError.addEventListener('click', function(event){
        event.preventDefault()
        alerts.style.display = "none"
    })
    closeSuccess.addEventListener('click', function(event){
        event.preventDefault()
        alerts.style.display = "none"
    })

    if(editNicknameBtn || imageBtn ){
        editNicknameBtn.addEventListener('click', function(event) {
            event.preventDefault();
            nicknameInput.readOnly = !nicknameInput.readOnly;
            if (!nicknameInput.readOnly) {
                nicknameInput.focus();
            }
            changeBtn.style.display= 'initial'
        });
        imageBtn.addEventListener( 'click', function (event) {
            event.preventDefault();
            changeBtn.style.display= 'initial'
        });
        changeBtn.addEventListener('click', function(event){
            event.preventDefault();
            // Capture input values
            const pictureFile = imageUpload.files[0];
            const textValue = document.getElementById('nickname').value;
    
            // Construct FormData object
            const formData = new FormData();
            formData.append('picture', pictureFile);
            formData.append('nickname', textValue);
    
            // Send AJAX request
            $.ajax({
                url: `${url}save`,
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                    // Handle success response
                    changeBtn.style.display= 'none'
                    closeSuccess.style.display = 'initial'
                    console.log(response);
                },
                error: function(xhr, status, error) {
                    // Handle error response
                    closeError.style.display = 'inintial'
                    console.error(xhr.responseText);
                }
            });
    
        })
    }

});

// Runner.prototype.gameOver = function(){}


