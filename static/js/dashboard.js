// DOM ELEMENTS
const logOut = document.querySelector('#logout')
const popup_balance = document.querySelector('#popup-balance');
const popup_deposit = document.querySelector('#popup-deposit');
const popup_transfer = document.querySelector('#popup-transfer');
const popup_withdraw = document.querySelector('#popup-withdraw');
const button_1 = document.querySelector('#button-1');
const sideButton1 = document.querySelector('#side-button-1');
const sideButton2 = document.querySelector('#side-button-2');
const button_2 = document.querySelector('#button-2');
const sideButton3 = document.querySelector('#side-button-3');
const button_3 = document.querySelector('#button-3');
const button_4 = document.querySelector('#button-4');
const sideButton4 = document.querySelector('#side-button-4');
const close_popup = document.querySelector('#close-popup');
const close_transfer_popup = document.querySelector('#close-transfer-popup');
const close_deposit_popup = document.querySelector('#close-deposit-popup');
const close_withdraw_popup = document.querySelector('#close-withdraw-popup');
const cancelPop1 = document.querySelector('.cancel-pop1');
const cancelPop2 = document.querySelector('.cancel-pop2');
const cancelPop3 = document.querySelector('.cancel-pop3');
const cancelPop4 = document.querySelector('.cancel-pop4');

const accName = document.querySelector('#name');
const amount = document.querySelector('.amount');

const overlay = document.querySelector(".overlay");

//balance visibillity
// Get elements by their IDs
const showIcon = document.getElementById('show-balance');
const hideIcon = document.getElementById('hide-balance');
const balanceValue = document.getElementById('balance-value');
const star = document.getElementById('hidden');

// Add comma  to the number every 3 digits
function addCommas(number) {
    return number.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
segment = addCommas(balanceValue.innerHTML);
balanceValue.innerHTML = segment

// Hide the balance value initially
balanceValue.style.display = 'none';

// Add click event listeners to toggle visibility
showIcon.addEventListener('click', function() {
    showIcon.style.display = 'none';
    hideIcon.style.display = 'inline-block';
    balanceValue.style.display = 'inline'; // Show the balance value
    star.style.display = 'none'; // Hide the hidden placeholder
});

hideIcon.addEventListener('click', function() {
    showIcon.style.display = 'inline-block';
    hideIcon.style.display = 'none';
    balanceValue.style.display = 'none';
    star.style.display = 'inline'; // Show the hidden placeholder
});
// WORKING OPERATION


// Overlay Cancel Popup

function openPopup(e) {
    let me = e.target.parentNode.parentNode.querySelector('.popup');
    me.classList.add('open-popup');
    $(".overlay").css('display', 'block');
    // $('body').css("overflowY", "hidden");
}

function closePopup(e) {
    let me = e.target.parentNode;
    me.classList.remove('open-popup');
    $(".overlay").css('display', 'none');
    $('body').css("overflowY", "scroll");
}


function rmOverlay() {
    popup_balance.classList.remove('open-popup');
    popup_transfer.classList.remove('open-popup');
    popup_deposit.classList.remove('open-popup');
    popup_withdraw.classList.remove('open-popup');
    popup_balance.classList.remove('open-popup');
    popup_transfer.classList.remove('open-popup');
    popup_deposit.classList.remove('open-popup');
    popup_withdraw.classList.remove('open-popup'); 
    $(".overlay").css('display', 'none');
    $('body').css("overflowY", "scroll");
}


button_1.addEventListener('click', function(e){
    openPopup(e);
})

sideButton1.addEventListener('click', function(e){
    popup_balance.classList.add('open-popup');
    overlay.style.display = 'block';
    // $('body').css("overflowY", "hidden");
})

close_popup.addEventListener('click', function(e){
    closePopup(e);
})



button_2.addEventListener('click', function(e){
    openPopup(e);
})

sideButton2.addEventListener('click', function(e){
    popup_transfer.classList.add('open-popup');
    overlay.style.display = 'block';
    // $('body').css("overflowY", "hidden");
})

close_transfer_popup.addEventListener('click', function(e){
    transfer()
    closePopup(e);
})

button_3.addEventListener('click', function(e){
    openPopup(e);
})

sideButton3.addEventListener('click', function(e){
    popup_deposit.classList.add('open-popup');
    overlay.style.display = 'block';
    // $('body').css("overflowY", "hidden");
})

close_deposit_popup.addEventListener('click', function(e){
    deposit()
    closePopup(e);
})

button_4.addEventListener('click', function(e){
    openPopup(e);
})

sideButton4.addEventListener('click', function(e){
    popup_withdraw.classList.add('open-popup');
    overlay.style.display = 'block';
    // $('body').css("overflowY", "hidden");
})

close_withdraw_popup.addEventListener('click', function(e){
    withdraw()
    closePopup(e);
})
cancelPop1.addEventListener('click', function(e){
    closePopup(e);
})
cancelPop2.addEventListener('click', function(e){
    closePopup(e);
})
cancelPop3.addEventListener('click', function(e){
    closePopup(e);
})
cancelPop4.addEventListener('click', function(e){
    closePopup(e);
})


$(".overlay").on('click', ()=>{
    rmOverlay();
})

$("body").keydown((e)=>{
    if(e.key === "Escape"){
        rmOverlay();
    }
})



// DEPOSIT ELEMENTS
const depositInput = document.querySelector('#deposit');

// WITHDRAW ELEMENTS
const withdrawInput = document.querySelector('#withdraw')

// TRANSFER ELEMENTS
const transferInputAmount = document.querySelector('#transfer-amount')
const transferInputName = document.querySelector('#transfer-name')

// LocalStorage keys for both Registration and login pages


// transaction history

// Transfer function




const integrityAcc = document.querySelector('.integrity-acc')
const transact = document.querySelector('.transact')
const integrityAccDetails1 = document.querySelector('.box1')
const integrityAccDetails2 = document.querySelector('.box2')
const integrityAccDetails3 = document.querySelector('.box3')
const transactDetails = document.querySelector('.trans-history-details')

integrityAcc.addEventListener('click', function(){
    integrityAcc.classList.add('active')
    transact.classList.remove('active')
    integrityAccDetails1.style.display = ''
    integrityAccDetails2.style.display = ''
    integrityAccDetails3.style.display = ''
    transactDetails.style.display = 'none'
})

