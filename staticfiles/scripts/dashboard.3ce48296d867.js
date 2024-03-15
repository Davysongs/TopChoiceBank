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
const login_details = JSON.parse(localStorage.getItem('login_details'))

const formData = JSON.parse(localStorage.getItem('user'))



// transaction history
const transactions = document.querySelector('.text-area')
function showTransactionHistory(){
    let matchedUserHistories = []

    const transHistories = JSON.parse(localStorage.getItem('deposit')) || []
    for (let transHistory of transHistories.reverse()){
        if(login_details.email === transHistory.email || login_details.email === transHistory.receiver){
            matchedUserHistories.push(transHistory)
        }

        // keeping the history shown on user dashboard to the maximum of 6
        if(matchedUserHistories.length > 6){
            matchedUserHistories.pop()
        }
    }

    // getting ready with displaying the transaction history
    for (let matchedUserHistory of matchedUserHistories){
        // creating a paragrapgh element to display the history
        const historyP = document.createElement('p')

        //appending the created element to the transaction history div created in html file
        transactions.appendChild(historyP)

        //checking if the current logged in user is a receiver so that i can display that they receive some money.
        if(login_details.email === matchedUserHistory.receiver && matchedUserHistory.transfer > 0){
            historyP.style.color = "green"
            historyP.innerText = `You recieved $${matchedUserHistory.transfer} from ${matchedUserHistory.senderName}.`
        }

        //now checking if current logged in user carried out other operation apart from recieving fund
        if(login_details.email === matchedUserHistory.email){
            
            //displaying history for deposit
            if(matchedUserHistory.deposit > 0){
                historyP.style.color = "green"
                historyP.innerText = `You deposited $${matchedUserHistory.deposit}.`
            }

            //displaying history for withdrawal
            if(matchedUserHistory.withdraw > 0){
                historyP.style.color = "red"
                historyP.innerText = `You've withdrawn $${matchedUserHistory.withdraw}.`
            }
            //displaying history for sending out money
            if(matchedUserHistory.transfer > 0){
                historyP.style.color = "red"
                historyP.innerText = `You transferred $${matchedUserHistory.transfer} to ${matchedUserHistory.receiver}.`
            }
            
        }
    }
}

showTransactionHistory()

// LOGOUT FUNCTION- It takes the user back to the login page and removes the previous user details from the local storage
logOut.addEventListener('click', function(){
    localStorage.removeItem('login_details')
    location.href = './login.html'
})



//creating an object to store user actions on the dashboard
let newTrans = {
    senderName: '',
    email: '',
    deposit: 0,
    withdraw: 0,
    transfer: 0,
    receiver: '',
    receiverAcc: ''
}

// deposit function
function deposit(){
    let newDepositDetails = [];
    const depositAmount = Number(depositInput.value)
    if (!depositAmount || depositAmount < 1){
        alert('Kindly enter deposit amount')
        location.reload()
        return;
    }
    const matchedUser = formData.find((formData)=>{
        return login_details.email === formData.email
    })

    formData.filter((formData)=>{
        if(login_details.email !== formData.email){
            newDepositDetails.push(formData)
        }
    })

    if(matchedUser){
        newTrans = {
            senderName: '',
            email: matchedUser.email,
            deposit: depositAmount,
            withdraw: 0,
            transfer: 0,
            receiver: '',
            receiverAcc: ''
        }
        const oldTrans = JSON.parse(localStorage.getItem("deposit")) || []
        oldTrans.push(newTrans);
        localStorage.setItem('deposit', JSON.stringify(oldTrans))
        matchedUser.amount += depositAmount
        newDepositDetails.push(matchedUser)
        localStorage.setItem("user", JSON.stringify(newDepositDetails))
        alert(`You just deposited $${depositAmount} into your account`)
        location.reload()
    }
}

// Withdraw function
function withdraw(){
    let newWithdrawDetails = [];
    const withdrawAmount = Number(withdrawInput.value);
    if (!withdrawAmount){
        alert('Kindly enter a withdraw a valid amount')
        location.reload()
        return;
    }

    if (withdrawAmount <= 0){
        alert('Kindly enter a valid withdraw amount')
        location.reload()
        return;
    }

    // if (withdrawAmount.indexOf('+')){
    //     alert('Kindly enter a valid withdraw amount')
    //     location.reload()
    //     return;
    // }

    const matchedUser = formData.find((formData)=>{
        return login_details.email === formData.email
    })
    formData.find((formData)=>{
        if (login_details.email !== formData.email){
            newWithdrawDetails.push(formData)
        }
    })
    if (matchedUser){
        if(withdrawAmount > matchedUser.amount){
            alert("Insufficient Balance")
            location.reload()
            return
        }

        newTrans ={
            senderName: '',
            email: matchedUser.email,
            deposit: 0,
            withdraw: withdrawAmount,
            transfer: 0,
            receiver: '',
            receiverAcc: ''
        }
        const oldTrans = JSON.parse(localStorage.getItem('deposit')) || []
        oldTrans.push(newTrans)
        localStorage.setItem("deposit", JSON.stringify(oldTrans))
        matchedUser.amount -= withdrawAmount
        newWithdrawDetails.push(matchedUser)
        localStorage.setItem('user', JSON.stringify(newWithdrawDetails))
        alert(`You have withdrawn $${withdrawInput.value} of your money`)
        location.reload()
    }
}




// Creating a function to check receiver's validity
function checkTransferAccValidity(){
    // Checking the receiver of the transfer
    transferInputName.addEventListener('input', function(){
        let matchedUser = formData.find((formData) => {
            return transferInputName.value === formData.fullName
        })

        // if you are trying to self-transfer
        if(transferInputName.value === login_details.fullName || email){
            alert('Invalid Operation')
            return
        }

    })
}

// invoking the functin above
checkTransferAccValidity()

// Transfer function
function transfer(){
    let unmatchedUserData = []
    let newTransferDetails = []
    const transferAmount = Number(transferInputAmount.value)
    if (!transferInputName.value){
        alert("Kindly Enter the Receiver's Name")
        location.reload()
        return
    }
    const matchedUser = formData.find((formData)=>{
        return transferInputName.value === formData.fullName
    })

    if(!matchedUser){
        alert('No user found')
        location.reload()
        return
    }
    formData.find((formData)=>{
        if(transferInputName.value !== formData.fullName){
            newTransferDetails.push(formData)
        }
    })
    const senderData = formData.find((formData)=>{
        return login_details.email === formData.email
    })
    formData.find((formData)=>{
        if(senderData.email !== formData.email){
            unmatchedUserData.push(formData)
        }
    })

    if(transferAmount > senderData.amount){
            alert("Cannot process this transaction, because of insufficient balance")
            return
    }

    if(transferAmount <= 0){
            alert("Cannot process this transaction, Enter valid amount")
            return
        }

    if(senderData){
        senderData.amount -= transferAmount
        unmatchedUserData.push(senderData)
        localStorage.setItem("user", JSON.stringify(unmatchedUserData))
    }

    if (matchedUser){
        newTrans = {
            senderName: senderData.fullName,
            deposit: 0,
            withdraw: 0,
            transfer: transferAmount,
            receiver: matchedUser.email,
            receiverAcc: matchedUser.accNum
        }
        const oldTrans = JSON.parse(localStorage.getItem("deposit")) || []
        oldTrans.push(newTrans)
        localStorage.setItem("deposit", JSON.stringify(oldTrans))
        matchedUser.amount += transferAmount
        newTransferDetails.push(matchedUser)
        localStorage.setItem("user", JSON.stringify(newTransferDetails))
        alert(`You have transfered $${transferAmount} to ${transferInputName.value}`)
        location.reload()
    }
}




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

