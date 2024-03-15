
// PRELOADER
const preload = document.querySelector('#preloader');

// HAMBURGER BUTTON
const menu_open = document.querySelector('.menu_open');
const menu_close = document.querySelector('.menu_close');
const toggle = document.querySelector('.toggle');
const nav_links = document.querySelector('.nav-links');


// PRELOADER
window.addEventListener('load', function(){
    preload.style.display = 'none';
    this.document.body.style.overflowY = "scroll";
})

// HAMBURGER BUTTON
menu_open.addEventListener('click', function(){
    nav_links.style.display = 'initial';
    menu_open.style.display = 'none';
    menu_close.style.display = 'initial';
})

menu_close.addEventListener('click', function(){
    nav_links.style.display = 'none';
    menu_open.style.display = 'initial';
    menu_close.style.display = 'none';
})


