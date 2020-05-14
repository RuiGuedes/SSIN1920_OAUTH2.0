var input_word = document.querySelector('input#word');

input_word.addEventListener('keypress', function(event) {
    if(event.keyCode === 32) {
        event.preventDefault();
    }
});
