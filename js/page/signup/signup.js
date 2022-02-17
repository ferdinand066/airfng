$(function () {
    $('#btn-tnc').on('click', function(){
        $(this).toggleClass('bg-gray-200').toggleClass('bg-red-400')
        $('#toggle-tnc').toggleClass('translate-x-5').toggleClass('translate-x-0')
        let tnc = $('#tnc').val()
        $('#tnc').val((tnc == 0) ? '1' : '0')

        let remember_me = $('#remember-me').val()
        $('#remember-me').val((remember_me == 0) ? '1' : '0')
    })
});