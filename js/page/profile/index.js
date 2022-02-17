$(function () {
    $('#btn-file').on('click', function(){
        $('#file-upload').trigger('click')
    })

    $('#file-upload').on('change', evt => {
        $('#temp-img').remove()
        $('#img-status').val('1')
        if (isExists("#new-img")){
            $('#new-img').attr('src', URL.createObjectURL(evt.target.files[0]))
        } else {
            $('#img-container').prepend(`<img src="${URL.createObjectURL(evt.target.files[0])}" alt="" id="new-img" class="w-40 h-40 mb-4 rounded-full">`)
        }
    })

    $('#btn-delete').on('click', function(){
        $('#img-status').val('2')
        $('#new-img').remove()
        if (!isExists('#temp-img')){
            $('#img-container').prepend(`<svg id="temp-img" xmlns="http://www.w3.org/2000/svg" class="w-40 h-40 text-gray-500" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
            </svg>`)
        }
    })

    function isExists(str){
        return $(str).length > 0;
    }
});