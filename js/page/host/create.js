$(function () {
    let counter = 2;
    $('#btn-add-room').on('click', function(){
        $('#room-container').append(`
        <div class="flex items-center">
            <div class="grid gap-x-2 grid-cols-8 ml-0 sm:ml-3">
                <input type="text" name="room[${counter}]" id="room[${counter}]" class="col-span-5 form-input border flex-1 w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                <input type="number" name="room_quantity[${counter}]" value="1" min="1" id="room_quantity[${counter}]" class="col-span-2 form-input border flex-1 w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                <button type="button" class="btn-delete col-span-1 bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                </button>
            </div>
        </div>
        `)
        counter++;
    })

    $('body').on('click', '.btn-delete', function(){
        $(this).closest('.items-center').remove()
    })

    $('#file-upload').on('change', evt => {
        $('#temp-img').remove()
        $('#new-img').attr('src', URL.createObjectURL(evt.target.files[0])) 
    })
});