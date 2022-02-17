$(function () {
    const price = $('#current-price').text()

    if($('#desc').outerHeight() / $('#desc').css('lineHeight').split('px')[0] > 10){
        $('#desc').addClass('line-clamp-desc')
    } else {
        $('#show-more,#show-less').remove()
    }

    function syncReview(){
        let list_review = $('.review-detail')
        let arr_review = [...list_review]

        arr_review.forEach(e => {
            if($(e).outerHeight() / $(e).css('lineHeight').split('px')[0] > 2){
                $(e).addClass('line-clamp')
            } else {
                $(e).closest('div').find('.review-show-more,.review-show-less').remove()
            }
        });
    }
       
    syncReview()

    $('#show-more,#show-less').on('click', function(){
        $('#show-more,#show-less').toggleClass('hidden')
        $('#desc').toggleClass('line-clamp-desc')
    })

    $('.review-show-more,.review-show-less').on('click', function(){
        $(this).closest('div').find('.review-show-more,.review-show-less').toggleClass('hidden')
        $(this).closest('div').find('.review-detail').toggleClass('line-clamp')
    })

    $('#check-in, #check-out, #guest').on('change', function(){
        let checkIn = $('#check-in').val()
        let checkOut = $('#check-out').val()
        let guest = $('#guest').val()
        if(checkValid()){
            let duration = Math.abs(new Date(checkOut) - new Date(checkIn))/(1000 * 3600 * 24) 
            $('#duration').text(duration)
            let totalPrice = duration * price;
            let servicePrice = Math.ceil(duration * price * 0.05);
            $('#total').text(totalPrice)
            $('#service-fee').text(servicePrice)
            $('#grand-total').text(Math.ceil(totalPrice + servicePrice))
            $('#detail-container').removeClass('hidden')
        } else {
            $('#detail-container').addClass('hidden')
        }
    })

    $('#forms').on('submit', function(){
        if (!checkValid()){
            createNotification(error, "Invalid Transaction Request!");
            return false;
        }
    })

    function checkValid(){
        let checkIn = $('#check-in').val()
        let checkOut = $('#check-out').val()
        let guest = $('#guest').val()

        let current = new Date();

        return (current < new Date(checkIn) 
            && current < new Date(checkOut) 
            && checkOut > checkIn && guest > 0)
    }
});