$(function () {
    let coords = null;

    if (localStorage.getItem("coords") === null) {
        navigator.geolocation.getCurrentPosition(showPosition);
    } else {
        let data = JSON.parse(localStorage.getItem('coords'));
        let secondsDiff = (new Date().getTime() - data.timestamp) / 1000;
        if (secondsDiff > (60 * 60)){
            localStorage.removeItem('coords');
            navigator.geolocation.getCurrentPosition(showPosition);
        } else {
            showPosition(data);
        }
    }
    

    function calcCrow(lat1, lon1, lat2, lon2) {
        var R = 6371;
        var dLat = toRad(lat2-lat1);
        var dLon = toRad(lon2-lon1);
        var lat1 = toRad(lat1);
        var lat2 = toRad(lat2);

        var a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.sin(dLon/2) * Math.sin(dLon/2) * Math.cos(lat1) * Math.cos(lat2); 
        var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)); 
        var d = R * c;
        return d;
    }

    function toRad(Value) 
    {
        return Value * Math.PI / 180;
    }

    function showPosition(position) {
        coords = position.coords;

        if (localStorage.getItem("coords") === null) {
            let obj = {
                'coords' : {
                    'longitude' : coords.longitude,
                    'latitude' : coords.latitude
                },
                'timestamp' : new Date().getTime().toString()
            }
            localStorage.setItem('coords', JSON.stringify(obj));
        }

        let locationList = $('.location');
        locationList.each(function(){
            let data = $(this).text()
            let result = data.split(',')
            result = calcCrow(coords.latitude, coords.longitude, result[0], result[1]).toFixed()
            $(this).text(result + ' kilometers away')
        })
        $('#city-container').removeClass('hidden')
    }
});
