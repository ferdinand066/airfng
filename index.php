<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AirFnG: Vacation Rentals, Cabins, Beach Houses, Unique Homes & Experiences</title>
    <link rel="shortcut icon" href="assets/images/favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="./css/layout/text.css">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.js" integrity="sha256-H+K7U5CnXl1h5ywQfKtSj8PCmoN9aaq30gDh27Xc0jk=" crossorigin="anonymous"></script>
    <script src="./js/layout/layout.js"></script>
    <script src="./js/page/index/index.js"></script>
</head>
<body class="h-screen flex flex-col justify-between bg-gray-100">
    <?php 
        include('./database/db.php'); 
        include('./helpers/function.php');
    ?>
    <div class="flex flex-col">
        <?php include('./layouts/header.php')?>
        <main class="max-w-7xl mx-auto px-2 lg:px-8 py-4 space-y-8">
            <div class="relative">
                <img src="./assets/images/index/desktop-home-1.webp" alt="" class="rounded hidden md:block w-full">
                <img src="./assets/images/index/tablet-home-1.webp" alt="" class="rounded block md:hidden">
                <div class="absolute bottom-6 sm:bottom-12 right-1/2 translate-x-1/2 flex flex-col justify-center align-center space-y-4 sm:space-y-6">
                    <span class="text-white text-xl sm:text-3xl brown text-center">Not sure where to go? Perfect.</span>
                    <a href="<?= route('host') ?>" class="mx-auto text-center text-red-800 bg-white px-2 py-1 sm:px-4 sm:py-2 font-semibold rounded-full w-32 hover:bg-gray-50 text-sm sm:text-md">I'm flexible</a>
                </div>
            </div>
            <div class="flex flex-col space-y-4 hidden" id="city-container">
                <span class="text-4xl brown">Inspiration for your next trip</span>
                <!-- This example requires Tailwind CSS v2.0+ -->
                <ul class="grid grid-cols-1 gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
                    <?php 
                        $sql = "SELECT * FROM cities order by name";
                        $result = $conn->query($sql);
                        $i = 0;
                        $colorList = ['red', 'orange', 'amber', 'yellow'];
                        while($row = $result->fetch_assoc()){
                    ?>

                    <li class="col-span-1 flex flex-col bg-<?= $colorList[$i] ?>-600 rounded-lg shadow divide-y divide-gray-200 text-white sm:h-96">
                        <a href="<?= route('host?city_id=' . $row['id']) ?>" class="flex-1 flex flex-col brown">
                            <img class="w-full rounded-t-lg" src="./assets/images/index/<?= $row['image'] ?>" alt="">
                            <div class="flex flex-col rounded-b-lg p-4 space-y-3">
                                <span class="text-3xl font-bold"><?= $row['name'] ?></span>
                                <span class="text-lg location"><?= $row['latitude'] .',' . $row['longitude'] ?></span>
                            </div>
                        </a>
                    </li>
                    <?php $i++; } ?>
                </ul>

            </div>
        </main>
    </div>
    <?php include('./layouts/footer.php')?>
    
</body>
</html>