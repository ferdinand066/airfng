<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AirFnG: Vacation Rentals, Cabins, Beach Houses, Unique Homes & Experiences</title>
    <link rel="shortcut icon" href="../assets/images/favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="../css/layout/text.css">
    <link rel="stylesheet" href="../css/host/show.css">
    <link href="https://unpkg.com/tailwindcss@^2/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://unpkg.com/@tailwindcss/custom-forms@0.2.1/dist/custom-forms.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.js" integrity="sha256-H+K7U5CnXl1h5ywQfKtSj8PCmoN9aaq30gDh27Xc0jk=" crossorigin="anonymous"></script>
    <script src="../js/layout/layout.js"></script>
    <script type="text/javascript" src="../js/page/host/show.js"></script>
</head>
<body class="h-screen flex flex-col justify-between bg-gray-100">
    <?php 
        include('../database/db.php'); 
        include('../helpers/function.php');
    ?>
    <div class="flex flex-col">
        <?php 
            include('../layouts/header.php') ;
            $sql = "SELECT h.*, c.name as city_name, 
                u.first_name as first_name, 
                concat(u.first_name, ' ', u.last_name) as full_name 
            FROM hosts h 
            join cities c on h.city_id = c.id 
            join users u on u.id = h.user_id
            where h.id = '" . $_GET['id'] . "'";
            $result = $conn->query($sql);
            if($result->num_rows != 1) header("location: ../../index");

            $row = $result->fetch_assoc();
        ?>
        <main class="max-w-7xl px-2 mx-auto lg:px-8 py-4 lg:py-12 space-y-8">
            <div class="flex flex-col space-y-4">
                <div class="flex flex-col">
                    <span class="text-3xl font-semibold brown"><?= $row['name'] ?></span>
                    <span class="text-xl">in <?= $row['city_name'] ?></span>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 md:space-x-4 space-y-4 md:space-y-0">
                    <div class="col-span-1 sm:col-span-2 space-y-4">
                        <img src="<?= route('assets/images/host/' . $row['photo']) ?>" alt="" class="w-full rounded-lg img-container object-cover">
                        <div class="flex flex-col">
                            <span class="text-xl">Entire home hosted by <a href="<?= route('profile/show?id=' . $row['user_id']) ?>" class="font-semibold"><?= $row['first_name'] ?></a></span>
                            <div class="flex flex-row space-x-1 text-lg">
                                <?php
                                    $data = json_decode($row['rooms']);
                                    $total = count($data);
                                    $i = 0;
                                    foreach($data as $key => $value){ ?>
                                        <span class="text-sm"><?= $value->quantity . ' ' . $value->room_name . (($i !== $total - 1)
                                            ? ' - ' : '') ?></span>
                                <?php $i++;} ?>
                            </div>
                            <span class="text-xl font-semibold mt-4">Description</span>
                            <span class="whitespace-pre-line" id="desc">
                                <?= trim($row['rules']) ?>
                            </span>
                            <span id="show-more" class="text-gray-500 text-sm cursor-pointer">Show more</span>
                            <span id="show-less" class="text-gray-500 text-sm cursor-pointer hidden">Show less</span>
                        </div>
                    </div>
                    <div class="bg-gray-50 col=span-1 p-4 border-2 border-gray-300 border-dashed rounded-lg md:shadow-lg order-container">
                        <span><span class="text-xl font-semibold">$<span id="current-price"><?= $row['price'] ?></span></span> / night</span>
                        <form action="<?= route('controllers/transaction/TransactionController') ?>" method="post" class="grid space-y-4" id="forms">
                            <!--
                            //////
                            /// QUESTION 5 SECTION 2D OF 3: Cross-Site Request Forgery (CSRF) - Token Field
                            /// SECTION STARTS HERE
                            //////
                            -->
                            
                            <?= csrf_field() ?>

                            <!-- //////
                            /// SECTION ENDS HERE
                            ////// -->
                            <input type="hidden" name="host_id" value="<?= $row['id'] ?>">
                            <div class="col-span-2 grid grid-cols-2 space-x-1">
                                <div class="col-span-1 flex flex-col">
                                    <label for="check-in" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">Check In</label>
                                    <input type="date" name="check_in" id="check-in" class="form-input flex-1 block w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border border-gray-300">
                                </div>
                                <div class="col-span-1 flex flex-col">
                                    <label for="check-out" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">Check Out</label>
                                    <input type="date" name="check_out" id="check-out" class="form-input flex-1 block w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border border-gray-300">
                                </div>
                            </div>
                            <div class="col-span-2 flex flex-col">
                                <label for="guest" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">Guests</label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <div class="max-w-lg flex flex-row-reverse rounded-md shadow-sm">
                                        <span class="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">
                                            guest(s)
                                        </span>
                                        <input type="number" name="guest" id="guest" min="1" class="form-input flex-1 block w-full focus:ring-indigo-500 focus:border-indigo-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                                    </div>
                                </div>
                            </div>
                            <div class="col-span-2">
                                <button type="submit" name="create" class="w-full inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400">
                                    Reserve
                                </button>
                            </div>
                            <div id="detail-container" class="col-span-2 space-y-2 hidden divide-y">
                                <div class="flex flex-col space-y-2">
                                    <div class="flex flex-row justify-between">
                                        <span>
                                            <span>$<span id="price"><?= $row['price'] ?></span> x <span id="duration"></span> night(s)</span>
                                        </span>
                                        <span>$<span id="total"></span></span>
                                    </div>
                                    <div class="flex flex-row justify-between">
                                        <span>
                                            Service fee
                                        </span>
                                        <span>$<span id="service-fee"></span></span>
                                    </div>
                                </div>
                                <div>
                                    <div class="flex flex-row justify-between font-bold mt-1">
                                        <span>Total</span> 
                                        <span>$<span id="grand-total"></span></span>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
                <span class="text-xl font-semibold">Review</span>
                <div class="grid grid-cols-1 md:grid-cols-2 md:gap-x-8 gap-y-4">
                    <?php 
                        $sql = "SELECT r.*, concat(u.first_name, ' ', u.last_name) as full_name, u.photo 
                        FROM reviews r
                        JOIN users u
                            on r.user_id = u.id
                            and r.host_id = '" . $_GET['id'] . "'
                        ORDER BY created_at desc
                        limit 6";
                        $result = $conn->query($sql);

                        while($row = $result->fetch_assoc()){;
                    ?>
                    <div class="flex flex-col">
                        <div class="col-span-1 flex flex-row space-x-1 items-center">
                            <?php if($row['photo'] !== null){ ?>
                                <img src="<?= route('assets/images/profile/' . $row['photo']) ?>" alt="" class="w-16 h-16 md:w-20 md:h-20 p-1 rounded-full flex flex-shrink-0">
                            <?php } else { ?>
                                <svg xmlns="http://www.w3.org/2000/svg" class="w-16 h-16 md:w-20 md:h-20 text-gray-500 flex flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                                </svg>
                            <?php } ?>
                            <div class="flex flex-col">
                                <span class="font-semibold"><?= $row['full_name'] ?></span>
                                <span class="text-gray-500 font-light"><?= date("F Y", strtotime($row['created_at'])) ?></span>
                            </div>
                        </div>
                        <span class="px-2 review-detail"><?= trim($row['review']) ?></span>
                        <span class="px-2 cursor-pointer review-show-more text-gray-500 text-sm">Show more</span>
                        <span class="px-2 cursor-pointer review-show-less text-gray-500 text-sm hidden">Show less</span>
                    </div>
                    <?php } ?>
                </div>
                <!-- //////
                /// QUESTION 3 SECTION 12 OF 12: Access Control
                /// Validate input can only be seen on users 
                /// who have made transactions on the host concerned.
                /// SECTION STARTS HERE
                ////// -->
                <?php 
                    if (isset($_SESSION['id'])){
                        $sql = "SELECT * 
                        from transactions t where t.host_id = '" . $_GET['id'] . "'
                        and t.user_id = '" . $_SESSION['id'] . "'";
                        $result = $conn->query($sql);
                        if($result->num_rows >= 1){
                ?>
                <form method="post" action="<?= route('controllers/review/ReviewController') ?>" class="flex w-full flex-col md:flex-row md:space-x-2 space-y-2 md:space-y-0 items-center py-12">
                    <!--
                    //////
                    /// QUESTION 5 SECTION 2E OF 3: Cross-Site Request Forgery (CSRF) - Token Field
                    /// SECTION STARTS HERE
                    //////
                    -->
                    
                    <?= csrf_field() ?>

                    <!-- //////
                    /// SECTION ENDS HERE
                    ////// -->
                    <input type="hidden" name="host_id" value="<?= $_GET['id'] ?>">
                    <div class="flex flex-row space-x-2 w-full">
                        <?php if($_SESSION['photo'] !== null){ ?>
                            <img src="<?= route('assets/images/profile/' . $_SESSION['photo']) ?>" alt="" class="w-16 h-16 md:w-20 md:h-20 rounded-full p-2 flex flex-shrink-0">
                        <?php } else { ?>
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-16 h-16 md:w-20 md:h-20 text-gray-500 flex flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd" />
                            </svg>
                        <?php } ?>
                        <textarea id="review" name="review" id="review" rows="3" class="w-full flex-1 form-input shadow-sm block focus:ring-red-500 focus:border-red-500 sm:text-sm border-gray-300 rounded-md"></textarea>
                        <button type="submit" name="create" class="h-10 ml-3 inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400">
                            Save
                        </button>
                    </div>
                </form>
                <?php } } ?>
                <!-- //////
                /// SECTION ENDS HERE
                ////// -->
            </div>
        </main>
    </div>
    <?php include('../layouts/footer.php') ?>

</body>

</html>