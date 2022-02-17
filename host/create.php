<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AirFnG: Vacation Rentals, Cabins, Beach Houses, Unique Homes & Experiences</title>
    <link rel="shortcut icon" href="../assets/images/favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="../css/layout/text.css">
    <link href="https://unpkg.com/tailwindcss@^2/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://unpkg.com/@tailwindcss/custom-forms@0.2.1/dist/custom-forms.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.js" integrity="sha256-H+K7U5CnXl1h5ywQfKtSj8PCmoN9aaq30gDh27Xc0jk=" crossorigin="anonymous"></script>
    <script src="../js/layout/layout.js"></script>
    <script src="../js/page/host/create.js"></script>
</head>
<body class="h-screen flex flex-col justify-between bg-gray-100">
    <?php 
        include('../database/db.php');
        include('../helpers/function.php'); 
    //////
    /// QUESTION 3 SECTION 3 OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE
    //////
        if(!isset($_SESSION['id'])){
            header('location: ../auth/login');
        }
    //////
    /// SECTION ENDS HERE
    //////
    ?>
    <div class="flex flex-col">
        <?php include('../layouts/header.php') ?>
        <main class="max-w-7xl mx-auto px-2 lg:px-8 py-4 space-y-8">
            <form action="<?= route('controllers/host/HostController') ?>" method="post" enctype="multipart/form-data" class="space-y-8 divide-y divide-gray-200" >
            <!--
            //////
            /// QUESTION 5 SECTION 2C OF 3: Cross-Site Request Forgery (CSRF) - Token Field
            /// SECTION STARTS HERE
            //////
            -->
            
              <?= csrf_field() ?>

            <!-- //////
            /// SECTION ENDS HERE
            ////// -->
                <div class="space-y-8 divide-y divide-gray-200 sm:space-y-5">
                    <div class="pt-8 space-y-6 sm:pt-10 sm:space-y-5">
                        <div>
                            <h3 class="text-lg leading-6 font-medium text-gray-900">
                                General
                            </h3>
                            <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                This information will be displayed in search page.
                            </p>
                        </div>

                        <div class="mt-6 sm:mt-5 space-y-6 sm:space-y-5">
                            <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-start sm:border-t sm:border-gray-200 sm:pt-5">
                                <label for="name" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">
                                    Name
                                </label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <div class="max-w-lg flex rounded-md shadow-sm">
                                        <input type="text" name="name" id="name" class="form-input flex-1 block w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border border-gray-300">
                                    </div>
                                </div>
                            </div>

                            <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-start sm:border-t sm:border-gray-200 sm:pt-5">
                                <label for="price" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">
                                    Price
                                </label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <div class="max-w-lg flex rounded-md shadow-sm">
                                        <span class="inline-flex items-center px-3 rounded-l-md border border-r-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">
                                            $
                                        </span>
                                        <input type="number" name="price" id="price" class="form-input border flex-1 block w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                                        <span class="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">
                                            / night
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-start sm:border-t sm:border-gray-200 sm:pt-5">
                                <label for="cover_photo" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">
                                    Photo
                                </label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <div id="bg-img" class="max-w-lg flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                                        <div class="space-y-1 text-center">
                                            <svg id="temp-img" class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48" aria-hidden="true">
                                                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                                            </svg>
                                            <img id="new-img" src="" alt="">
                                            <div class="flex text-sm text-gray-600 justify-center">
                                                <label for="file-upload" class="relative cursor-pointer rounded-md font-medium text-red-400 hover:text-red-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-red-500">
                                                    <span>Upload a photo</span>
                                                    <input id="file-upload" name="file_upload" type="file" class="sr-only" accept="image/*">
                                                </label>
                                                <p class="pl-1">of your place</p>
                                            </div>
                                            <p class="text-xs text-gray-500">
                                                PNG, JPG, GIF up to 10MB
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="pt-8 space-y-6 sm:pt-10 sm:space-y-5">
                        <div>
                            <h3 class="text-lg leading-6 font-medium text-gray-900">
                                Detail Information
                            </h3>
                            <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                Write your place location and some rules about your place.
                            </p>
                        </div>
                        <div class="space-y-6 sm:space-y-5">
                            <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-start sm:border-t sm:border-gray-200 sm:pt-5">
                                <label for="city" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">
                                    City
                                </label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <select id="city" name="city" class="form-select max-w-lg block focus:ring-red-500 focus:border-red-500 w-full shadow-sm sm:max-w-xs sm:text-sm border-gray-300 rounded-md">
                                    <?php 
                                        $sql = "SELECT * FROM cities order by name";
                                        $result = $conn->query($sql);
                                        while($row = $result->fetch_assoc()){
                                    ?>
                                        <option value="<?= $row['id'] ?>"><?= $row['name'] ?></option>
                                    <?php } ?>
                                    </select>
                                </div>
                            </div>

                            <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-start sm:border-t sm:border-gray-200 sm:pt-5">
                                <label for="street_address" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">
                                    Street address
                                </label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <textarea id="street_address" name="street_address" rows="3" class="form-input max-w-lg shadow-sm block w-full focus:ring-red-500 focus:border-red-500 sm:text-sm border-gray-300 rounded-md"></textarea>
                                </div>
                            </div>

                            <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-start sm:border-t sm:border-gray-200 sm:pt-5">
                                <label for="rules" class="block text-sm font-medium text-gray-700 sm:mt-px sm:pt-2">
                                    Rules and Descriptions
                                </label>
                                <div class="mt-1 sm:mt-0 sm:col-span-2">
                                    <textarea id="rules" name="rules" rows="3" class="form-input max-w-lg shadow-sm block w-full focus:ring-red-500 focus:border-red-500 sm:text-sm border-gray-300 rounded-md"></textarea>
                                    <p class="mt-2 text-sm text-gray-500">Write some descriptions and rules of your place</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="divide-y divide-gray-200 pt-8 space-y-6 sm:pt-10 sm:space-y-5">
                        <div>
                            <h3 class="text-lg leading-6 font-medium text-gray-900">
                                Facility
                            </h3>
                            <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                Write the detail about facility that you provide.
                            </p>
                        </div>
                        <div class="space-y-6 sm:space-y-5 divide-y divide-gray-200">
                            <div class="pt-6 sm:pt-5">
                                <div role="group" aria-labelledby="label-email">
                                    <div class="sm:grid sm:grid-cols-3 sm:gap-4 sm:items-baseline">
                                        <div>
                                            <div class="text-base font-medium text-gray-900 sm:text-sm sm:text-gray-700" id="label-email">
                                                Rooms
                                            </div>
                                        </div>
                                        <div class="mt-4 sm:mt-0 sm:col-span-2">
                                            <div class="max-w-lg space-y-4" id="room-container">
                                                <div class="flex items-center">
                                                    <div class="grid gap-x-2 grid-cols-8 ml-0 sm:ml-3">
                                                        <input type="text" name="room[0]" value="Bedroom" readonly id="room[0]" class="col-span-6 form-input border flex-1 w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                                                        <input type="number" name="room_quantity[0]" value="1" min="1" id="room_quantity[0]" class="col-span-2 form-input border flex-1 w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                                                    </div>
                                                </div>
                                                <div class="flex items-center">
                                                    <div class="grid gap-x-2 grid-cols-8 ml-0 sm:ml-3">
                                                        <input type="text" name="room[1]" value="Toilet" readonly id="room[1]" class="col-span-6 form-input border flex-1 w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                                                        <input type="number" name="room_quantity[1]" value="1" min="1" id="room_quantity[1]" class="col-span-2 form-input border flex-1 w-full focus:ring-red-500 focus:border-red-500 min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="flex items-center">
                                                <button type="button" id="btn-add-room" class="mt-4 sm:mt-2 ml-0 sm:ml-3 inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400">
                                                    Add Room
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="pt-5">
                    <div class="flex justify-end">
                        <button type="button" class="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                            Cancel
                        </button>
                        <button type="submit" name="create" class="ml-3 inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-red-400 hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400">
                            Save
                        </button>
                    </div>
                </div>
            </form>

        </main>
    </div>
    <?php include('../layouts/footer.php') ?>

</body>

</html>